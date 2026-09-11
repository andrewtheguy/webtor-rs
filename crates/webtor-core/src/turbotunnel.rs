//! A Turbo tunnel session that outlives the connection carrying it.
//!
//! Snowflake's bridge keys a session by the client ID each connection opens
//! with, not by the connection. A new connection that opens with the same ID
//! picks the session up where the last one left it, and the bridge holds the
//! session's packets for a minute while no connection has it. So when a proxy
//! goes, or stops delivering, this dials another and carries on, as the
//! official client does: KCP above retransmits what was lost in between, and
//! nothing above KCP notices.

use crate::error::Result;
use crate::time::Instant;
use crate::turbo::TurboStream;
use futures::future::LocalBoxFuture;
use futures::{AsyncRead, AsyncWrite, FutureExt};
use gloo_timers::future::TimeoutFuture;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tracing::{info, warn};

/// How long a connection may deliver nothing before it is given up for
/// another, as the official client's `SnowflakeTimeout`. The bridge's smux
/// sends a keepalive every ten seconds, so a working connection is never
/// this quiet.
const SILENCE_TIMEOUT: Duration = Duration::from_secs(20);
/// Connections in a row that may end without delivering anything. Past this
/// the session is taken to be gone at the bridge, rather than each proxy
/// being unlucky, and the stream fails so that a fresh session can be opened.
const MAX_SILENT_CONNECTIONS: u32 = 3;

/// Opens one connection to the bridge: a proxy's data channel, or a WebSocket.
pub(crate) type Dial<S> = Rc<dyn Fn() -> LocalBoxFuture<'static, Result<S>>>;

enum Connection<S> {
    Up {
        turbo: TurboStream<S>,
        /// When the connection last delivered anything, or opened.
        heard: Instant,
        /// Wakes the reader to check `heard`.
        silence: TimeoutFuture,
        delivered: bool,
    },
    Dialing(LocalBoxFuture<'static, Result<TurboStream<S>>>),
    Failed(String),
}

pub(crate) struct TurboSession<S> {
    client_id: [u8; 8],
    dial: Dial<S>,
    connection: Connection<S>,
    silent_connections: u32,
}

async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    dial: Dial<S>,
    client_id: [u8; 8],
) -> Result<TurboStream<S>> {
    let stream = dial().await?;
    let mut turbo = TurboStream::with_client_id(stream, client_id);
    turbo.initialize().await?;
    Ok(turbo)
}

fn up<S>(turbo: TurboStream<S>) -> Connection<S> {
    Connection::Up {
        turbo,
        heard: Instant::now(),
        silence: TimeoutFuture::new(SILENCE_TIMEOUT.as_millis() as u32),
        delivered: false,
    }
}

/// What reading from the current connection came to.
enum Outcome {
    Read(usize),
    Lost(String),
    Waiting,
}

impl<S: AsyncRead + AsyncWrite + Unpin + 'static> TurboSession<S> {
    /// Open a session on its first connection. A failure here belongs to the
    /// bootstrap that asked, so it is returned rather than redialed.
    pub(crate) async fn open(dial: Dial<S>) -> Result<Self> {
        let client_id = rand::random();
        let turbo = connect(dial.clone(), client_id).await?;
        Ok(Self {
            client_id,
            dial,
            connection: up(turbo),
            silent_connections: 0,
        })
    }

    /// Give up the current connection, for `reason`, and dial another.
    fn redial(&mut self, reason: &str) {
        if let Connection::Up { delivered, .. } = &self.connection {
            self.silent_connections = if *delivered {
                0
            } else {
                self.silent_connections + 1
            };
        }
        if self.silent_connections >= MAX_SILENT_CONNECTIONS {
            warn!("Snowflake connection lost ({reason}), and {MAX_SILENT_CONNECTIONS} in a row delivered nothing; giving the session up");
            self.connection = Connection::Failed(format!(
                "Snowflake session lost: {MAX_SILENT_CONNECTIONS} connections in a row delivered nothing"
            ));
            return;
        }
        warn!("Snowflake connection lost ({reason}); dialing another for the same session");
        self.connection = Connection::Dialing(connect(self.dial.clone(), self.client_id).boxed_local());
    }

    /// Drive a dial in progress: ready once a connection is up, or the
    /// session has failed.
    fn poll_up(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.connection {
                Connection::Up { .. } => return Poll::Ready(Ok(())),
                Connection::Failed(message) => {
                    return Poll::Ready(Err(io::Error::other(message.clone())))
                }
                Connection::Dialing(dialing) => match ready!(dialing.as_mut().poll(cx)) {
                    Ok(turbo) => {
                        info!("Snowflake session resumed on a new connection");
                        self.connection = up(turbo);
                    }
                    Err(error) => {
                        warn!("Could not dial another Snowflake connection: {error}");
                        self.connection =
                            Connection::Failed(format!("Snowflake session lost: {error}"));
                    }
                },
            }
        }
    }

    fn poll_current(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Outcome {
        let Connection::Up {
            turbo,
            heard,
            silence,
            delivered,
        } = &mut self.connection
        else {
            return Outcome::Waiting;
        };
        match Pin::new(turbo).poll_read(cx, buf) {
            Poll::Ready(Ok(0)) => Outcome::Lost("the connection closed".to_string()),
            Poll::Ready(Ok(read)) => {
                *heard = Instant::now();
                *delivered = true;
                Outcome::Read(read)
            }
            Poll::Ready(Err(error)) => Outcome::Lost(error.to_string()),
            Poll::Pending => loop {
                if Pin::new(&mut *silence).poll(cx).is_pending() {
                    return Outcome::Waiting;
                }
                let quiet = heard.elapsed();
                if quiet >= SILENCE_TIMEOUT {
                    return Outcome::Lost(format!(
                        "nothing arrived for {} seconds",
                        quiet.as_secs()
                    ));
                }
                // Something arrived since the timer was set: wait out the rest.
                *silence = TimeoutFuture::new((SILENCE_TIMEOUT - quiet).as_millis() as u32);
            },
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + 'static> AsyncRead for TurboSession<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            ready!(this.poll_up(cx))?;
            match this.poll_current(cx, buf) {
                Outcome::Read(read) => return Poll::Ready(Ok(read)),
                Outcome::Waiting => return Poll::Pending,
                Outcome::Lost(reason) => this.redial(&reason),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + 'static> AsyncWrite for TurboSession<S> {
    /// A packet that fails to go out is lost with its connection, and KCP
    /// sends it again; while a new connection is dialed, writes wait for it.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            ready!(this.poll_up(cx))?;
            let Connection::Up { turbo, .. } = &mut this.connection else {
                continue;
            };
            match ready!(Pin::new(turbo).poll_write(cx, buf)) {
                Ok(written) => return Poll::Ready(Ok(written)),
                Err(error) => this.redial(&error.to_string()),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            ready!(this.poll_up(cx))?;
            let Connection::Up { turbo, .. } = &mut this.connection else {
                continue;
            };
            match ready!(Pin::new(turbo).poll_flush(cx)) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(error) => this.redial(&error.to_string()),
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().connection {
            Connection::Up { turbo, .. } => Pin::new(turbo).poll_close(cx),
            Connection::Dialing(_) | Connection::Failed(_) => Poll::Ready(Ok(())),
        }
    }
}
