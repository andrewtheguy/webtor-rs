//! A Turbo tunnel session that outlives the connection carrying it.
//!
//! Snowflake's bridge keys a session by the client ID each connection opens
//! with, not by the connection. A new connection that opens with the same ID
//! picks the session up where the last one left it, and the bridge holds the
//! session's packets for a minute while no connection has it. So when a proxy
//! goes, or stops delivering, this dials another and carries on, as the
//! official client does: KCP above retransmits what was lost in between, and
//! nothing above KCP notices.

use crate::error::{Result, TorError};
use crate::retry::with_timeout;
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
/// How long after a connection is lost a replacement may still be dialed.
/// The Snowflake server forgets a client ID it has not used for a minute
/// (`clientMapTimeout`), and a connection that opens with a forgotten one
/// starts a session nothing above is waiting on.
const SESSION_RETENTION: Duration = Duration::from_secs(60);
/// The wait after a replacement fails to dial, doubling from the first to
/// the last, so that a bridge that is briefly unreachable is asked again soon
/// without being hammered.
const FIRST_REDIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_REDIAL_BACKOFF: Duration = Duration::from_secs(8);

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

/// Dial a replacement for a lost connection, and dial again after a failure
/// for as long as the bridge may still hold the session. A dial still going
/// when that time is up is given up, since what it would connect to is gone:
/// the session then fails, its Tor channel closes, and the channel is opened
/// again with a new session.
async fn reconnect<S: AsyncRead + AsyncWrite + Unpin>(
    dial: Dial<S>,
    client_id: [u8; 8],
) -> Result<TurboStream<S>> {
    let lost = Instant::now();
    let mut attempt = 0;
    loop {
        let remaining = SESSION_RETENTION.saturating_sub(lost.elapsed());
        let dialed = with_timeout(
            Duration::from_millis(remaining.as_millis() as u64),
            "Dialing another Snowflake connection while the bridge held the session",
            connect(dial.clone(), client_id),
        );
        let error = match dialed.await {
            Ok(turbo) => return Ok(turbo),
            Err(error) => error,
        };
        let Some(backoff) = redial_backoff(&error, attempt, lost.elapsed()) else {
            return Err(error);
        };
        warn!("Could not dial another Snowflake connection ({error}); trying again in {backoff:?}");
        crate::retry::sleep(backoff).await;
        attempt += 1;
    }
}

/// The wait before dialing again once replacement `attempt` has failed with
/// `error`, `since_lost` after the connection went; `None` when the failure
/// is not one a retry would fix, or the next dial would start after the
/// bridge has let the session go.
fn redial_backoff(error: &TorError, attempt: u32, since_lost: Duration) -> Option<Duration> {
    let backoff = FIRST_REDIAL_BACKOFF
        .saturating_mul(2u32.saturating_pow(attempt))
        .min(MAX_REDIAL_BACKOFF);
    (error.is_retryable() && since_lost + backoff < SESSION_RETENTION).then_some(backoff)
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
        self.connection =
            Connection::Dialing(reconnect(self.dial.clone(), self.client_id).boxed_local());
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
                        warn!("Could not dial another Snowflake connection ({error}); giving the session up");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_redial_backs_off_while_the_bridge_holds_the_session() {
        let unreachable = TorError::network("the bridge did not answer");
        let backoffs: Vec<_> = (0..5)
            .map(|attempt| redial_backoff(&unreachable, attempt, Duration::ZERO))
            .collect();
        let seconds = |s| Some(Duration::from_secs(s));
        assert_eq!(backoffs, [seconds(1), seconds(2), seconds(4), seconds(8), seconds(8)]);

        assert_eq!(redial_backoff(&unreachable, 3, Duration::from_secs(51)), seconds(8));
        assert_eq!(redial_backoff(&unreachable, 3, Duration::from_secs(52)), None);
        assert_eq!(
            redial_backoff(&TorError::Internal("no dial".to_string()), 0, Duration::ZERO),
            None
        );
    }
}
