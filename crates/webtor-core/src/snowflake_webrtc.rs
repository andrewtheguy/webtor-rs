//! Snowflake client transport through volunteer WebRTC proxies.

use crate::error::{Result, TorError};
use crate::kcp_stream::{KcpConfig, KcpStream};
use crate::smux::SmuxStream;
use crate::snowflake_broker::NatPolicy;
use crate::time::Instant;
use crate::turbotunnel::{Dial, TurboSession};
use crate::webrtc_stream::{PeerConnectionClass, WebRtcStream};
use futures::{AsyncRead, AsyncWrite, FutureExt};
use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;
use subtle_tls::TlsStream;
use tracing::{info, warn};

/// Proxies one connection asks the broker for before giving up. The broker
/// often has none to offer for a poll or two, and a matched proxy is often
/// unreachable, so a handful is not enough to ride out either.
const MAX_WEBRTC_ATTEMPTS: u32 = 10;
/// The least time from the start of one attempt to the start of the next, as
/// the official client's `ReconnectTimeout`: a broker that had no proxy is not
/// asked again at once, and an attempt that took longer is followed at once.
const ATTEMPT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub(crate) struct SnowflakeWebRtcConfig {
    pub(crate) broker_url: String,
    pub(crate) fingerprint: String,
    pub(crate) stun_urls: Vec<String>,
    pub(crate) peer_connection: PeerConnectionClass,
}

type SnowflakeWebRtcStack = SmuxStream<KcpStream<TurboSession<WebRtcStream>>>;

pub(crate) struct SnowflakeWebRtcStream {
    inner: TlsStream<SnowflakeWebRtcStack>,
}

// Browser WASM is single-threaded, while Arti requires its transport stream to
// satisfy Send at the generic boundary. Threaded WASM is not single-threaded,
// so it gets no such claim and fails to compile instead.
#[cfg(not(target_feature = "atomics"))]
unsafe impl Send for SnowflakeWebRtcStream {}

impl SnowflakeWebRtcStream {
    pub(crate) async fn connect(config: SnowflakeWebRtcConfig, nat: Rc<NatPolicy>) -> Result<Self> {
        let config = Rc::new(config);
        let dial: Dial<WebRtcStream> = Rc::new(move || {
            let config = config.clone();
            let nat = nat.clone();
            async move { dial_proxy(&config, &nat).await }.boxed_local()
        });
        let session = TurboSession::open(dial).await?;
        let kcp = KcpStream::new(session, KcpConfig::default());
        let mut smux = SmuxStream::with_stream_id(kcp, 3);
        smux.initialize().await?;

        // Tor authenticates the bridge through its CERTS cells, so the TLS
        // layer only has to exist; the SNI is filler.
        let inner = TlsStream::connect(smux, "www.example.com")
            .await
            .map_err(|error| TorError::tls(format!("Snowflake TLS handshake failed: {error}")))?;
        info!("Snowflake connection established: WebRTC → Turbo → KCP → SMUX → TLS");

        Ok(Self { inner })
    }
}

/// A data channel through the first volunteer proxy that can be reached, for
/// the session's first connection and for every one after it.
async fn dial_proxy(config: &SnowflakeWebRtcConfig, nat: &NatPolicy) -> Result<WebRtcStream> {
    let mut last_error = None;
    for attempt in 1..=MAX_WEBRTC_ATTEMPTS {
        let started = Instant::now();
        info!("Connecting to a Snowflake volunteer proxy (attempt {attempt}/{MAX_WEBRTC_ATTEMPTS})");
        match WebRtcStream::connect(
            &config.broker_url,
            &config.fingerprint,
            &config.stun_urls,
            &config.peer_connection,
            nat,
        )
        .await
        {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                warn!("Snowflake WebRTC attempt {attempt} failed: {error}");
                if !error.is_retryable() {
                    return Err(error);
                }
                last_error = Some(error);
                let wait = ATTEMPT_INTERVAL.saturating_sub(started.elapsed());
                if attempt < MAX_WEBRTC_ATTEMPTS && !wait.is_zero() {
                    crate::retry::sleep(wait).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        TorError::network(format!(
            "Snowflake WebRTC failed after {MAX_WEBRTC_ATTEMPTS} attempts"
        ))
    }))
}

impl tor_rtcompat::StreamOps for SnowflakeWebRtcStream {}

impl tor_rtcompat::CertifiedConn for SnowflakeWebRtcStream {
    fn peer_certificate(&self) -> io::Result<Option<Cow<'_, [u8]>>> {
        Ok(self.inner.peer_certificate().map(Cow::Borrowed))
    }

    fn own_certificate(&self) -> io::Result<Option<Cow<'_, [u8]>>> {
        Ok(None)
    }

    fn export_keying_material(
        &self,
        length: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        tracing::warn!("export_keying_material is not implemented for browser Snowflake TLS");
        Ok(vec![0; length])
    }
}

impl AsyncRead for SnowflakeWebRtcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(context, output)
    }
}

impl AsyncWrite for SnowflakeWebRtcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
    }
}
