//! Snowflake client transport through volunteer WebRTC proxies.

use crate::error::{Result, TorError};
use crate::kcp_stream::{KcpConfig, KcpStream};
use crate::smux::SmuxStream;
use crate::turbo::TurboStream;
use crate::webrtc_stream::WebRtcStream;
use futures::{AsyncRead, AsyncWrite};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use subtle_tls::{TlsConfig, TlsConnector, TlsStream, TlsVersion};
use tracing::{info, warn};

const MAX_WEBRTC_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone)]
pub(crate) struct SnowflakeWebRtcConfig {
    pub(crate) broker_url: String,
    pub(crate) fingerprint: String,
    pub(crate) stun_urls: Vec<String>,
}

type SnowflakeWebRtcStack = SmuxStream<KcpStream<TurboStream<WebRtcStream>>>;

pub(crate) struct SnowflakeWebRtcStream {
    inner: TlsStream<SnowflakeWebRtcStack>,
}

// Browser WASM is single-threaded, while Arti requires its transport stream to
// satisfy Send at the generic boundary.
unsafe impl Send for SnowflakeWebRtcStream {}

impl SnowflakeWebRtcStream {
    pub(crate) async fn connect(config: SnowflakeWebRtcConfig) -> Result<Self> {
        let mut connected = None;
        let mut last_error = None;

        for attempt in 1..=MAX_WEBRTC_ATTEMPTS {
            info!("Connecting to a Snowflake volunteer proxy (attempt {attempt}/{MAX_WEBRTC_ATTEMPTS})");
            match WebRtcStream::connect(
                &config.broker_url,
                &config.fingerprint,
                &config.stun_urls,
            )
            .await
            {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) => {
                    warn!("Snowflake WebRTC attempt {attempt} failed: {error}");
                    if !error.is_retryable() {
                        return Err(error);
                    }
                    last_error = Some(error);
                    if attempt < MAX_WEBRTC_ATTEMPTS {
                        crate::retry::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }

        let webrtc = connected.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                TorError::network("Snowflake WebRTC failed after three attempts")
            })
        })?;

        let mut turbo = TurboStream::new(webrtc);
        turbo.initialize().await?;
        let kcp = KcpStream::new(turbo, KcpConfig::default());
        let mut smux = SmuxStream::with_stream_id(kcp, 3);
        smux.initialize().await?;

        let connector = TlsConnector::with_config(TlsConfig {
            // Tor authenticates the bridge through its CERTS cells.
            skip_verification: true,
            alpn_protocols: vec![],
            // subtle-tls carries TLS 1.2 again, but nothing here negotiates
            // it: every retained path requires TLS 1.3.
            version: TlsVersion::Tls13,
        });
        let inner = connector
            .connect(smux, "www.example.com")
            .await
            .map_err(|error| TorError::tls(format!("Snowflake TLS handshake failed: {error}")))?;
        info!("Snowflake connection established: WebRTC → Turbo → KCP → SMUX → TLS");

        Ok(Self { inner })
    }
}

impl tor_rtcompat::StreamOps for SnowflakeWebRtcStream {}

impl tor_rtcompat::CertifiedConn for SnowflakeWebRtcStream {
    fn peer_certificate(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inner.peer_certificate().map(|certificate| certificate.to_vec()))
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
