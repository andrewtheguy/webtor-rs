//! Future direct browser WebSocket transport for the Snowflake bridge.

use crate::error::{Result, TorError};
use crate::kcp_stream::{KcpConfig, KcpStream};
use crate::smux::SmuxStream;
use crate::turbo::TurboStream;
use crate::websocket::WebSocketStream;
use futures::{AsyncRead, AsyncWrite};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use subtle_tls::{TlsConfig, TlsConnector, TlsStream};

type SnowflakeWsStack = SmuxStream<KcpStream<TurboStream<WebSocketStream>>>;

pub(crate) struct SnowflakeWsStream {
    inner: TlsStream<SnowflakeWsStack>,
}

// Browser WASM is single-threaded; Arti requires channel streams to be Send.
unsafe impl Send for SnowflakeWsStream {}

impl SnowflakeWsStream {
    pub(crate) async fn connect(url: &str) -> Result<Self> {
        let websocket = WebSocketStream::connect(url).await?;
        let mut turbo = TurboStream::new(websocket);
        turbo.initialize().await?;
        let kcp = KcpStream::new(turbo, KcpConfig::default());
        let mut smux = SmuxStream::with_stream_id(kcp, 3);
        smux.initialize().await?;
        let connector = TlsConnector::with_config(TlsConfig {
            skip_verification: true,
            alpn_protocols: Vec::new(),
        });
        let inner = connector
            .connect(smux, "www.example.com")
            .await
            .map_err(|error| TorError::tls(format!("Snowflake TLS failed: {error}")))?;
        Ok(Self { inner })
    }
}

impl tor_rtcompat::StreamOps for SnowflakeWsStream {}

impl tor_rtcompat::CertifiedConn for SnowflakeWsStream {
    fn peer_certificate(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self
            .inner
            .peer_certificate()
            .map(|certificate| certificate.to_vec()))
    }

    fn export_keying_material(
        &self,
        length: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        tracing::warn!("export_keying_material is not implemented for browser Snowflake TLS");
        Ok(vec![0_u8; length])
    }
}

impl AsyncRead for SnowflakeWsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for SnowflakeWsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
    }
}
