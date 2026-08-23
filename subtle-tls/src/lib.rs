//! Browser TLS 1.3 implemented with Web Crypto.

mod cert;
mod crypto;
mod error;
mod handshake;
mod record;
mod stream;
mod trust_store;

pub use error::{Result, TlsError};
pub use stream::TlsStream;

pub struct TlsConnector {
    config: TlsConfig,
}

#[derive(Clone)]
pub struct TlsConfig {
    /// Skip certificate verification for the self-signed Tor bridge link only.
    pub skip_verification: bool,
    pub alpn_protocols: Vec<String>,
}

impl TlsConnector {
    pub fn with_config(config: TlsConfig) -> Self {
        Self { config }
    }

    pub async fn connect<S>(&self, stream: S, server_name: &str) -> Result<TlsStream<S>>
    where
        S: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin,
    {
        TlsStream::connect(stream, server_name, self.config.clone()).await
    }
}
