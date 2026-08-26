use thiserror::Error;

pub type Result<T> = std::result::Result<T, TorError>;

#[derive(Error, Debug)]
pub enum TorError {
    #[error("WebSocket connection failed: {0}")]
    WebSocketConnection(String),
    #[error("Tor protocol error: {0}")]
    TorProtocol(String),
    #[error("Relay selection failed: {0}")]
    RelaySelection(String),
    #[error("Consensus fetch failed: {0}")]
    ConsensusFetch(String),
    #[error("Directory request returned HTTP {0}")]
    DirectoryStatus(u16),
    #[error("HTTP request failed: {0}")]
    HttpRequest(String),
    #[error("TLS setup failed: {0}")]
    TlsSetup(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("NetDoc error: {0}")]
    NetDoc(#[from] tor_netdoc::Error),

    #[error("Onion service error: {0}")]
    Onion(String),
}

impl TorError {
    pub fn websocket_connection(message: impl Into<String>) -> Self {
        Self::WebSocketConnection(message.into())
    }

    pub(crate) fn tor_protocol(message: impl Into<String>) -> Self {
        Self::TorProtocol(message.into())
    }

    pub(crate) fn relay_selection(message: impl Into<String>) -> Self {
        Self::RelaySelection(message.into())
    }

    pub(crate) fn http_request(message: impl Into<String>) -> Self {
        Self::HttpRequest(message.into())
    }

    pub fn tls(message: impl Into<String>) -> Self {
        Self::TlsSetup(message.into())
    }

    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self::Timeout(message.into())
    }

    pub(crate) fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration(message.into())
    }

    pub(crate) fn network(message: impl Into<String>) -> Self {
        Self::Network(message.into())
    }

    pub(crate) fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }

    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::WebSocketConnection(_)
                | Self::ConsensusFetch(_)
                | Self::HttpRequest(_)
                | Self::Timeout(_)
                | Self::Network(_)
                | Self::Io(_)
        )
    }
}
