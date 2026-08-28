//! Configuration for the browser Tor client.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct LogCallback(pub Arc<LogHandler>);

type LogHandler = dyn Fn(&str, LogType) + Send + Sync;

impl fmt::Debug for LogCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogCallback")
    }
}

/// Told about a directory the client downloaded, as the encoded seed a later
/// bootstrap would take.
#[derive(Clone)]
pub(crate) struct DirectoryCallback(pub Arc<DirectoryHandler>);

type DirectoryHandler = dyn Fn(&str) + Send + Sync;

impl fmt::Debug for DirectoryCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DirectoryCallback")
    }
}

/// The bridge every constructor here reaches unless the caller names another.
const PUBLIC_SNOWFLAKE_FINGERPRINT: &str = "2B280B23E1107BB62ABFC40DDCC8824814F80A72";
const SNOWFLAKE_BROKER_URL: &str = "https://snowflake-broker.torproject.net/";
const DIRECT_SNOWFLAKE_WS_URL: &str = "wss://snowflake.torproject.net/";

/// Browser transport used to reach the Snowflake bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeType {
    /// Through a volunteer Snowflake WebRTC proxy, brokered over HTTPS.
    SnowflakeWebRtc {
        broker_url: String,
        stun_urls: Vec<String>,
        fingerprint: String,
    },
    /// Direct browser WebSocket to the bridge, chosen explicitly by the caller.
    SnowflakeWebSocket { url: String, fingerprint: String },
}

impl BridgeType {
    /// The bridge's RSA identity. Nothing else authenticates a bridge, so a
    /// wrong value here fails the channel handshake; it cannot quietly put the
    /// client on some other relay.
    pub(crate) fn fingerprint(&self) -> &str {
        match self {
            Self::SnowflakeWebRtc { fingerprint, .. }
            | Self::SnowflakeWebSocket { fingerprint, .. } => fingerprint,
        }
    }
}

/// Client options. The bridge choice is the only transport decision: a
/// browser cannot open a raw socket to a guard, so entry is always Snowflake.
#[derive(Debug, Clone)]
pub struct TorClientOptions {
    pub bridge: BridgeType,
    connection_timeout: u64,
    pub(crate) on_log: Option<LogCallback>,
    pub(crate) on_directory_change: Option<DirectoryCallback>,
}

#[derive(Debug, Clone, Copy)]
pub enum LogType {
    Info,
    Success,
    /// Something went wrong that the client is carrying on past, including
    /// every `tracing` warning the Arti crates emit under it.
    Warn,
    Error,
}

impl TorClientOptions {
    pub fn snowflake_webrtc(stun_urls: Vec<String>) -> Self {
        Self {
            bridge: BridgeType::SnowflakeWebRtc {
                broker_url: SNOWFLAKE_BROKER_URL.to_string(),
                stun_urls,
                fingerprint: PUBLIC_SNOWFLAKE_FINGERPRINT.to_string(),
            },
            connection_timeout: 300_000,
            on_log: None,
            on_directory_change: None,
        }
    }

    /// Construct the direct browser WebSocket transport: no broker, no
    /// volunteer proxy, and no STUN, at the cost of one fixed endpoint.
    pub fn snowflake_websocket() -> Self {
        Self {
            bridge: BridgeType::SnowflakeWebSocket {
                url: DIRECT_SNOWFLAKE_WS_URL.to_string(),
                fingerprint: PUBLIC_SNOWFLAKE_FINGERPRINT.to_string(),
            },
            connection_timeout: 300_000,
            on_log: None,
            on_directory_change: None,
        }
    }

    /// The same transport aimed at a bridge the caller runs, which has its own
    /// RSA identity: `scripts/local-bridge` puts one on localhost so a test
    /// does not have to pull the whole directory across the public bridge.
    pub fn snowflake_websocket_at(url: String, fingerprint: String) -> Self {
        Self {
            bridge: BridgeType::SnowflakeWebSocket { url, fingerprint },
            connection_timeout: 300_000,
            on_log: None,
            on_directory_change: None,
        }
    }

    pub fn with_connection_timeout(mut self, timeout: u64) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn with_on_log<F>(mut self, on_log: F) -> Self
    where
        F: Fn(&str, LogType) + Send + Sync + 'static,
    {
        self.on_log = Some(LogCallback(Arc::new(on_log)));
        self
    }

    /// Take every directory this client downloads, encoded the way
    /// [`crate::TorClient::directory_cache_json`] encodes one.
    ///
    /// A client refreshes its directory while a published service is up, and
    /// `directory_cache_json` is a pull: without this, a caller that exported
    /// the cache once after bootstrap stores the directory it started with and
    /// never sees a newer one. Where the seed is kept is still entirely the
    /// caller's: this hands over a string and makes no assumption about what
    /// happens to it.
    ///
    /// A seed supplied through [`crate::TorClient::set_directory_seed`] is not
    /// announced. The caller already has it, and reporting it back would say a
    /// directory changed when none did.
    pub fn with_on_directory_change<F>(mut self, on_directory_change: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.on_directory_change = Some(DirectoryCallback(Arc::new(on_directory_change)));
        self
    }

    pub(crate) fn connection_timeout(&self) -> Duration {
        Duration::from_millis(self.connection_timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_path_is_explicit_and_fixed() {
        assert_eq!(
            TorClientOptions::snowflake_websocket().bridge,
            BridgeType::SnowflakeWebSocket {
                url: DIRECT_SNOWFLAKE_WS_URL.to_string(),
                fingerprint: PUBLIC_SNOWFLAKE_FINGERPRINT.to_string(),
            }
        );
    }

    #[test]
    fn a_named_bridge_replaces_both_the_url_and_the_identity() {
        let options = TorClientOptions::snowflake_websocket_at(
            "ws://localhost:8080/".to_string(),
            "AAAA".to_string(),
        );
        assert_eq!(options.bridge.fingerprint(), "AAAA");
        assert_eq!(
            options.bridge,
            BridgeType::SnowflakeWebSocket {
                url: "ws://localhost:8080/".to_string(),
                fingerprint: "AAAA".to_string(),
            }
        );
    }
}
