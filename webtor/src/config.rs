//! Configuration for the browser Tor signaling client.

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

pub(crate) const SNOWFLAKE_FINGERPRINT: &str =
    "2B280B23E1107BB62ABFC40DDCC8824814F80A72";
const SNOWFLAKE_BROKER_URL: &str = "https://snowflake-broker.torproject.net/";
const DIRECT_SNOWFLAKE_WS_URL: &str = "wss://snowflake.torproject.net/";

/// Browser transport used to reach the Snowflake bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeType {
    /// Current production path through a volunteer Snowflake WebRTC proxy.
    SnowflakeWebRtc {
        broker_url: String,
        stun_urls: Vec<String>,
    },
    /// Reserved browser WebSocket path for a future explicit transport policy.
    SnowflakeWebSocket { url: String },
}

/// Options intentionally limited to the two browser transports retained by pTransfer.
#[derive(Debug, Clone)]
pub struct TorClientOptions {
    pub bridge: BridgeType,
    connection_timeout: u64,
    pub(crate) on_log: Option<LogCallback>,
}

#[derive(Debug, Clone, Copy)]
pub enum LogType {
    Info,
    Success,
    Error,
}

impl TorClientOptions {
    pub fn snowflake_webrtc(stun_urls: Vec<String>) -> Self {
        Self {
            bridge: BridgeType::SnowflakeWebRtc {
                broker_url: SNOWFLAKE_BROKER_URL.to_string(),
                stun_urls,
            },
            connection_timeout: 240_000,
            on_log: None,
        }
    }

    /// Construct the future direct browser WebSocket transport explicitly.
    pub fn snowflake_websocket() -> Self {
        Self {
            bridge: BridgeType::SnowflakeWebSocket {
                url: DIRECT_SNOWFLAKE_WS_URL.to_string(),
            },
            connection_timeout: 240_000,
            on_log: None,
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
            }
        );
    }
}
