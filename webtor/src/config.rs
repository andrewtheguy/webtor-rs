//! Configuration options for the Tor client

use crate::isolation::StreamIsolationPolicy;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct LogCallback(pub Arc<dyn Fn(&str, LogType) + Send + Sync>);

impl fmt::Debug for LogCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogCallback")
    }
}

/// Snowflake bridge identity.
pub const SNOWFLAKE_FINGERPRINT: &str = "2B280B23E1107BB62ABFC40DDCC8824814F80A72";
pub const SNOWFLAKE_BROKER_URL: &str = "https://snowflake-broker.torproject.net/";

/// Bridge type configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeType {
    /// Standard Snowflake client transport through a volunteer WebRTC proxy.
    SnowflakeWebRtc {
        /// Broker used to exchange the WebRTC offer and answer.
        broker_url: String,
        /// STUN URLs supplied by the embedding application.
        stun_urls: Vec<String>,
    },
}

impl Default for BridgeType {
    fn default() -> Self {
        BridgeType::SnowflakeWebRtc {
            broker_url: SNOWFLAKE_BROKER_URL.to_string(),
            stun_urls: Vec::new(),
        }
    }
}

/// Configuration options for the TorClient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorClientOptions {
    /// Bridge configuration
    pub bridge: BridgeType,

    /// Timeout in milliseconds for establishing initial connections
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout: u64,

    /// Timeout in milliseconds for circuit creation and readiness
    #[serde(default = "default_circuit_timeout")]
    pub circuit_timeout: u64,

    /// Whether to create the first circuit immediately upon construction
    #[serde(default = "default_create_circuit_early")]
    pub create_circuit_early: bool,

    /// Interval in milliseconds between automatic circuit updates, or null to disable
    #[serde(default = "default_circuit_update_interval")]
    pub circuit_update_interval: Option<u64>,

    /// Time in milliseconds to allow old circuit usage before forcing new circuit during updates
    #[serde(default = "default_circuit_update_advance")]
    pub circuit_update_advance: u64,

    /// Optional bridge fingerprint (hex string) to verify the bridge identity
    pub bridge_fingerprint: Option<String>,

    /// Stream isolation policy for domain-based circuit separation
    #[serde(default)]
    pub stream_isolation: StreamIsolationPolicy,

    /// Optional logging callback function (for WASM bindings)
    #[serde(skip)]
    pub on_log: Option<LogCallback>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogType {
    Info,
    Success,
    Error,
}

impl std::fmt::Display for LogType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogType::Info => write!(f, "info"),
            LogType::Success => write!(f, "success"),
            LogType::Error => write!(f, "error"),
        }
    }
}

impl Default for TorClientOptions {
    fn default() -> Self {
        Self {
            bridge: BridgeType::default(),
            connection_timeout: default_connection_timeout(),
            circuit_timeout: default_circuit_timeout(),
            create_circuit_early: default_create_circuit_early(),
            circuit_update_interval: default_circuit_update_interval(),
            circuit_update_advance: default_circuit_update_advance(),
            bridge_fingerprint: None,
            stream_isolation: StreamIsolationPolicy::default(),
            on_log: None,
        }
    }
}

fn default_connection_timeout() -> u64 {
    15_000 // 15 seconds
}

fn default_circuit_timeout() -> u64 {
    90_000 // 90 seconds
}

fn default_create_circuit_early() -> bool {
    true
}

fn default_circuit_update_interval() -> Option<u64> {
    Some(600_000) // 10 minutes
}

fn default_circuit_update_advance() -> u64 {
    60_000 // 1 minute
}

/// Maximum number of circuits to maintain (for preemptive building)
pub const MAX_CIRCUITS: usize = 5;

/// Maximum circuits per isolation key (one circuit per first-party domain)
pub const MAX_CIRCUITS_PER_ISOLATION_KEY: usize = 1;

/// Age threshold for preemptive circuit building (circuit_timeout - 10 seconds)
pub const CIRCUIT_PREBUILD_AGE_THRESHOLD_MS: u64 = 80_000; // 90_000 - 10_000

impl TorClientOptions {
    /// Connect through a Snowflake volunteer proxy using the caller's STUN list.
    pub fn snowflake_webrtc(stun_urls: Vec<String>) -> Self {
        Self {
            bridge: BridgeType::SnowflakeWebRtc {
                broker_url: SNOWFLAKE_BROKER_URL.to_string(),
                stun_urls,
            },
            bridge_fingerprint: Some(SNOWFLAKE_FINGERPRINT.to_string()),
            ..Default::default()
        }
    }

    pub fn with_connection_timeout(mut self, timeout: u64) -> Self {
        self.connection_timeout = timeout;
        self
    }

    pub fn with_circuit_timeout(mut self, timeout: u64) -> Self {
        self.circuit_timeout = timeout;
        self
    }

    pub fn with_create_circuit_early(mut self, create_early: bool) -> Self {
        self.create_circuit_early = create_early;
        self
    }

    pub fn with_circuit_update_interval(mut self, interval: Option<u64>) -> Self {
        self.circuit_update_interval = interval;
        self
    }

    pub fn with_circuit_update_advance(mut self, advance: u64) -> Self {
        self.circuit_update_advance = advance;
        self
    }

    pub fn with_bridge_fingerprint(mut self, fingerprint: String) -> Self {
        self.bridge_fingerprint = Some(fingerprint);
        self
    }

    pub fn with_stream_isolation(mut self, policy: StreamIsolationPolicy) -> Self {
        self.stream_isolation = policy;
        self
    }

    pub fn with_on_log<F>(mut self, on_log: F) -> Self
    where
        F: Fn(&str, LogType) + Send + Sync + 'static,
    {
        self.on_log = Some(LogCallback(Arc::new(on_log)));
        self
    }

    pub fn connection_timeout_duration(&self) -> Duration {
        Duration::from_millis(self.connection_timeout)
    }

    pub fn circuit_timeout_duration(&self) -> Duration {
        Duration::from_millis(self.circuit_timeout)
    }

    pub fn circuit_update_interval_duration(&self) -> Option<Duration> {
        self.circuit_update_interval.map(Duration::from_millis)
    }

    pub fn circuit_update_advance_duration(&self) -> Duration {
        Duration::from_millis(self.circuit_update_advance)
    }
}
