//! Browser WASM Tor transport for pTransfer's anonymous Nostr signaling.
//!
//! The active entry path uses Snowflake WebRTC. A direct browser Snowflake
//! WebSocket entry path is retained for a future explicit transport policy.

mod circuit;
mod client;
mod config;
mod directory;
mod error;
mod http;
mod kcp_stream;
mod onion;
mod relay;
mod retry;
mod smux;
mod snowflake_broker;
mod snowflake_webrtc;
mod snowflake_ws;
mod time;
mod turbo;
mod wasm_runtime;
mod webrtc_stream;
mod websocket;

pub use client::{is_onion_host, TorClient};
pub use config::{BridgeType, LogType, TorClientOptions};
pub use error::{Result, TorError};
pub use http::{HttpRequest, HttpResponse};
pub use retry::with_timeout;
pub use tor_proto::client::stream::DataStream;
