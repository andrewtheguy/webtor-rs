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
mod onion_url;
mod relay;
pub mod relay_socket;
mod retry;
mod smux;
mod snowflake_broker;
mod snowflake_webrtc;
mod snowflake_ws;
mod time;
mod turbo;
mod wasm_runtime;
mod wasm_runtime_unsupported;
mod webrtc_stream;
mod websocket;

pub use client::TorClient;
pub use onion_url::{is_onion_host, OnionUrl};
pub use relay_socket::{RelayMessage, RelaySocketReader, RelaySocketWriter};
pub use config::{BridgeType, LogType, TorClientOptions};
pub use error::{Result, TorError};
pub use http::{HttpRequest, HttpResponse};
pub use retry::with_timeout;
pub use tor_proto::client::stream::DataStream;
