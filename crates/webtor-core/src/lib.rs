//! A browser Tor client for v3 onion services, without TLS.
//!
//! The client enters the network through a Snowflake bridge and only ever
//! builds circuits to onion services: it never uses an exit, so there is no
//! clearnet TLS to terminate inside WASM and no server certificate to check.
//! The onion address commits to the service key and the circuit is encrypted
//! end to end, which is why `http://` and `ws://` are the two schemes it
//! carries and `https://`/`wss://` are refused rather than tolerated.
//!
//! [`TorClient`] issues HTTP requests ([`TorClient::send`]), opens raw onion
//! streams ([`TorClient::open_stream`]) and, through [`onion_websocket`],
//! speaks RFC 6455 over one.

mod authority;
mod circuit;
mod client;
mod config;
mod dir_http;
mod directory;
mod error;
mod http;
mod kcp_stream;
mod onion;
mod onion_service;
mod onion_url;
pub mod onion_websocket;
mod relay;
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
pub use directory::{describe_directory, DirectoryDescription};
pub use onion_service::{OnionService, OnionServiceOptions};
pub use onion_url::{is_onion_host, OnionUrl};
pub use onion_websocket::{WebSocketMessage, WebSocketReader, WebSocketWriter};
pub use config::{BridgeType, LogType, TorClientOptions};
pub use error::{Result, TorError};
pub use http::{HttpRequest, HttpResponse};
pub use retry::with_timeout;
pub use tor_proto::client::stream::{DataReader, DataStream, DataWriter};
