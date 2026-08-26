//! SubtleTLS — the TLS 1.3 client that fronts webtor's Tor link channel.
//!
//! A Tor relay's ORPort speaks TLS, so the bytes the Snowflake tunnel carries
//! to the bridge have to be a TLS session even though the browser already
//! wrapped the outer hop. This crate is that session, and only that session:
//! TLS 1.3, X25519, ChaCha20-Poly1305, no certificate validation. Tor does not
//! trust the TLS certificate; it authenticates the relay through the CERTS
//! cells exchanged on the channel, which need the peer certificate bytes and
//! nothing more. Everything is pure Rust, so the record layer can encrypt from
//! `poll_read`/`poll_write`.

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod record;
pub mod stream;

pub use error::{Result, TlsError};
pub use stream::TlsStream;
