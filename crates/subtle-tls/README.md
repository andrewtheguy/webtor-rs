# subtle-tls

The TLS 1.3 client that fronts webtor's Tor link channel.

A Tor relay's ORPort speaks TLS, so the bytes a Snowflake tunnel carries to the
bridge have to be a TLS session even though the browser already wrapped the
outer hop. This crate is that session and nothing else — it is not a general
TLS library, and it should not be used as one.

## Scope

One profile, no negotiation:

- TLS 1.3 only. There is no TLS 1.2 fallback and no earlier version.
- X25519 key exchange only (`crypto::X25519KeyPair`), advertised as the sole
  supported group.
- ChaCha20-Poly1305 only, with SHA-256 for the transcript and HKDF.
- **No certificate validation, no hostname verification and no trust store.**
  The server's certificate is accepted as presented and handed back through
  `TlsStream::peer_certificate`. Tor does not trust the TLS certificate: it
  authenticates the relay through the CERTS cells exchanged on the channel,
  which need the peer certificate bytes and nothing more.
- `server_name` fills the SNI extension and has no other effect.

Everything is pure Rust (`chacha20poly1305`, `sha2`, `hmac`, `x25519-dalek`),
so the record layer can encrypt from inside `poll_read`/`poll_write` without an
await point. The crate name is a leftover: an earlier version reached for the
browser's SubtleCrypto API, which is async and therefore could not be called
from a `poll_` method. Nothing here touches WebCrypto today.

## Usage

`TlsStream::connect` performs the handshake and returns a stream implementing
`futures::io::AsyncRead + AsyncWrite`.

```rust
use futures::io::{AsyncReadExt, AsyncWriteExt};
use subtle_tls::TlsStream;

let mut tls = TlsStream::connect(transport, "snowflake.torproject.net").await?;
tls.write_all(&cell).await?;
let mut buffer = [0u8; 512];
let count = tls.read(&mut buffer).await?;

// What Tor actually authenticates the peer with:
let der = tls.peer_certificate();
```

In webtor this wraps the Snowflake transports — see `snowflake_ws.rs` and
`snowflake_webrtc.rs` — and the resulting stream is what `tor-proto` builds its
channel on.

## Layout

```
src/
├── lib.rs        # re-exports: TlsStream, TlsError, Result
├── crypto.rs     # X25519, ChaCha20-Poly1305, SHA-256, HMAC, HKDF
├── handshake.rs  # ClientHello/ServerHello, key schedule, transcript
├── record.rs     # record layer framing and encryption
├── stream.rs     # TlsStream: handshake driver + AsyncRead/AsyncWrite
└── error.rs      # TlsError
```

## Tests

Unit tests cover the crypto primitives and the record layer, and run natively:

```bash
cargo test -p subtle-tls
```

The handshake itself has no offline test; it is exercised end to end whenever
webtor bootstraps, since every bootstrap opens a channel to the bridge through
this crate.

## License

MIT
