# subtle-tls

A TLS 1.3 client for the retained browser WASM Tor transports. Cryptographic
operations use the browser Web Crypto API where it provides the required
primitive; all imported and generated Web Crypto keys are non-extractable.

The crate exposes a `TlsConnector` and a `TlsStream` implementing
`futures::io::AsyncRead` and `AsyncWrite`. It supports the TLS 1.3 cipher suites
and certificate roots needed by the Snowflake bridge, Tor Check, and Nostr
relay paths in this repository. It has no native runtime or TLS 1.2 fallback.

```rust
use futures::io::{AsyncReadExt, AsyncWriteExt};
use subtle_tls::{TlsConfig, TlsConnector};

let connector = TlsConnector::with_config(TlsConfig {
    skip_verification: false,
    alpn_protocols: vec!["http/1.1".to_string()],
});
let mut stream = connector.connect(transport, "example.com").await?;

stream.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
let mut response = Vec::new();
stream.read_to_end(&mut response).await?;
```

`skip_verification` is reserved for the self-signed Snowflake-to-bridge TLS
link, whose identity is authenticated by the subsequent Tor protocol. Tor
Check and Nostr relay connections use certificate and hostname verification.

Run `cargo test` from the `webtor-rs` workspace to execute the retained tests.

## License

MIT
