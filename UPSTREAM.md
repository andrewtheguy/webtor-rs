# webtor-rs fork provenance

This repository is a source-minimized fork of
[`privacy-ethereum/webtor-rs`](https://github.com/privacy-ethereum/webtor-rs)
at commit `9be6e2f5e606c4c03e9639751c18d0d927a4c19d` (version 0.5.7).

Only the core browser Tor client, a minimal TLS 1.3 client for the bridge
link, and the Arti crates needed for an onion-service client in WebAssembly
are retained.
Anonymous signaling uses the Snowflake broker and browser WebRTC client
transport with STUN URLs supplied by the embedding application. The direct
browser Snowflake WebSocket transport is also retained, selectable per transfer
from the Anonymous signaling options; it is not an automatic fallback.
pTransfer adds:

- `webtor/src/onion.rs`, a v3 onion-service client written on `tor-proto`:
  HSDir ring selection, descriptor fetch and decryption, and the
  introduce/rendezvous exchange. Upstream never had one, and Arti's own
  `tor-hsclient` needs `tor-circmgr`, `tor-netdir` and friends, which do not
  fit a browser;
- `TorClient::open_stream`, a raw stream API that only reaches `.onion` hosts;
- `webtor::relay_socket`, an RFC 6455 client for the Nostr relay socket
  (text frames, ping/pong, close) so the wasm carries no HTTP parser or
  general WebSocket stack, and `webtor::OnionUrl`, which parses the one URL
  shape reached here (`scheme://<v3 onion>[:port][/path][?query]`) so the
  `url` crate and its IDNA/Unicode tables stay out of the binary; and
- `anonymous-signaling-wasm`, a plain WebSocket binding used only for Nostr
  signaling over onion streams, with a console subscriber for `tracing`
  warnings and errors so a reactor's exit reason reaches the browser console.

Directory bootstrap keeps the microdescriptors of a supplied directory whose
consensus has expired: microdescriptors have no lifetime of their own, so a
fresh consensus names almost all of them and only the rest are downloaded.
Directory requests are bounded, and a bridge instance that stops answering
(Snowflake balances one fingerprint over several) costs one reconnect.

The fork keeps only those two browser entry transports, on-demand onion
circuits, and the TLS session a Tor relay's ORPort demands on the bridge
channel. Upstream's native runtime, exit circuits, general HTTP client,
isolation and circuit-pool policies, cancellation, background-update, and
alternate bridge paths are gone, and so is every clearnet path pTransfer once
carried: exit verification, the CA bundle, and relay TLS. `subtle-tls` is cut
to that one job: TLS 1.3 with X25519 and ChaCha20-Poly1305, pure Rust with no
SubtleCrypto, no TLS 1.2, no AES, and no certificate validation — Tor
authenticates the bridge through its CERTS cells, which need only the peer
certificate bytes. The crates still compile for the host so `cargo check`,
`cargo clippy`, and `cargo test` work there, but browser APIs only run in a
browser.

Arti dependencies come directly from crates.io. The vendored Arti tree is
limited to `tor-proto`, kept as the unmodified crates.io package apart from one
divergence: its channel and channel-reactor generic bound is relaxed from the
full `tor_rtcompat::Runtime` trait to `CoarseTimeProvider + SleepProvider`,
which is all a browser client driving an already-connected stream can supply.
`vendor/arti/README.md` records the baseline and the upgrade procedure.

The upstream code is MIT-licensed. Vendored Arti crates retain their own
`MIT OR Apache-2.0` licensing metadata.
