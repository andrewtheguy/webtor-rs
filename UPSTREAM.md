# webtor-rs fork provenance

This repository is a source-minimized fork of
[`privacy-ethereum/webtor-rs`](https://github.com/privacy-ethereum/webtor-rs)
at commit `9be6e2f5e606c4c03e9639751c18d0d927a4c19d` (version 0.5.7).

Only the core browser Tor client, the bridge-side TLS implementation, and the
Arti crates needed for an onion-service client in WebAssembly are retained.
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
- `anonymous-signaling-wasm`, a plain WebSocket binding used only for Nostr
  signaling over onion streams; and
- non-extractable Web Crypto key generation/import in `subtle-tls`.

The fork keeps only those two browser entry transports, on-demand onion
circuits, and the browser TLS implementation for the bridge channel. Upstream's
native runtime, exit circuits, general HTTP client, isolation and circuit-pool
policies, cancellation, background-update, and alternate bridge paths are gone,
and so is every clearnet path pTransfer once carried: exit verification, the
CA bundle, and relay TLS. The crates still compile for the host so
`cargo check`, `cargo clippy`, and `cargo test` work there, but browser APIs only
run in a browser.

The vendored Arti tree contains only crates present in this workspace's resolved
Cargo graph, with their sources pruned to what this workspace compiles.
Onion-service support restores the pruned `hs` modules of `tor-cell`,
`tor-netdoc`, `tor-proto` and `tor-linkspec`, and vendors `tor-hscrypto` with
its `tor-key-forge` key-encoding impls removed, since that crate drags in
`ssh-key` and nothing here stores keys. Optional and development-only crates
that the project does not resolve are not copied into the repository.

The upstream code is MIT-licensed. Vendored Arti crates retain their own
`MIT OR Apache-2.0` licensing metadata.
