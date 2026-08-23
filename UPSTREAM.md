# webtor-rs fork provenance

This directory is a source-minimized fork of
[`privacy-ethereum/webtor-rs`](https://github.com/privacy-ethereum/webtor-rs)
at commit `9be6e2f5e606c4c03e9639751c18d0d927a4c19d` (version 0.5.7).

Only the core browser Tor client, its TLS implementation, and the Arti crates
patched by upstream for WebAssembly are retained. Anonymous signaling uses the
Snowflake broker and browser WebRTC client transport with STUN URLs supplied by
the embedding application. The direct Snowflake WebSocket transport is retained
as an inactive alternative for a future explicit fallback policy. pTransfer
adds:

- `TorClient::open_stream`, an exit-side raw TCP stream API;
- `anonymous-signaling-wasm`, a TLS WebSocket binding used only for Nostr
  signaling; and
- non-extractable Web Crypto key generation/import in `subtle-tls`.

The vendored Arti tree contains only crates present in this workspace's resolved
Cargo graph. Optional and development-only crates that the project does not
resolve are not copied into the repository.

The upstream code is MIT-licensed. Vendored Arti crates retain their own
`MIT OR Apache-2.0` licensing metadata.
