# webtor-rs

A source-minimized browser Tor client fork used by pTransfer's experimental
anonymous Nostr signaling. The repository contains the Rust workspace and the
generated `@andrewtheguy/anonymous-signaling-wasm` package consumed by the
adjacent pTransfer checkout.

Upstream provenance and the retained Arti crates are documented in
[UPSTREAM.md](./UPSTREAM.md).

## Local package layout

pTransfer consumes the checked-in wasm-pack output directly from this sibling
repository:

```json
"@andrewtheguy/anonymous-signaling-wasm": "file:../webtor-rs/anonymous-signaling-wasm/pkg"
```

Keep the two repositories next to each other under the same parent directory.
Normal pTransfer builds use the generated package and do not compile Rust.

## Development

After changing Rust, regenerate the package and validate the workspace:

```bash
npm install
npm run build
cargo clippy
cargo test
```

Commit the regenerated `anonymous-signaling-wasm/pkg/` files with the source
change so local consumers always receive matching JavaScript, declarations,
and WebAssembly.
