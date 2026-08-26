# webtor-rs

A source-minimized browser Tor client fork used by pTransfer's experimental
anonymous Nostr signaling. The repository contains the Rust workspace and the
generated `@andrewtheguy/anonymous-signaling-wasm` package consumed by the
adjacent pTransfer checkout.

Upstream provenance and the retained Arti crates are documented in
[UPSTREAM.md](./UPSTREAM.md).

## WASM API

`AnonymousSignalingClient.create()` bootstraps a circuit and verifies the exit
before it resolves, so every method below runs on a verified circuit.

- `connect(wss://...)` opens a Nostr relay WebSocket over a Tor stream. This is
  what pTransfer's anonymous signaling rides on.
- `httpRequest(method, url, headers, body)` issues one HTTP/1.1 request over the
  circuit and buffers the whole response (`{ status, headers, body }`, capped at
  8 MiB). It is not a browser `fetch`, so the origin's CORS policy does not
  apply and the server sees the exit address. Bodies are sent verbatim, so a
  multipart upload is assembled by the caller, and redirects are reported rather
  than followed. pTransfer uses it to probe whether public store-and-forward
  file hosts are usable from a Tor exit.
- `directoryCache()` exports the consensus and microdescriptors from the last
  successful bootstrap so the caller can persist them.

## Releases

The wasm-pack output is published as a `.tgz` asset on a GitHub release, and
that is what pTransfer installs:

```json
"@andrewtheguy/anonymous-signaling-wasm": "https://github.com/andrewtheguy/webtor-rs/releases/download/v<version>/andrewtheguy-anonymous-signaling-wasm-<version>.tgz"
```

The release version is the `anonymous-signaling-wasm` crate version — not the
workspace version, which still tracks the upstream webtor-rs lineage. Bump the
crate version, push `main`, and run the `Publish` workflow
(`gh workflow run publish.yml`): it reads the version from `cargo metadata`,
refuses to overwrite an existing release, builds the package, `npm pack`s it,
and creates the tag and release. A SemVer pre-release version such as
`0.0.1-alpha.1` is published as a GitHub pre-release automatically.

The current line is `0.0.1-alpha.*`: anonymous signaling is a proof of concept,
so the package is versioned as one.

## Local development override

The checked-in `anonymous-signaling-wasm/pkg/` is still the source of truth for
development against an unreleased build. With both repositories checked out
under the same parent directory, point pTransfer at it without touching its
`package.json`:

```bash
cd ../ptransfer
npm run wasm:local     # install the sibling build
npm run wasm:released  # go back to the released .tgz
```

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
