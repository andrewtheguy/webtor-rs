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

## Onion relay probe

`scripts/onion_ws_probe.py` asks whether a Nostr relay exposed as an onion
service accepts a WebSocket and serves a `REQ` over it. The WASM client cannot
answer that yet — it has no onion client — so this speaks SOCKS5 to a running
Tor, then the WebSocket handshake and RFC 6455 framing by hand. Standard
library only.

```bash
./scripts/onion_ws_probe.py ws://<addr>.onion
TOR_SOCKS_PROXY='[fdb8::1]:32050' ./scripts/onion_ws_probe.py ws://<addr>.onion
```

The proxy defaults to `127.0.0.1:9050`; `--proxy` and `TOR_SOCKS_PROXY` both
override it, and an IPv6 literal needs brackets. It exits non-zero on failure
and names the step that failed, so a Tor SOCKS `0x04` (no descriptor, service
down) reads differently from a relay that upgrades and then refuses the `REQ`.

A `ws://` URL carries no TLS, which is the point: the onion protocol
authenticates the service against its own address and encrypts the circuit end
to end, so a relay reached this way needs neither an exit nor a certificate.
`wss://` is supported for relays that insist on it — including clearnet
relays through an exit, which is useful for comparison — with the certificate
deliberately unchecked, since these are routinely self-signed.

Relay addresses come from
[`0xtrr/onion-service-nostr-relays`](https://github.com/0xtrr/onion-service-nostr-relays),
a community-maintained list with no uptime tracking; expect a share of any
sample to be gone.

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
