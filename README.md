# webtor-rs

A source-minimized browser Tor client fork used by pTransfer's experimental
anonymous Nostr signaling. The repository contains the Rust workspace and the
generated `@andrewtheguy/anonymous-signaling-wasm` package consumed by the
adjacent pTransfer checkout.

## What the client does

The client reaches Nostr relays only as v3 onion services. It never builds a
circuit to an exit, so there is no exit to verify, no clearnet TLS to
terminate inside WASM and no relay certificate to check: the onion address
commits to the service key and the onion circuit is encrypted end to end.

Bootstrap opens the Snowflake bridge channel and installs a directory — the
consensus plus microdescriptors for a sample of middle relays and for every
relay with the HSDir flag, since the HSDir hash ring is computed from all of
them. Connecting to a `.onion` then runs the onion client in `webtor/src/onion.rs`:

1. compute the current time period and shared random value from the
   consensus, blind the service key and pick the responsible HSDirs;
2. build a circuit bridge → middle → HSDir and fetch the descriptor;
3. build a circuit to a rendezvous point and establish a cookie there;
4. build a circuit to one of the descriptor's introduction points and send an
   `INTRODUCE1` carrying the rendezvous point and an hs-ntor handshake;
5. finish the handshake with the `RENDEZVOUS2` the service delivers and extend
   the rendezvous circuit by a virtual hop, then begin streams on it.

## WASM API

`AnonymousSignalingClient.create(directorySeed, stunUrls, websocketBridge)`
bootstraps and then fetches the Tor Project's own onion site
(`http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/`)
before it resolves, so a client that is handed to the caller has already
completed one full onion rendezvous.

- `connect(ws://<address>.onion[/path])` opens a Nostr relay WebSocket over an
  onion stream. `wss://` and clearnet hosts are refused.
- `directoryCache()` exports the consensus and microdescriptors from the last
  successful bootstrap so the caller can persist them and seed the next
  `create`. The cache format is versioned; a seed from an older client is
  rejected and a fresh directory is downloaded.

## Checking relays

Two tools answer whether an onion relay works, from different vantage points.

`scripts/onion-signaling-check/run.mjs` runs the WASM client itself in
headless Chrome — bootstrap, the onion-site check, then a `REQ` to each relay
given — which is the closest thing to what pTransfer will do:

```bash
npm run build
node scripts/onion-signaling-check/run.mjs ws://<addr>.onion ws://<addr>.onion
```

It expects `playwright-core` where pTransfer's live web test installs it
(`/tmp/ptransfer-web-live-e2e-cache`; override with `PLAYWRIGHT_CORE`) and a
Chrome-family binary (`CHROME_PATH`). It uses the direct Snowflake WebSocket
bridge; `WEBRTC_BRIDGE=1` selects the WebRTC path instead.

`scripts/onion_ws_probe.py` asks the same question through a running Tor's
SOCKS5 port, with no WASM involved, so it separates a relay being down from
the client being wrong:

```bash
./scripts/onion_ws_probe.py ws://<addr>.onion
TOR_SOCKS_PROXY='[fdb8::1]:32050' ./scripts/onion_ws_probe.py ws://<addr>.onion
```

Relay addresses come from
[`0xtrr/onion-service-nostr-relays`](https://github.com/0xtrr/onion-service-nostr-relays),
a community-maintained list with no uptime tracking; expect a share of any
sample to be gone. `docs/onion-relay-probe-2026-08-25.md` records one pass
over the whole list.

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
