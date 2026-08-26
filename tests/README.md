# tests

Drives the built `webtor-wasm` package in headless Chrome. Self-contained:
`playwright-core` is a devDependency of this repository, the pages are served
from a loopback port here, and the directory snapshot is built by a tool in
this directory.

## Running

```bash
npm run build      # required first: the harness imports webtor-wasm/pkg/
npm test           # tests/api.test.mjs   — no network, ~1s
npm run seed       # a directory snapshot, ~40 MiB, valid three hours
npm run test:live  # tests/live.test.mjs  — real onion services, ~1 minute
```

`CHROME_PATH` points at a Chrome-family binary (default
`/usr/bin/google-chrome`). `playwright-core` ships no browser of its own, which
is why it needs one already installed.

## The two suites

**`api.test.mjs`** covers what answers without a circuit: `isOnionHost`,
`parseOnionUrl`, and the option validation `WebtorClient.create` runs before it
touches the network — unknown keys, wrong types, a bridge that needs STUN. It
needs no Tor and no directory, so it is the one to run while editing.

**`live.test.mjs`** bootstraps one client and reuses it for every case:
directory cache export, an HTTP GET, a server-chosen 4xx, caller-supplied
headers, the schemes the client refuses, a WebSocket exchange, the
`maxMessageBytes` limit, and finally that a closed client refuses work. Each
case builds its own rendezvous — around five seconds — so the cost of the file
is the bootstrap plus roughly that per case.

Environment: `DIRECTORY_SEED` (default `tests/.directory-seed.json`), `BRIDGE`
(`websocket` or `webrtc`), `STUN_URLS` (comma-separated, for `webrtc`).

## The directory snapshot

`npm run seed` fetches the microdesc consensus and every microdescriptor in it
from a directory authority and writes them in the shape `directorySeed`
accepts. Without it the browser downloads the directory over a single Snowflake
circuit — and it needs *every* HSDir microdescriptor, because a relay's
position on the hash ring comes from the ed25519 identity in its
microdescriptor, so that is thousands of documents through one circuit.

Seeded, a bootstrap is a few seconds. A consensus is valid for three hours and
the client rejects an expired one, so a snapshot has to be rebuilt to stay
useful; a stale one is not fatal, since the client keeps the microdescriptors
it can still use and downloads only the consensus and the digests it is
missing.

## Targets

`support/targets.mjs` holds the public onion services the live suite uses: the
Tor Project's own site for HTTP, and onion Nostr relays for WebSocket and for
NIP-11 over HTTP. None of them is under our control, so each is a list and a
case takes the first that answers, giving each candidate 90 seconds before
moving on. A case fails only when every candidate fails, and the error then
says what each one said.

Relay addresses come from
[`0xtrr/onion-service-nostr-relays`](https://github.com/0xtrr/onion-service-nostr-relays),
which tracks no uptime; `docs/onion-relay-probe-2026-08-25.md` records one pass
over the whole list.

## How the harness works

WASM objects cannot cross the CDP boundary, so `harness/index.html` keeps the
client and its sockets in the page, keyed by id, and exposes methods that
return plain JSON. `support/browser.mjs` gives the Node side a `call(method,
...args)` that runs one of them. The harness re-throws WASM rejections — which
are plain strings — as `Error`s, which is what lets a test assert on the
message.

The directory snapshot is fetched by the page from the local server rather than
passed in as a `call` argument: forty megabytes does not want to travel through
CDP.
