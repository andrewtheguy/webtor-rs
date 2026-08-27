# webtor-rs

A browser Tor client, compiled to WASM, that reaches v3 onion services over
`http://` and `ws://`. No exit, no TLS, no proxy: the page builds Tor circuits
itself and speaks HTTP or RFC 6455 on them. It also runs v3 onion services the
other way around — the page publishes its own `.onion` address and answers what
clients send it.

The Rust workspace builds `@andrewtheguy/webtor-wasm`, the package a web app
installs.

## Why there is no TLS

Every destination is an onion service, so no circuit is ever built to an exit.
That removes the two things a browser cannot do well: there is no clearnet TLS
to terminate inside WASM and no server certificate to validate. The onion
address commits to the service key and the circuit is encrypted end to end, so
`https://` and `wss://` are refused rather than tolerated — a TLS layer over an
onion circuit would add nothing this client could check.

## What a connection does

Bootstrap opens the Snowflake bridge channel and installs a directory: the
consensus plus microdescriptors for a sample of middle relays and for every
relay with the HSDir flag, since the HSDir hash ring is computed from all of
them. Connecting to a `.onion` then runs the onion client in
`webtor/src/onion.rs`:

1. compute the current time period and shared random value from the consensus,
   blind the service key and pick the responsible HSDirs;
2. build a circuit bridge → middle → HSDir and fetch the descriptor;
3. build a circuit to a rendezvous point and establish a cookie there;
4. build a circuit to one of the descriptor's introduction points and send an
   `INTRODUCE1` carrying the rendezvous point and an hs-ntor handshake;
5. finish the handshake with the `RENDEZVOUS2` the service delivers and extend
   the rendezvous circuit by a virtual hop, then begin streams on it.

Publishing a service runs the same machinery from the other end, in
`webtor/src/onion_service.rs`: generate an identity keypair and derive the
address from it, establish introduction points with `ESTABLISH_INTRO`, sign a
descriptor naming them and upload it to the responsible HSDirs — for the
current time period and for the ones either side of it, so that a client whose
consensus places it in a neighbouring period still finds the service. Every
`INTRODUCE2` that arrives afterwards is answered by building a circuit to the
client's rendezvous point, completing the hs-ntor handshake as the responder,
and sending `RENDEZVOUS1`; the streams the client then begins are handed to the
caller. Nothing is stored: the identity key lives in the page and dies with the
service, so every address is ephemeral.

## Using it

```js
import init, { WebtorClient } from '@andrewtheguy/webtor-wasm';

await init();
const client = await WebtorClient.create({ directorySeed });

const response = await client.fetch('http://<address>.onion/status', {
  headers: { Accept: 'application/json' },
});
console.log(response.status, response.text());

const socket = await client.connectWebSocket('ws://<address>.onion/');
await socket.send('hello');
const message = await socket.receive();  // {type: "text", text} | {type: "binary", bytes}
await socket.close();

const service = await client.publishOnionService();
console.log(service.onionAddress);   // <56 characters>.onion, reachable now
const stream = await service.accept();
await stream.send(`you said: ${new TextDecoder().decode(await stream.receive())}`);
await stream.close();

await client.close();
```

### `WebtorClient.create(options?)`

Bootstraps a client. Every option is optional.

| Option | Default | Meaning |
| --- | --- | --- |
| `bridge` | `"websocket"` | `"websocket"` opens a direct WebSocket to the Snowflake bridge: one fixed endpoint, no broker, no volunteer proxy, no STUN. `"webrtc"` goes through a volunteer proxy brokered over HTTPS — harder to block, and it needs `stunUrls`. |
| `stunUrls` | — | STUN servers for the `"webrtc"` bridge; required there and refused otherwise. |
| `directorySeed` | — | A previous `directoryCache()`. Without one the client downloads the directory over a single bridge circuit, which is the slowest and least reliable part of a bootstrap. |
| `connectionTimeoutMs` | `300000` | Bootstrap budget. |
| `log` | `true` | Write bootstrap progress to the console. |
| `logPrefix` | `"[webtor]"` | |

An unknown option is an error, not a shrug: a misspelled `maxMessageBytes`
would otherwise leave a limit un-enforced for minutes before anything noticed.

`create` resolves once the client has a Tor channel and a directory, and it
reaches nothing on its own. A caller that wants proof of a full rendezvous
before it trusts the client does that itself — `fetch` whatever onion it
considers a good witness and check the status, the way
`examples/nostr-onion-poc` does. Which service is worth reaching is the
caller's question, and no third-party address is compiled into the wasm.

### Methods

- `fetch(url, options?)` — one HTTP/1.1 request to `http://<address>.onion`.
  Options: `method` (default `"GET"`), `headers`, `body` (string or
  `Uint8Array`), `timeoutMs` (default 240000). Resolves to an `OnionResponse`
  with `status`, `ok`, `headers`, `bytes()` and `text()`. A 4xx or 5xx is a
  response, not a rejection.
- `connectWebSocket(url, options?)` — RFC 6455 over an onion stream. Options:
  `maxMessageBytes` (default 1048576), `timeoutMs` (default 240000). The
  socket has `send(text)`, `sendBinary(bytes)`, `receive()` and `close()`;
  `receive()` answers pings itself and resolves to `null` once the peer closes.
  An `OnionStream` — what `connectStream` returns and what a published service
  accepts — is the same shape without the framing: `send(text)`,
  `sendBytes(bytes)`, `receive()` and `close()`, where `receive()` resolves to
  the next bytes or `null` at end of stream.
- `connectStream(address, port)` — a raw stream to an onion address and virtual
  port with nothing layered on top, for a service that speaks neither HTTP nor
  WebSocket. Resolves to an `OnionStream`.
- `publishOnionService(options?)` — publish a v3 onion service from this page.
  Options: `introPoints` (default 3, at most 6). Resolves once an HSDir has
  stored the descriptor, which is when clients can reach the address, to a
  service with `onionAddress`, `accept()` and `close()`. `accept()` resolves to
  the next client's `OnionStream`, or `null` once the service is closed;
  `close()` withdraws the introduction points and every client circuit. The
  identity key is generated in the page and never stored, so every call yields
  a new address that lives as long as the service.
- `directoryCache()` — the consensus, the authority certificates that check its
  signatures, and the microdescriptors from the last successful bootstrap, to
  persist and hand back as `directorySeed`. A seed is verified against the
  pinned directory authorities before any of it is installed, so it needs no
  trust of its own. The format is versioned; a seed from an older client is
  rejected and a fresh directory downloaded.
- `close()` — aborts calls still building circuits and tears the client down.

Two free functions need no client and touch no network: `isOnionHost(host)` and
`parseOnionUrl(url)`, which throws exactly what a request would.

## Tests

`tests/` is a self-contained project — it drives the built package in headless
Chrome and needs nothing outside this repository.

```bash
bun install       # install dependencies from bun.lock
bun run build     # wasm-pack the package into webtor-wasm/pkg/
bun run test      # API suite: URL helpers and option validation, no network
bun run seed      # fetch a directory snapshot to tests/.directory-seed.json
bun run test:live # end to end against public onion services
```

One test does reach outside the repository. `bun run test:interop` checks the
two halves against a known-good implementation — the `tor` proof of concept in
the sibling [ptransfer-cli](https://github.com/andrewtheguy/ptransfer-cli),
which publishes an ephemeral onion address and echoes back every line. The page
opens a raw stream to a service the CLI publishes, then publishes a service of
its own for the CLI to connect to, so a failure says which side is wrong.
Set `PTRANSFER_BIN` if the binary is not at
`../ptransfer-cli/target/release/ptransfer`, and `ONLY=client` or `ONLY=server`
to run one direction.

The repository pins its Bun version in `package.json`. `bun run test` is a
second or two. `bun run test:live` bootstraps a real Tor client
and builds a fresh set of circuits per case, so it runs in minutes; a snapshot
from `bun run seed` is what keeps the bootstrap to under a minute, and a
snapshot expires when its consensus does, three hours after it is made. See
`tests/README.md`.

`scripts/onion_ws_probe.py` asks the same question through a running Tor's
SOCKS5 port, with no WASM involved, so it separates a service being down from
the client being wrong:

```bash
./scripts/onion_ws_probe.py ws://<addr>.onion
TOR_SOCKS_PROXY='[fdb8::1]:32050' ./scripts/onion_ws_probe.py ws://<addr>.onion
```

## Browser Nostr proof

[`examples/nostr-onion-poc`](examples/nostr-onion-poc) is a small Vite/React
project that loads the local WASM build and performs a live Nostr round trip
through an onion relay. It uses separate subscriber and publisher streams,
requires the relay's positive publication acknowledgement, and verifies the
signed event received by the subscriber.

## Releases

The wasm-pack output is published as a `.tgz` asset on a GitHub release:

```json
"@andrewtheguy/webtor-wasm": "https://github.com/andrewtheguy/webtor-rs/releases/download/v<version>/andrewtheguy-webtor-wasm-<version>.tgz"
```

The release version is the `webtor-wasm` crate version — not the workspace
version, which tracks the upstream webtor-rs lineage. Bump the crate version,
push `main`, and run the `Publish` workflow (`gh workflow run publish.yml`): it
reads the version from `cargo metadata`, refuses to overwrite an existing
release, builds the package, `bun pm pack`s it, and creates the tag and release.
A SemVer pre-release version such as `0.0.1-alpha.1` is published as a GitHub
pre-release automatically.

The current line is `0.0.1-alpha.*`.

## Layout

```
webtor/       the Tor client: directory, circuits, onion rendezvous, HTTP, WebSocket
webtor-wasm/  the wasm-bindgen surface packed for distribution
subtle-tls/   the TLS 1.3 session the bridge channel runs inside (see its README)
tests/        the browser test project
examples/     standalone browser integrations
scripts/      onion_ws_probe.py, a SOCKS-based cross-check
```
