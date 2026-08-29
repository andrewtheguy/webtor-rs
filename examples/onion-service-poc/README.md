# Onion messaging proof

A small Vite/React app that loads the locally built `webtor-wasm` package and
passes messages between two browser tabs over Tor. Each tab picks a side:

- **Listen for messages** publishes a v3 onion service **from the tab**: it
  generates the service identity, establishes its own introduction points,
  uploads a signed descriptor to the responsible HSDirs, and reads the
  messages clients POST to it on the rendezvous circuits.
- **Send a message** POSTs to an address the other side printed, through a Tor
  client bootstrapped in the tab over Snowflake — or, when the page is open in
  Tor Browser, through the browser's own Tor.

## Run it

Build the WASM package first, then install and start the example:

```bash
cd /path/to/webtor-rs
bun run build
cd examples/onion-service-poc
bun install
bun run dev
```

Open the printed local URL in one tab, choose **Listen for messages** and
**Publish onion service**. The first bootstrap can take several minutes because
the browser may need to download Tor directory data over Snowflake; publishing
then costs one circuit per introduction point plus one per HSDir.

Open it again in a second tab (or another browser, or another machine), choose
**Send a message**, paste the address, write something, and send. The message
shows up in the listening tab.

For a faster first run, create a current directory snapshot before starting
Vite:

```bash
bun run tor:directory
```

The generated `public/tor-directory.json` is intentionally ignored: a
microdescriptor consensus is valid for only a few hours, so rebuild it shortly
before testing rather than committing it.

## The wire

A message is `POST http://<address>.onion/message` with a `text/plain` body of
up to 64 KiB; the listener answers `200` with a running count. Anything else on
the address gets a small HTML page. So a shell works as the sending side too:

```bash
curl --socks5-hostname 127.0.0.1:9050 -d hello http://<address>.onion/message
```

Every answer carries `Access-Control-Allow-Origin: *`, which is what lets a
sending page in Tor Browser read the reply with the browser's `fetch`.

## Sending from Tor Browser

The sending side probes on load whether the browser's own `fetch` reaches
`.onion` (an opaque request to torproject.org's onion, which fails fast
elsewhere) and, when it does, defaults **Send via** to the browser's Tor. The
listener then runs on its tab's Snowflake client while the message arrives
from a second, unrelated Tor client: proof that the address is reachable from
outside its own circuits, without the sending tab bootstrapping a client of
its own.

## What a run proves

That a browser can be the *server* end of a Tor onion service: it signed an
ESTABLISH_INTRO with a key it generated, the configured number of relays
accepted it as introduction points, HSDirs accepted a descriptor signed by the
blinded identity, and a client that knew nothing but the address completed the
hs-ntor handshake against this tab and delivered bytes.

There is no external Tor daemon, application proxy, backend, or inbound port.
Every circuit starts at a Snowflake bridge, which is also how the tab reaches
the network at all.

## Limits

The identity key is never written to disk, so closing the listening tab
permanently ends the address. While it stays open, the library refreshes the
directory and republishes descriptors for the current period and whichever
neighbouring periods the directory supports every 60–120 minutes, or shortly
after a period boundary, and replaces an introduction point whose circuit dies
or whose relay leaves the consensus. It has no persistent INTRODUCE2 replay
cache or other durable service state. Messages are held in the listening tab's
memory only.
