# Onion service proof

A small Vite/React app that loads the locally built `webtor-wasm` package and
publishes a v3 onion service **from the browser tab**. The page generates the
service identity, establishes its own introduction points, uploads a signed
descriptor to the responsible HSDirs, and answers HTTP on the streams clients
open on the rendezvous circuits.

It is the other half of the client this repository already ships: same Tor
client, same Snowflake bridge, opposite direction.

## Run it

Build the WASM package first, then install and start the example:

```bash
cd /path/to/webtor-rs
bun run build
cd examples/onion-service-poc
bun install
bun run dev
```

Open the printed local URL and select **Publish onion service**. The first
bootstrap can take several minutes because the browser may need to download Tor
directory data over Snowflake; publishing then costs one circuit per
introduction point plus one per HSDir.

For a faster first run, create a current directory snapshot before starting
Vite:

```bash
bun run tor:directory
```

The generated `public/tor-directory.json` is intentionally ignored: a
microdescriptor consensus is valid for only a few hours, so rebuild it shortly
before testing rather than committing it.

## What to do with the address

The page prints `http://<address>.onion/`. Reach it from anywhere:

- **Fetch it back through Tor** in the page — the same client connects to the
  service over the network, so the whole round trip happens in one tab.
- Open the address in Tor Browser.
- `curl --socks5-hostname 127.0.0.1:9050 http://<address>.onion/` through a
  local Tor daemon.

The service answers only while the tab is open, and the identity key exists
only in that tab's memory: closing the page destroys the address for good.

## What a run proves

That a browser can be the *server* end of a Tor onion service: it signed an
ESTABLISH_INTRO with a key it generated, three relays accepted it as
introduction points, HSDirs accepted a descriptor signed by the blinded
identity, and a client that knew nothing but the address completed the hs-ntor
handshake against this tab and got bytes back.

There is no proxy, no backend, no inbound port. Every circuit starts at a
Snowflake bridge, which is also how the tab reaches the network at all.

## Limits

Everything a real service does about persistence is missing on purpose: no
identity key on disk, no descriptor re-upload as the time period rolls over, no
introduction point rotation or replacement when one dies, and no replay cache
for INTRODUCE2. A published descriptor lasts three hours; the service is
expected to outlive nothing.
