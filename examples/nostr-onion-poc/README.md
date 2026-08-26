# Nostr onion round-trip proof

A small Vite/React app that loads the locally built `webtor-wasm` package and
proves a Nostr message can be sent and received through an onion relay without
a proxy or backend.

The proof uses one Tor client and two independent onion WebSockets. It opens a
subscription on the first socket, waits for `EOSE`, publishes a freshly signed
kind `24243` event on the second, requires a positive relay `OK`, and verifies
the event and signature received by the subscriber. It never falls back to a
clearnet relay.

## Run it

Build the WASM package first, then install and start the example:

```bash
cd /path/to/webtor-rs
bun run build
cd examples/nostr-onion-poc
bun install
bun run dev
```

Open the printed local URL and select **Run round trip**. The first bootstrap
can take several minutes because the browser may need to download Tor directory
data over Snowflake. Later runs reuse a validated directory cache in IndexedDB.

For a faster first run, create a current directory snapshot before starting
Vite:

```bash
bun run tor:directory
```

The generated `public/tor-directory.json` is intentionally ignored. A Tor
microdescriptor consensus is valid for only a few hours, so rebuild it shortly
before testing rather than committing it.

## What the result proves

A passing run proves that this browser bootstrapped Tor, completed an onion
rendezvous, opened two RFC 6455 streams to the selected Nostr onion service,
published a valid signed event, received the relay's acceptance, and received
the same valid event on a separate subscribed stream.

The message is deliberately plaintext test data. Tor hides the browser's
network address from the relay, but it does not provide application-level
content encryption. The app uses ephemeral Nostr keys and an ephemeral event
kind with a five-minute expiration tag.

The relay candidates are the write-tested subset recorded in
[`../../docs/onion-relay-probe-2026-08-25.md`](../../docs/onion-relay-probe-2026-08-25.md).
They are public, independently operated services and can be unavailable.
