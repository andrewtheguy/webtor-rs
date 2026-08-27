# A Snowflake bridge on localhost

The public Snowflake bridge is the slowest thing in a cold start, and not
because of the WebRTC rendezvous: webtor fetches the consensus, the authority
certificates and every HSDir microdescriptor **one hop from the bridge**
(`create_firsthop_fast` in `webtor/src/directory.rs`). That is megabytes across
a shared volunteer bridge. Run your own and the same download is local.

The container is the real `snowflake-server` in front of a real tor bridge, so
it exercises the same turbotunnel/KCP/smux path as the public one. Only the
first hop changes; circuits still extend into the real Tor network.

Measured: a cold `bun run test:live` with no directory seed at all — 5352
microdescriptors in 117 batches — bootstraps in **7.1 s**, and the whole live
suite, publishing an onion service and round-tripping to it included, finishes
in 40 s. Against the public bridge the same seedless bootstrap takes minutes.

## Build and run

```bash
podman build -t localhost/webtor-local-bridge scripts/local-bridge
podman run -d --name webtor-bridge -p 127.0.0.1:8080:8080 \
  -v webtor-bridge-data:/var/lib/tor localhost/webtor-local-bridge
podman logs -f webtor-bridge
```

The `-p 127.0.0.1:` prefix matters: this bridge has no anonymity story and no
business being reachable from the rest of the network.

Wait for `Bootstrapped 100%`, which takes a minute or two on first start — the
bridge has to fill its own directory cache before it can serve yours. The logs
print what you need:

```
bridge fingerprint: 82F663FA372767B5373A3CA7EAD6F2F68F331ADB
bridge websocket:   ws://localhost:8080/
```

Keep the named volume. The fingerprint is the identity tor generated on first
start; without the volume it changes every run and every config below goes
stale.

## Point something at it

The live suite:

```bash
BRIDGE_URL=ws://localhost:8080/ \
BRIDGE_FINGERPRINT=<fingerprint from the logs> \
bun run test:live
```

The onion service example, in `examples/onion-service-poc/.env.local`:

```
VITE_BRIDGE_URL=ws://localhost:8080/
VITE_BRIDGE_FINGERPRINT=<fingerprint from the logs>
```

Both are all-or-nothing. A URL with no fingerprint is a request to trust
whatever answers on that port, so it is refused rather than defaulted.

`ws://` and not `wss://` is deliberate: `-disable-tls` avoids a certificate for
a bridge only this machine reaches, and the browser allows a `ws://localhost`
connection from an `http://localhost` page. Serving the page over HTTPS would
make it mixed content, at which point the bridge needs a certificate.

`Couldn't format extend cell` once a minute in the logs is expected and
harmless — tor keeps trying to build a self-test circuit to an ORPort that has
no routable address here. Client circuits are unaffected; the measurements
above were taken with those warnings scrolling past.

## What this is not

A bridge anyone else should use. `PublishServerDescriptor 0` keeps it out of
BridgeDB and `AssumeReachable 1` skips the ORPort self-test that could never
pass from inside a container with no inbound port. Both are safe only because
this bridge is never handed to anybody. Do not lift this torrc into anything
that is.

It is also not anonymity: the bridge sees your IP, which the public one does
not, since a volunteer proxy sits in front of it. That is fine for a test rig
and wrong for anything else.
