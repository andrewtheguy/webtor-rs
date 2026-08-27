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

## Run it

`bridge.sh` wraps the podman commands:

```bash
scripts/local-bridge/bridge.sh start     # builds the image if it is missing
scripts/local-bridge/bridge.sh status
scripts/local-bridge/bridge.sh logs      # follow, ctrl-c to detach
scripts/local-bridge/bridge.sh stop
```

`start` waits for tor to generate the identity and prints what the client
needs:

```
export BRIDGE_URL=ws://localhost:8080/
export BRIDGE_FINGERPRINT=82F663FA372767B5373A3CA7EAD6F2F68F331ADB
```

`env` prints those two lines alone and `fingerprint` prints the identity alone,
so a shell can take them directly:

```bash
eval "$(scripts/local-bridge/bridge.sh env)" && bun run test:live
```

The container runs with `--rm` and no volume, so `stop` takes the whole thing
with it: the tor identity, the directory cache, all of it. Nothing about a
test bridge is worth keeping between runs, and a stale fingerprint outliving
the container it belonged to is a trap rather than a saving.

Two things follow. **The fingerprint is different on every start**, so read it
from `env` or `fingerprint` each time rather than pasting it somewhere and
forgetting — and neither answers while the bridge is down, since there is
nothing left to read. And each start refills the bridge's own directory cache,
which takes about 25 seconds to reach `Bootstrapped 100%`. It cannot serve
directory data before then; `status` says whether it has.

## Point something at it

The live suite:

```bash
eval "$(scripts/local-bridge/bridge.sh env)" && bun run test:live
```

The onion service example, in `examples/onion-service-poc/.env.local`:

```
VITE_BRIDGE_URL=ws://localhost:8080/
VITE_BRIDGE_FINGERPRINT=<what `bridge.sh fingerprint` prints>
```

That one has to be rewritten after every `bridge.sh start`, since the
fingerprint it names is gone. The client refuses a wrong one at `create()`
rather than failing later in the channel handshake, so a stale file is a clear
error and not a mystery.

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
BridgeDB, `AssumeReachable 1` skips the ORPort self-test that could never pass
from inside a container with no inbound port, and `bridge.sh` publishes the
port on `127.0.0.1` only. All three are safe only because this bridge is never
handed to anybody. Do not lift this torrc into anything
that is.

It is also not anonymity: the bridge sees your IP, which the public one does
not, since a volunteer proxy sits in front of it. That is fine for a test rig
and wrong for anything else.
