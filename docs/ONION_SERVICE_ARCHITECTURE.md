# Onion-Service Architecture

This document describes the Tor behavior implemented by `webtor` and exposed
to browser applications through `@andrewtheguy/webtor-wasm`. Applications own
whatever protocol they carry over an `OnionStream`; bridge bootstrapping,
directory validation, onion-service lookup and publication, and rendezvous
circuits belong to this repository.

## Scope and Security Boundary

webtor reaches and publishes v3 onion services only. It builds no exit
circuits, accepts only `http://` and `ws://` URLs at its higher-level APIs, and
offers raw onion streams for application protocols. There is no clearnet TLS
session to terminate inside WASM and no server certificate to validate: the
onion address commits to the service identity, and the rendezvous circuit is
encrypted end to end.

Tor hides the two application endpoints from one another, not from every
component of the path. The first transport peer sees the browser's network
address — the fixed bridge endpoint in direct WebSocket mode or the volunteer
proxy in WebRTC mode. HSDirs see descriptor publication or lookup, and a
rendezvous point sees two Tor circuits meet without learning either endpoint's
network address. Each relay otherwise sees only its adjacent circuit hops and
transport metadata. Onion-stream contents are protected by Tor; an embedding
application may encrypt them again under its own keys.

## Entering Tor Through Snowflake

Every circuit starts at a Snowflake bridge. `WebtorClient.create` offers two
paths to it:

| Bridge | Network path |
| --- | --- |
| `websocket` (default) | A direct WebSocket to one fixed Snowflake bridge endpoint. It uses no broker, volunteer proxy, or STUN and has fewer moving parts, but blocking that endpoint blocks the client. |
| `webrtc` | A volunteer proxy selected through the Snowflake broker over HTTPS. It requires caller-supplied STUN URLs and is harder to block, at the cost of another dependency and a slower start. |

For development, `bridgeUrl` and `bridgeFingerprint` replace the public
WebSocket bridge. They are accepted only together and only in `websocket` mode:
a URL without the bridge's RSA identity would ask the client to trust whatever
answered it. [`../scripts/local-bridge`](../scripts/local-bridge/README.md)
runs such a bridge on localhost.

## Directory Bootstrap and Seeds

An onion client needs more directory data than a client building ordinary exit
circuits. The HSDir hash ring depends on every HSDir relay's ed25519 identity,
so bootstrap downloads and verifies:

- the current microdescriptor consensus;
- the authority certificates that validate its signatures;
- a sample of eligible middle relays; and
- the microdescriptor of every relay carrying the HSDir flag.

The download runs one hop from the bridge and includes thousands of
microdescriptors, which makes it the slowest and least reliable part of a cold
public-bridge bootstrap.

`directoryCache()` exports the verified consensus, certificates, and
microdescriptors in a versioned JSON envelope. Passing that value back as
`directorySeed` lets a later client install it before downloading anything.
The seed has no authority of its own: webtor revalidates the consensus against
the included certificates and its pinned directory authorities, checks its
validity window, and accepts only a cache version it understands. When a
decoded seed carries a rejected consensus, webtor downloads a current one and
reuses cached microdescriptors whose digests it still names.

A currently valid consensus can still be undesirable for an application's
onion-service policy near a time-period boundary. webtor computes HSDir
placement from the consensus it installed; callers that require both peers to
use the wall clock's current onion-service period may impose a stricter
freshness rule before passing a seed to `create`.

The rule is the caller's; reading the consensus to apply it is not.
`describeDirectory(seed)` answers what a seed says about itself — its validity
window, the time period it places descriptors in, and the period covering any
instant — with no client, no network, and no trust claim, so an application
imposing a stricter rule does not carry a second implementation of the
placement arithmetic. Where the seed was stored is likewise outside webtor:
`directoryCache()` returns a string and `directorySeed` accepts one, and no
storage API is reachable from the wasm.

A published service refreshes the directory and republishes every 60–120
minutes, so the directory a long-lived client holds is not the one it
bootstrapped with. `onDirectoryChange` is handed each downloaded directory as
it is installed, in the same encoding `directoryCache()` returns, which is how
an application keeps a current seed without polling for one. A seed the caller
supplied is never announced back: nothing about the directory changed.

## Connecting to an Onion Service

For `connectStream`, `fetch`, or `connectWebSocket`, the client:

1. computes the onion-service time period and shared-random value from its
   installed consensus, blinds the service key, and selects the responsible
   HSDirs;
2. builds a circuit to an HSDir and fetches the signed descriptor;
3. builds a circuit to a rendezvous point and establishes a rendezvous cookie;
4. builds a circuit to one of the descriptor's introduction points and sends
   `INTRODUCE1`, carrying the rendezvous point and an hs-ntor handshake; and
5. verifies the service's `RENDEZVOUS2`, extends the rendezvous circuit by its
   virtual hs-ntor hop, and begins streams on it.

Steps 1 through 5 run once per service rather than once per stream. The
descriptor is kept for the lifetime it declares and dropped at a time period
turnover, since the subcredential it was fetched under belongs to that period;
the rendezvous circuit carries every later stream to the same service, as Tor
Browser's does. Concurrent connects to one service wait for the same
rendezvous. A kept circuit that fails a new `BEGIN` for any reason other than
an `END` from the service is replaced by a fresh rendezvous once, and a kept
descriptor none of whose introduction points answer is fetched again before
the connect fails.

The raw API stops at the resulting byte stream. `fetch` layers one HTTP/1.1
exchange on it, while `connectWebSocket` performs the RFC 6455 upgrade and owns
WebSocket framing, masking, fragmentation, and control frames.

## Publishing an Onion Service

`publishOnionService` runs the other half:

1. generate an onion-service identity in memory and derive its v3 address;
2. establish the requested number of introduction points, from 1 through 6;
3. blind the service identity separately for the current time period and every
   adjacent period for which the consensus supplies a shared-random value;
4. sign a descriptor for each period and upload it to that period's responsible
   HSDirs; and
5. answer each `INTRODUCE2` by building a circuit to the client's rendezvous
   point, completing hs-ntor as the responder, and handing the client's streams
   to `accept()`.

Initial publication succeeds only after the descriptor for the current period
has been stored. Failure to cover an adjacent period is logged but does not make
the current service unusable.

Descriptors expire and HSDir rings rotate, so publication is not a one-shot
operation. While the service remains open, webtor refreshes its directory and
republishes every 60–120 minutes, or shortly after a time-period boundary when
that comes first. It republishes for the current and supported adjacent periods
each time.

The identity key is never persisted. Closing or dropping the service stops
descriptor republication, tears down introduction and client circuits, and
wakes a pending `accept()` with `null`. Already-published descriptors remain on
HSDirs until they expire, but without live introduction points they cannot
reach the closed service.

Introduction points are maintained for the same reason descriptors are. A
point whose circuit ends says so — the circuit's end wakes the maintainer —
and one whose relay has left the consensus is spotted when the directory is
refreshed; either way it is retired, a replacement is established at a relay
none of the others are on, and the descriptor goes back up naming what is
actually answering. Uploads stay at most one a minute, so a relay that keeps
dropping its circuit cannot turn into a run of uploads, and a shortfall that
cannot be made up on the spot is retried on a delay that grows to ten minutes.
A publication that reached only some of the time periods leaves the same work
outstanding — the rings it missed still hold a descriptor naming the retired
point — and is retried on that timer rather than at the next republication,
whichever of the two loops made the change.

A retired point's circuit is dropped with it, where Arti keeps a retired one
answering until the last descriptor naming it has expired. It has no
persistent `INTRODUCE2` replay cache or other durable onion-service state.

## Ownership Above the Stream

webtor authenticates the onion service, creates the encrypted rendezvous
circuit, and delivers a reliable byte stream. It does not define application
passwords, message framing, content keys, transfer limits, or retry policy.
Those belong to the application using `OnionStream` and must be documented by
that application rather than here.
