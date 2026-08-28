# Roadmap

Things webtor cannot do, and what makes each one hard. Not a schedule and not
a list of intentions: each entry is written down because it will otherwise be
rediscovered from the outside, where it shows up as a service that quietly
stops working rather than as an error anyone can read.

The common thread is a service that outlives one page load. Everything here
already works for the case this client was built for — a page opens, publishes
an address, moves bytes, closes — and every entry below is a place where "for
hours" or "again tomorrow" turns out to be a different problem from "now".

Two things that *are* handled, so nobody adds them here: a published service
refreshes its directory and republishes its descriptor every 60–120 minutes,
or shortly after an onion-service time period turns over if that comes first,
which covers both descriptor expiry and the HSDir rings moving underneath it.
A caller keeps the refreshed directory through `onDirectoryChange`.

## A published address does not survive the page

`publish_onion_service` generates the identity keypair, and its public half
*is* the `.onion` address (`onion_service.rs`). The key never leaves that
function's memory, so every launch is a new address: a caller cannot restart a
service at the address it advertised, and anyone holding the old one reaches
nothing.

Persisting it is not the directory problem again. A directory seed needs no
trust of its own — the client revalidates it against the pinned authorities
whatever the page did with it in between — while the identity key *is* the
service's authority: whatever holds it can be the service. So the shape of an
answer is a key the caller supplies, generated and stored under whatever
protection that application can offer, rather than any storage inside webtor.
What makes it awkward is that the browser's own answer does not fit: a
non-extractable WebCrypto key cannot be handed to the Ed25519 signing Arti
does in WASM, so the material is ordinary bytes in linear memory no matter
where it was kept between runs.

## Nothing recovers a lost bridge channel

Every circuit rides one Snowflake channel. When its reactor stops, the client
logs a warning and goes on holding a dead handle: `ensure_ready` returns early
because `initialized` is still set, and only `close` clears it (`client.rs`).
A transfer notices and starts again. A service meant to stay up ends on one
dropped WebSocket.

The missing piece is less a reconnect loop than a decision about what
reconnecting means. Circuits do not survive a new channel, so an established
service loses its introduction points and every open stream along with it. A
caller told "the channel is gone, here is a fresh one" can rebuild on top; a
client that reconnected quietly would hand back a service whose address has
stopped answering and say nothing.

## Introduction points are established once

`establish_intro_points` runs during `launch` and nothing runs it again. The
republish loop re-signs a descriptor naming the *same* points every hour or
two, so a relay that goes down, leaves the consensus, or drops its circuit
stays advertised for as long as the service is up. Reachability decays one
point at a time and nothing observes it: the descriptor is still stored, the
address still resolves, and introductions simply stop arriving.

C tor and Arti both watch their introduction points and replace one that has
failed. The republish loop is the natural home for that — it already wakes on
the right cadence and already holds the relay list — but it has no signal to
act on, so the per-point circuit handler would first have to report its own
end instead of just stopping.
