# onion-cli-poc

A native Tor onion-service echo peer for webtor to be tested *against*.

```bash
cargo build --release --manifest-path reference/onion-cli-poc/Cargo.toml

# One terminal: publish an ephemeral address and echo every line back.
./reference/onion-cli-poc/target/release/onion-cli-poc serve

# Another: send one line to that address and print what comes back.
./reference/onion-cli-poc/target/release/onion-cli-poc connect <address>.onion --message hello
```

`serve` prints the `.onion` address on its own line, then `ready` once clients
can reach it; `connect` prints the echo and nothing else. Progress goes to the
log on stderr, at `RUST_LOG` (default `info`).

## Why a second implementation

`tests/live.test.ts` proves the browser client can reach public onion services
and that a service it publishes can be looked up. What neither shows is which
side is wrong when a round trip fails. This peer is `arti-client` assembled the
way Arti's own documentation says to assemble one, so it shares no code with
`webtor-core` and a failure between the two names a side.

That is the whole reason this exists, and it is why nothing here may depend on
`webtor-core`, `webtor-wasm`, or `subtle-tls`. A shared crate would make the
two implementations agree by construction, which is the one thing this cannot
do and still be worth running.

`tests/tools/interop-cli.ts` drives it in both directions: the page opens a
stream to a service this program publishes, then publishes one of its own for
this program to connect to.

## Why it is outside the root workspace

`../../Cargo.toml` excludes `reference/`, so this project has its own
`Cargo.toml` and its own `Cargo.lock`. The root workspace builds for
`wasm32-unknown-unknown` and holds no tokio and no Arti client stack; joining
them would put the whole native tree behind every `cargo clippy` and
`cargo test` run at the root. Build and check it explicitly with
`--manifest-path`.

## What it is made of

Three files, and only `echo.rs` is about echoing:

| File | What it carries |
| --- | --- |
| `main.rs` | the two subcommands, the log sink, and the rustls provider |
| `client.rs` | bootstrapping `arti-client`, publishing a service, opening a stream |
| `echo.rs` | the line protocol, the address parsing, and the disconnect rule |

There is no directory code, no state manager, no descriptor signing and no
introduction-point handling here, because `arti-client` and `tor-hsservice`
already have all of it. The dependency list is the minimum for one onion
service and one onion client: no TUI, no file transfer, no signaling.

## Storage, and what stays ephemeral

The directory cache and client state are Arti's defaults — `~/.cache/arti` and
`~/.local/share/arti` on Linux — which is what makes a second run bootstrap in
seconds rather than tens of them. Two processes may share them: Arti gives the
second the cache read-only, and the state lock is advisory, so `serve` and
`connect` run side by side.

Two things are deliberately not persistent, each one line of configuration:

- **the identity key**, because the keystore is Arti's `Ephemeral` kind. The
  key exists only in the running process, so every `serve` publishes a fresh
  address and none of them reach disk. This is what Arti offers for a throwaway
  service without a custom `KeyMgr` — a real in-memory `StateMgr` is arti#1186
  and unscheduled.
- **the onion-service state**, which is filed under a nickname unique to each
  run. The introduction-point manager keys its records by nickname, so a fresh
  key under a reused nickname would make it find records belonging to an
  identity that no longer exists.
