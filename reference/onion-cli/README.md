# onion-cli

A native Tor onion-service peer for webtor to be tested *against*. It is a
placeholder: the directory, the manifest and the workspace boundary are in
place, and the implementation is still to be migrated from the `tor` proof of
concept in the sibling `ptransfer-cli`.

## Why a second implementation

`tests/live.test.ts` proves the browser client can reach public onion services
and that a service it publishes can be looked up. What neither shows is which
side is wrong when a round trip fails. A peer built on Arti's own client stack
— `tor-circmgr`, `tor-hsclient`, `tor-hsservice`'s layers — shares no code with
`webtor-core`, so a failure between the two names a side.

That is the whole reason this exists, and it is why nothing here may depend on
`webtor-core`, `webtor-wasm`, or `subtle-tls`. A shared crate would make the
two implementations agree by construction, which is the one thing this cannot
do and still be worth running.

## Why it is outside the root workspace

`../../Cargo.toml` excludes `reference/`, so this project has its own
`Cargo.toml` and its own `Cargo.lock`. The root workspace builds for
`wasm32-unknown-unknown` and holds no tokio and no Arti client stack; joining
them would put the whole native tree behind every `cargo clippy` and
`cargo test` run at the root.

Build it explicitly:

```bash
cargo build --release --manifest-path reference/onion-cli/Cargo.toml
```

## What migrates here

From `../ptransfer-cli/src/tor/`:

| Source | What it carries |
| --- | --- |
| `client.rs` | the Tor client assembled below `arti-client`, so nothing touches a path |
| `netdir.rs` | a `NetDirProvider` over a directory fetched into memory |
| `memstate.rs` | the `StateMgr` guard and vanguard state live in |
| `service.rs` | `OnionListener` — launch a service, wait for the descriptor to publish, accept |
| `config.rs` | bootstrap parameters |
| `echo.rs` | `serve` prints an address and echoes lines; `connect` sends one and reads the echo |

The CLI surface `tests/tools/interop-cli.ts` drives today is `ptransfer tor
serve` and `ptransfer tor connect <address> <message>`; the migrated binary
owns that contract and the test's `PTRANSFER_BIN` default moves with it.
