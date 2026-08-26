# Vendored Arti patches

This directory contains the browser-specific fork of the small part of Arti that cannot come from crates.io unchanged. The baseline is Arti 1.8.0 / crate version 0.37.0, published from upstream revision `6c79dfb9a31e2fdde6230da4edcb71cc082ca7d9`.

`Cargo.toml` patches only these seven crates. All other Arti crates must remain ordinary crates.io dependencies.

## Patch inventory

The two replacement crates are intentionally much further from upstream than the five targeted forks.

| Crate | Kind | Required divergence |
| --- | --- | --- |
| `tor-rtcompat` | Browser replacement | Retains only time, sleep, spawn, stream-operation, and certified-connection traits needed by the browser client. It replaces native runtimes, sockets, and TLS with `web-time`-based types and no-op stream operations. Re-port the public surface used by `webtor` and the other patched crates; do not line-merge removed native backends. |
| `tor-memquota` | No-op replacement | Keeps the upstream memory-cost derives and memory-aware queue, but replaces tracker/account/participation state with no-op handles. Browser builds never enable reclamation. Re-port queue API changes while preserving the no-accounting invariant; do not restore the upstream tracker and its configuration/runtime dependencies. |
| `tor-proto` | Targeted fork plus pruning | Uses browser-compatible instants, supplies a WASM atomic timestamp implementation, removes `tor-config` builder macros, and prunes relay, server/incoming-stream, experimental Conflux-handler, circuit-padding-backend, CGO, benchmark, and test-only paths not used by the client. `hs-client` and `send-control-msg` are required. |
| `tor-basic-utils` | Targeted fork | Adds the non-Unix/non-Windows `IoErrorExt::is_not_a_directory` implementation required by `wasm32-unknown-unknown`. |
| `tor-log-ratelim` | Targeted fork | Uses `tor_rtcompat::Instant` and accepts the smaller `Spawn + SleepProvider` browser runtime bound instead of upstream's full `Runtime` trait. |
| `tor-linkspec` | Dependency pruning | Removes `tor-config`; local `builder()` constructors replace `impl_standard_builder!`. The experimental `decode` and `verbatim` features remain required by the onion-service directory path. |
| `tor-hscrypto` | Dependency pruning | Removes `tor-key-forge` encodable-key implementations and the Equi-X dependency. The onion-service client cryptographic types and disabled-PoW stub remain; service key storage and `hs-pow-full` do not form part of the supported build. |

Every vendored manifest also removes workspace-relative paths, unused features, development dependencies, and dependencies belonging only to pruned code. Those path-to-version edits are mechanical and should be redone after copying a new upstream manifest.

The supported feature surface is the one selected in the workspace `Cargo.toml`: `tor-proto/hs-client`, `tor-proto/send-control-msg`, and `tor-linkspec/decode+verbatim`, plus their transitive requirements. Some dormant upstream feature names still exist in the 0.37.0 fork even though their implementation was pruned. They are not compatibility promises and may not compile; remove them when touching the corresponding manifest rather than carrying them into an upgrade.

## Exact differences

From the repository root, run:

```console
vendor/arti/compare-upstream.sh
```

The script itself is independent of the current working directory. It reads [`UPSTREAM_VERSION`](UPSTREAM_VERSION), locates or fetches each pristine crates.io package, and prints every modified, removed, or added path. Against 0.37.0, the recorded fork has 7 modified manifests, 34 modified source/content files, 71 removed files, and no added crate-content files. Useful variants are:

```console
vendor/arti/compare-upstream.sh --compact
vendor/arti/compare-upstream.sh --diff
vendor/arti/compare-upstream.sh --version NEW_CRATE_VERSION
```

The first command is a quick scope check. The second emits the full patch against the recorded baseline. The last previews how the current fork differs from a proposed upstream release; it is diagnostic, not an automatically applicable upgrade patch.

## Upgrade procedure

1. Choose one Arti release and update all Arti versions together. Record its crate version in `UPSTREAM_VERSION` and its Arti release/revision above.
2. Fetch the new packages, then run `compare-upstream.sh --version NEW_CRATE_VERSION` before editing. This exposes upstream additions and removals in each forked area.
3. Start each vendored crate from its new pristine `Cargo.toml.orig` and package contents. Port only the behavior in the table above. Do not carry compatibility branches for the previous Arti API.
4. Handle `tor-rtcompat` and `tor-memquota` as API replacements. For the other five crates, use the full baseline diff as a checklist and reassess every deleted module against the new dependency graph.
5. Remove a `[patch.crates-io]` entry whenever the new upstream crate builds for the browser without its documented divergence. Do not vendor an otherwise unchanged transitive crate.
6. Update `Cargo.lock`, then confirm `compare-upstream.sh` reports only intentional paths and update this inventory when that set changes.
7. Run `cargo clippy` followed by `cargo test`. Also compile the browser target used by the project so native-only APIs cannot hide a WASM regression.

An Arti upgrade changes the forked public/runtime contract. Follow the repository versioning rule and make the branch's single patch-version bump when the upgrade is performed.
