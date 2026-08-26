# Vendored Arti patches

This directory contains the browser-specific fork of the small part of Arti that cannot come from crates.io unchanged. The baseline is Arti 2.5.1 / crate version 0.45.0, published from upstream revision `009354f78d1a61214a878d6f1712a50844e6c215`. These crates require Rust 1.91; the repository's pinned toolchain is new enough.

`Cargo.toml` patches exactly one crate, `tor-proto`. Every other Arti crate is an ordinary crates.io dependency at 0.45.0, including `tor-rtcompat`, `tor-memquota`, `tor-basic-utils`, `tor-log-ratelim`, `tor-linkspec` and `tor-hscrypto`, all of which were forks against the previous 0.37.0 baseline and now build for `wasm32-unknown-unknown` unmodified.

## Patch inventory

| Crate | Kind | Required divergence |
| --- | --- | --- |
| `tor-proto` | Targeted fork | Relaxes the channel and channel-reactor generic bound from `tor_rtcompat::Runtime` to `CoarseTimeProvider + SleepProvider`. Nothing else differs from the published package; the manifest is byte-identical to upstream's. |

The browser client hands `tor-proto` an already-connected stream, so its channel reactor needs only the time and sleep subset of the runtime contract. Upstream's `Runtime` supertrait additionally demands blocking, TCP, Unix, UDP and TLS providers that `WasmRuntime` has nothing to implement with. Implementing those as stubs purely to satisfy a bound is the alternative to this patch; do not switch to it without first weighing its maintenance cost against four one-line bound changes.

The supported feature surface is the one selected in the workspace `Cargo.toml`: `tor-proto/hs-client`, `tor-proto/send-control-msg`, and `tor-linkspec/decode+verbatim`, plus their transitive requirements. Because the fork is otherwise pristine, the remaining upstream features are upstream's own; they are still not compatibility promises for this build.

## Exact differences

From the repository root, run:

```console
vendor/arti/compare-upstream.sh
```

The script itself is independent of the current working directory. It reads [`UPSTREAM_VERSION`](UPSTREAM_VERSION), locates or fetches each pristine crates.io package, and prints every modified, removed, or added path. Against 0.45.0, the recorded fork has an unchanged manifest, 4 modified source files, no removed files, and no added crate-content files:

```text
tor-proto: manifest=unchanged, source/content=4 modified, 0 removed, 0 added
  M src/channel/handshake.rs
  M src/channel/reactor.rs
  M src/channel.rs
  M src/client/channel/handshake.rs
```

Useful variants are:

```console
vendor/arti/compare-upstream.sh --compact
vendor/arti/compare-upstream.sh --diff
vendor/arti/compare-upstream.sh --version NEW_CRATE_VERSION
```

The first command is a quick scope check. The second emits the full patch against the recorded baseline. The last previews how the current fork differs from a proposed upstream release; it is diagnostic, not an automatically applicable upgrade patch.

Each vendored crate is the unpacked crates.io package, so its `Cargo.toml` is the registry-normalized manifest and the comparison baseline is the pristine `Cargo.toml`, not `Cargo.toml.orig`.

## Upgrade procedure

1. Choose one Arti release and update all Arti versions together, including `subtle-tls`'s own direct `tor-rtcompat` pin. Record its crate version in `UPSTREAM_VERSION` and its Arti release/revision above.
2. Fetch the new packages, then run `compare-upstream.sh --version NEW_CRATE_VERSION` before editing. This exposes upstream additions and removals in each forked area.
3. Start each vendored crate from the new pristine package contents, unmodified, and re-apply only the divergence in the table above. Do not carry compatibility branches for the previous Arti API.
4. Drop the `[patch.crates-io]` entry entirely whenever the new upstream crate builds for the browser without its documented divergence. Do not vendor an otherwise unchanged transitive crate. Reintroduce a dependency-pruning fork only if a release-WASM size measurement proves it worthwhile.
5. Update `Cargo.lock`, then confirm `compare-upstream.sh` reports only intentional paths and update this inventory when that set changes.
6. Run `cargo clippy` followed by `cargo test`. Also run `cargo check --workspace --target wasm32-unknown-unknown` so native-only APIs cannot hide a WASM regression.

An Arti upgrade changes the forked public/runtime contract. Follow the repository versioning rule and make the branch's single patch-version bump when the upgrade is performed.
