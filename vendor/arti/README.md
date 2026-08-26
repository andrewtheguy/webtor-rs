# Vendored Arti patches

This directory contains the browser-specific fork of the small part of Arti that cannot come from crates.io unchanged. The baseline is Arti 2.5.1 / crate version 0.45.0, published from upstream revision `009354f78d1a61214a878d6f1712a50844e6c215`. These crates require Rust 1.91; the repository's pinned toolchain is new enough.

`Cargo.toml` patches exactly one crate, `tor-proto`. Every other Arti crate is an ordinary crates.io dependency at 0.45.0, including `tor-rtcompat`, `tor-memquota`, `tor-basic-utils`, `tor-log-ratelim`, `tor-linkspec` and `tor-hscrypto`, all of which were forks against the previous 0.37.0 baseline and now build for `wasm32-unknown-unknown` unmodified.

## Patch inventory

| Crate | Kind | Required divergence |
| --- | --- | --- |
| `tor-proto` | Targeted fork | Relaxes the channel and channel-reactor generic bound from `tor_rtcompat::Runtime` to `CoarseTimeProvider + SleepProvider`. Nothing else differs from the published package; the manifest is byte-identical to upstream's. |

### Why the patch is needed

Without it, the browser build does not compile. With `[patch.crates-io]` removed and pristine `tor-proto` 0.45.0 in its place, `cargo check --workspace --target wasm32-unknown-unknown` fails with 31 errors from a single cause, at `VerifiedClientChannel::finish()` and `Reactor::run()` in `webtor/src/client.rs`:

```text
the trait bound `WasmRuntime: Runtime` is not satisfied
the trait bound `WasmRuntime: futures::task::Spawn` is not satisfied
the trait bound `WasmRuntime: Blocking` is not satisfied
the trait bound `WasmRuntime: NetStreamProvider` is not satisfied
the trait bound `WasmRuntime: NetStreamProvider<unix::SocketAddr>` is not satisfied
the trait bound `WasmRuntime: TlsProvider<_>` is not satisfied
the trait bound `WasmRuntime: UdpProvider` is not satisfied
```

`tor_rtcompat::Runtime` is a supertrait alias for `Sync + Send + Spawn + Blocking + Clone + SleepProvider + CoarseTimeProvider + NetStreamProvider<net::SocketAddr> + NetStreamProvider<unix::SocketAddr> + TlsProvider + UdpProvider + Debug + 'static`. The browser client hands `tor-proto` an already-connected stream, so it has no sockets, no listeners and no TLS stack of its own to satisfy those with.

The bound is also wider than the code it guards. In the non-relay path the runtime value is used exactly twice, both as `DynTimeProvider::new(runtime.clone())` — in `Channel::new` and in `Reactor::run` — and that constructor's own bound is `R: SleepProvider + CoarseTimeProvider`. The patch therefore narrows the bound to what is actually called rather than removing a capability anything uses.

The alternative is implementing the whole contract on `WasmRuntime`: TCP and Unix stream providers, a TLS provider, a UDP provider, and `Blocking`, whose `block_on`/`reenter_block_on` cannot be honored on a browser thread at all. That trades four one-line bound changes for a set of stubs that can only panic. Do not switch to it without weighing that cost.

**The relaxation holds only while the `relay` feature is off.** `Reactor::handle_create` passes `&self.runtime` to a relay-side create handler; it is `#[cfg(feature = "relay")]` and this build never enables it. Enabling `relay` would reintroduce a real `Runtime` requirement and invalidate the patch.

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
