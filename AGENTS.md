Strict no backward compatibility or legacy code path under any circumstances, bump package version to signal breaking changes instead.

No change logs on the repo because git already tracks all changes, and the commit history is the change log.

run cargo clippy and cargo test after rust changes

no cargo fmt

use biome for lint for javascript projects, and use async await instead of promises unless promises is meant for a specific reason

when a branch changes anything under crates/, bump the webtor-wasm patch version once on that branch, and leave the other crates' versions alone
