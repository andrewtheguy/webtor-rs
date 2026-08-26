Strict no backward compatibility or legacy code path under any circumstances, bump package version to signal breaking changes instead.

No change logs on the repo because git already tracks all changes, and the commit history is the change log.

run cargo clippy and cargo test after rust changes

no cargo fmt

always bump only webtor-wasm by patch version for breaking changes, but only one bump per branch
