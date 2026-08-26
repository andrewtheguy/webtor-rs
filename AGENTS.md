Strict no backward compatibility or legacy code path under any circumstances, bump package version to signal breaking changes instead.

Always use extractable: false for Web Crypto API keys even for asymmetric keys because public keys can always be exported

run cargo clippy and cargo test after rust changes

no cargo fmt

always bump by patch version only for breaking changes, but only one bump per branch
