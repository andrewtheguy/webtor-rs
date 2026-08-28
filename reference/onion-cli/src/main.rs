//! Placeholder for the onion-service peer webtor is tested against.
//!
//! The structure is what exists so far: this project sits outside the root
//! workspace and depends on nothing in it. The Tor client, the onion service
//! and the echo commands migrate here from the `tor` proof of concept in the
//! sibling `ptransfer-cli`; see README.md for what each source file carries
//! and for the CLI contract `tests/tools/interop-cli.ts` already drives.

fn main() {
    eprintln!(
        "onion-cli is not implemented yet; the Arti-based echo service migrates \
         here from ptransfer-cli. See reference/onion-cli/README.md."
    );
    std::process::exit(1);
}
