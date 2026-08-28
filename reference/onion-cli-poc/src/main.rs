//! An Arti onion-service echo peer, for webtor to be tested *against*.
//!
//! Two commands, and between them they exercise both directions of a v3 onion
//! service:
//!
//! ```text
//! onion-cli-poc serve
//! onion-cli-poc connect <address>.onion --message hello
//! ```
//!
//! `serve` publishes an ephemeral address and echoes every line back;
//! `connect` sends one line to an address and prints what comes back. Run both
//! against each other and the round trip is CLI to CLI. Point one of them at
//! the browser instead — `tests/tools/interop-cli.ts` drives exactly that — and
//! a failure names a side, which is the whole reason this program exists. See
//! README.md.
//!
//! Nothing here is shared with `crates/`: the client is `arti-client`,
//! assembled the way Arti's own documentation says to assemble one.

mod client;
mod echo;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Virtual port both sides use. Onion services have their own port space, so
/// this collides with nothing on either machine.
pub const DEFAULT_PORT: u16 = 9735;

#[derive(Parser)]
#[command(name = "onion-cli-poc", version, about = "An Arti onion-service echo peer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish an ephemeral onion service that echoes every line back.
    Serve {
        /// Virtual port to answer on.
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// Send one line to an onion service and print the echo.
    Connect {
        /// A v3 `<address>.onion`, optionally with `:<port>`.
        address: String,
        /// The line to send. It must not contain a newline.
        #[arg(long)]
        message: String,
        /// Virtual port, when the address does not name one.
        #[arg(long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // tor-rtcompat's rustls backend takes the process-default provider and
    // installs none of its own. Doing it here rather than leaving Arti to warn
    // and pick one keeps the choice in this binary.
    let _already_installed = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match Cli::parse().command {
        Command::Serve { port } => echo::serve(port).await,
        Command::Connect {
            address,
            message,
            port,
        } => {
            println!("{}", echo::connect(&address, port, &message).await?);
            Ok(())
        }
    }
}
