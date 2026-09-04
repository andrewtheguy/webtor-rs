//! A backend for the onion gateway's directory endpoints, and a one-off
//! snapshot writer for the test suites and the other examples.
//!
//!   webtor-directory-server serve --listen 127.0.0.1:5180 [--web-root examples/onion-gateway/dist]
//!   webtor-directory-server snapshot tests/.directory-seed.json

mod fetch;
mod server;
mod snapshot;

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "webtor-directory-server", version, about)]
struct Cli {
    /// Directory authority URLs to fetch from, tried in order.
    #[arg(long = "authority", global = true, value_name = "URL")]
    authorities: Vec<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve `/api/directory`, refreshing the seed as each consensus is
    /// published, and optionally the gateway's built `dist/` in front of it.
    Serve {
        #[arg(short, long, env = "WEBTOR_DIRECTORY_LISTEN", default_value = "127.0.0.1:5180")]
        listen: SocketAddr,
        /// A built onion gateway to serve from `/`, with `index.html` for any
        /// path that is not a file.
        #[arg(long, env = "WEBTOR_DIRECTORY_WEB_ROOT", value_name = "DIR")]
        web_root: Option<PathBuf>,
    },
    /// Build one seed and write it to `output`.
    Snapshot { output: PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let authorities = if cli.authorities.is_empty() {
        fetch::DEFAULT_AUTHORITIES.iter().map(|url| url.to_string()).collect()
    } else {
        cli.authorities
    };
    let authorities = Arc::new(fetch::Authorities::new(authorities)?);

    match cli.command {
        Command::Serve { listen, web_root } => {
            if let Some(root) = &web_root {
                anyhow::ensure!(
                    root.join("index.html").is_file(),
                    "{} has no index.html; build the gateway first (`bun run build` in examples/onion-gateway)",
                    root.display()
                );
            }
            let directory = server::Shared::default();
            tokio::spawn(server::refresh_forever(directory.clone(), authorities));
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("cannot listen on {listen}"))?;
            info!("Serving {} on http://{listen}", server::DIRECTORY_PATH);
            axum::serve(listener, server::router(directory, web_root))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Command::Snapshot { output } => {
            let seed = authorities.build_seed().await?;
            tokio::fs::write(&output, &seed.encoded)
                .await
                .with_context(|| format!("writing {}", output.display()))?;
            info!(
                "Wrote {} ({} MiB, {} relays); rebuild before {}",
                output.display(),
                seed.encoded.len() / (1024 * 1024),
                seed.relay_count,
                snapshot::iso8601(seed.valid_until)
            );
        }
    }
    Ok(())
}
