//! Bootstrapping an Arti client, and publishing a service on it.
//!
//! Everything here is `arti-client`'s own machinery, taken as it comes: the
//! SQLite directory cache, the on-disk client state, the guard and vanguard
//! managers, `tor-hsservice`'s introduction-point manager and publisher. That
//! is the point — a peer assembled out of Arti's documented API disagrees with
//! webtor only where Arti does.
//!
//! Two departures from a bare `TorClientConfig::default()`, both one line:
//!
//! - the keystore is [`ArtiKeystoreKind::Ephemeral`], so the service identity
//!   key exists only in this process and every `serve` publishes a fresh
//!   address. It is what Arti offers for a throwaway service without a custom
//!   `KeyMgr`, which is arti#1186 and unscheduled.
//! - the onion-service state lives under a nickname unique to this run, because
//!   the introduction-point manager keys its records by nickname and an
//!   ephemeral key under a reused nickname makes it find records belonging to
//!   an identity that no longer exists.
//!
//! The directory cache and client state stay where Arti puts them
//! (`~/.cache/arti`, `~/.local/share/arti` on Linux), which is what makes a
//! second run bootstrap in seconds instead of tens of them. Arti supports two
//! processes sharing those: the second takes the cache read-only and the state
//! lock is advisory, so `serve` and `connect` can run side by side.

use std::sync::Arc;

use anyhow::{Context, Result};
use arti_client::config::TorClientConfig;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{DataStream, TorClient};
use futures::{Stream, StreamExt as _};
use safelog::DisplayRedacted as _;
use tor_config::ExplicitOrAuto;
use tor_hsservice::status::State;
use tor_hsservice::{RendRequest, RunningOnionService, handle_rend_requests};
use tor_keymgr::config::ArtiKeystoreKind;
use tor_rtcompat::PreferredRuntime;

/// Build a client on Arti's default storage and bootstrap it.
///
/// This reaches the real Tor network. Cold it takes tens of seconds; warm,
/// against the cache a previous run left behind, a few.
pub async fn bootstrap() -> Result<Arc<TorClient<PreferredRuntime>>> {
    log::info!("bootstrapping a Tor client");
    let client = TorClient::create_bootstrapped(config()?)
        .await
        .context("failed to bootstrap the Tor client")?;
    log::info!("bootstrapped");
    Ok(client)
}

/// Arti's default configuration, with the keystore moved into memory.
fn config() -> Result<TorClientConfig> {
    let mut builder = TorClientConfig::builder();
    builder
        .storage()
        .keystore()
        .primary()
        .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
    builder
        .build()
        .context("failed to build the Tor client configuration")
}

/// A published onion service and the stream of requests arriving on it.
pub struct Service {
    /// Held so the service keeps running; dropping it takes the service down.
    running: Arc<RunningOnionService>,
    /// The `.onion` address, spelled out.
    address: String,
}

impl Service {
    /// Publish an ephemeral onion service.
    ///
    /// Returns as soon as the address is known — which is before clients can
    /// reach it. [`Service::wait_until_reachable`] is the other half.
    pub fn launch(
        tor: &TorClient<PreferredRuntime>,
    ) -> Result<(Self, impl Stream<Item = tor_hsservice::StreamRequest>)> {
        // Unique per run: see the module comment. `HsNickname` accepts
        // `[A-Za-z0-9_]`, so the timestamp is joined with an underscore.
        let nickname = format!(
            "onion_cli_poc_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        );
        let config = OnionServiceConfigBuilder::default()
            .nickname(nickname.parse().context("invalid onion service nickname")?)
            .build()
            .context("failed to build the onion service configuration")?;

        let (running, rend_requests): (_, Box<dyn Stream<Item = RendRequest> + Unpin + Send>) = {
            let (running, requests) = tor
                .launch_onion_service(config)
                .context("failed to launch the onion service")?
                .context("the onion service was disabled by its own configuration")?;
            (running, Box::new(Box::pin(requests)))
        };

        let address = running
            .onion_address()
            .context("the onion service has no address")?
            .display_unredacted()
            .to_string();

        Ok((Self { running, address }, handle_rend_requests(rend_requests)))
    }

    /// The `.onion` address clients connect to.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Resolve once Arti believes clients can reach this service.
    ///
    /// That is introduction points established *and* the descriptor uploaded;
    /// until both, the address resolves to nothing. It usually takes under a
    /// minute.
    pub async fn wait_until_reachable(&self) -> Result<()> {
        let mut events = self.running.status_events();
        // Arti republishes the same state as often as it re-examines it, so
        // only a change is worth a line.
        let mut reported: Option<State> = None;
        loop {
            let status = self.running.status();
            if status.state().is_fully_reachable() {
                return Ok(());
            }
            if reported != Some(status.state()) {
                log::info!("onion service is {:?}", status.state());
                reported = Some(status.state());
            }
            if status.state() == State::Broken {
                if let Some(problem) = status.current_problem() {
                    anyhow::bail!("the onion service failed to publish: {problem:?}");
                }
                anyhow::bail!("the onion service failed to publish");
            }
            events
                .next()
                .await
                .context("the onion service stopped reporting its status")?;
        }
    }
}

/// Open a stream to `host`:`port`, which must be a v3 onion address.
pub async fn connect(
    tor: &TorClient<PreferredRuntime>,
    host: &str,
    port: u16,
) -> Result<DataStream> {
    tor.connect((host, port))
        .await
        .with_context(|| format!("failed to connect to {host}:{port}"))
}
