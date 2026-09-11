//! Circuit construction for one client session.
//!
//! Every circuit starts at the Snowflake bridge and passes through one middle
//! relay before its final hop: an HSDir, a rendezvous point or an
//! introduction point. Nothing here ever reaches an exit.

use crate::bridge::Bridge;
use crate::config::LogType;
use crate::error::{Result, TorError};
use crate::relay::{Relay, RelayManager};
use crate::retry::with_timeout;
use std::sync::Arc;
use std::time::Duration;
use async_lock::{Mutex, RwLock};
use tor_linkspec::{CircTarget, HasRelayIds};
use tor_proto::ccparams::{
    Algorithm, CongestionControlParamsBuilder, CongestionWindowParamsBuilder,
    FixedWindowParamsBuilder, RoundTripEstimatorParamsBuilder,
};
use tor_proto::channel::Channel;
use tor_proto::circuit::CircParameters;
use tor_proto::client::circuit::TimeoutEstimator;
use tor_proto::{CellCount, ClientTunnel, FlowCtrlParameters};
use tor_units::Percentage;
use tracing::{error, info};

pub(crate) fn make_circ_params() -> Result<CircParameters> {
    let fixed_window_params = FixedWindowParamsBuilder::default()
        .circ_window_start(1000)
        .circ_window_min(100)
        .circ_window_max(1000)
        .build()
        .map_err(|error| {
            TorError::Internal(format!("Failed to build fixed window params: {error}"))
        })?;

    let cwnd_params = CongestionWindowParamsBuilder::default()
        .cwnd_init(1000)
        .cwnd_inc_pct_ss(Percentage::new(100))
        .cwnd_inc(1)
        .cwnd_inc_rate(1)
        .cwnd_min(100)
        .cwnd_max(1000)
        .sendme_inc(31)
        .build()
        .map_err(|error| {
            TorError::Internal(format!("Failed to build congestion window params: {error}"))
        })?;

    let rtt_params = RoundTripEstimatorParamsBuilder::default()
        .ewma_cwnd_pct(Percentage::new(50))
        .ewma_max(10)
        .ewma_ss_max(10)
        .rtt_reset_pct(Percentage::new(50))
        .build()
        .map_err(|error| {
            TorError::Internal(format!("Failed to build round-trip estimator params: {error}"))
        })?;

    let congestion_control = CongestionControlParamsBuilder::default()
        .alg(Algorithm::FixedWindow(fixed_window_params))
        .fixed_window_params(fixed_window_params)
        .cwnd_params(cwnd_params)
        .rtt_params(rtt_params)
        .build()
        .map_err(|error| {
            TorError::Internal(format!("Failed to build congestion control params: {error}"))
        })?;

    let flow_control = FlowCtrlParameters {
        cc_xoff_client: CellCount::new(500),
        cc_xoff_exit: CellCount::new(500),
        cc_xon_rate: CellCount::new(500),
        cc_xon_change_pct: 25,
        cc_xon_ewma_cnt: 2,
    };

    Ok(CircParameters::new(
        true,
        congestion_control,
        flow_control,
    ))
}

/// How long one circuit, all three hops of it, may take to build.
///
/// tor-proto waits for an extension's answer as long as the relay takes, and
/// a relay that never answers holds the circuit open with nothing to show for
/// it: Arti's own circuit manager is what bounds a build, and this client
/// builds circuits without it. A circuit that has not come up in this long is
/// given up, so that whatever wanted it can move on to other relays. Building
/// one takes a second or two, through a Snowflake proxy included.
const CIRCUIT_BUILD_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) struct SimpleTimeoutEstimator;

impl TimeoutEstimator for SimpleTimeoutEstimator {
    fn circuit_build_timeout(&self, _length: usize) -> Duration {
        Duration::from_secs(60)
    }
}

pub(crate) struct CircuitManager {
    relay_manager: Arc<RwLock<RelayManager>>,
    bridge: Bridge,
    /// The bridge channel, once one has been opened and until the client is
    /// closed.
    channel: RwLock<Option<Arc<Channel>>>,
    /// Held while a closed channel is replaced, so that everything that finds
    /// it closed at once shares the one new channel.
    reopening: Mutex<()>,
}

impl CircuitManager {
    pub(crate) fn new(relay_manager: Arc<RwLock<RelayManager>>, bridge: Bridge) -> Self {
        Self {
            relay_manager,
            bridge,
            channel: RwLock::new(None),
            reopening: Mutex::new(()),
        }
    }

    /// Open a new bridge channel for a bootstrap, in place of any there was,
    /// which is terminated: one a bootstrap gave up on, or one that timed out
    /// and left its channel here.
    pub(crate) async fn open_channel(&self) -> Result<Arc<Channel>> {
        let channel = self.bridge.open().await?;
        if let Some(replaced) = self.channel.write().await.replace(channel.clone()) {
            replaced.terminate();
        }
        Ok(channel)
    }

    /// Close the channel and forget it. Nothing reopens one until the next
    /// bootstrap. Kept circuits hold the channel too, so it is terminated
    /// rather than dropped, which would leave it running under them.
    pub(crate) async fn close_channel(&self) {
        if let Some(channel) = self.channel.write().await.take() {
            channel.terminate();
        }
    }

    /// Build a fresh three-hop tunnel Snowflake → middle → `target`, choosing
    /// a middle relay that is neither the bridge nor the target. Returns the
    /// tunnel and the middle relay it went through.
    pub(crate) async fn build_tunnel_to<T: CircTarget>(
        &self,
        target: &T,
    ) -> Result<(ClientTunnel, Relay)> {
        // A channel reopened on the way is not the circuit's time to spend.
        let channel = self.channel().await?;
        with_timeout(
            CIRCUIT_BUILD_TIMEOUT,
            "Circuit build",
            self.build_on(&channel, target),
        )
        .await
    }

    async fn build_on<T: CircTarget>(
        &self,
        channel: &Arc<Channel>,
        target: &T,
    ) -> Result<(ClientTunnel, Relay)> {
        let bridge_fingerprint = bridge_fingerprint(channel);

        let middle = {
            let relay_manager = self.relay_manager.read().await;
            let mut criteria =
                crate::relay::selection::middle_relays().without_fingerprint(&bridge_fingerprint);
            if let Some(identity) = target.rsa_identity() {
                criteria = criteria.without_fingerprint(&hex::encode(identity.as_bytes()));
            }
            relay_manager.select_relay(&criteria)?
        };
        let middle_target = middle.as_circ_target()?;

        let (pending_tunnel, reactor) = channel
            .new_tunnel(Arc::new(SimpleTimeoutEstimator) as Arc<dyn TimeoutEstimator>)
            .await
            .map_err(|error| {
                TorError::Internal(format!("Failed to create pending tunnel: {error}"))
            })?;

        wasm_bindgen_futures::spawn_local(async move {
            if let Err(error) = reactor.run().await {
                error!(
                    "Circuit reactor finished with error: {}",
                    crate::error::error_chain(&error)
                );
            }
        });

        let tunnel = pending_tunnel
            .create_firsthop_fast(make_circ_params()?)
            .await
            .map_err(|error| TorError::Internal(format!("Failed to create first hop: {error}")))?;

        info!("Extending to middle relay {}", middle.nickname);
        tunnel
            .as_single_circ()
            .map_err(|error| {
                TorError::Internal(format!("Failed to access middle circuit: {error}"))
            })?
            .extend(&middle_target, make_circ_params()?)
            .await
            .map_err(|error| {
                TorError::Internal(format!("Failed to extend to middle relay: {error}"))
            })?;

        info!("Extending to the final hop");
        tunnel
            .as_single_circ()
            .map_err(|error| {
                TorError::Internal(format!("Failed to access final circuit: {error}"))
            })?
            .extend(target, make_circ_params()?)
            .await
            .map_err(|error| {
                TorError::Internal(format!("Failed to extend to the final hop: {error}"))
            })?;

        Ok((tunnel, middle))
    }

    /// The bridge channel, reopened first if it has closed.
    ///
    /// Every circuit rides this one channel, so once it closes nothing works
    /// until there is another. A client's own calls reopen it before they
    /// start, and a published service reopens it here, when it next needs a
    /// circuit, since nothing else would.
    pub(crate) async fn channel(&self) -> Result<Arc<Channel>> {
        if let Some(channel) = self.live_channel().await? {
            return Ok(channel);
        }
        let _reopening = self.reopening.lock().await;
        if let Some(channel) = self.live_channel().await? {
            return Ok(channel);
        }
        self.bridge.log(
            "The Snowflake bridge channel closed; opening another",
            LogType::Warn,
        );
        let channel = self.bridge.open().await?;
        let mut current = self.channel.write().await;
        // A client closed while this was opening wants no channel.
        if current.is_none() {
            channel.terminate();
            return Err(not_established());
        }
        *current = Some(channel.clone());
        Ok(channel)
    }

    /// The channel while it is open, `None` once it has closed, and an error
    /// when there is none to reopen.
    async fn live_channel(&self) -> Result<Option<Arc<Channel>>> {
        match self.channel.read().await.as_ref() {
            Some(channel) if channel.is_closing() => Ok(None),
            Some(channel) => Ok(Some(channel.clone())),
            None => Err(not_established()),
        }
    }
}

fn not_established() -> TorError {
    TorError::Internal("Channel not established".to_string())
}

fn bridge_fingerprint(channel: &Channel) -> String {
    channel
        .target()
        .rsa_identity()
        .map(|identity| hex::encode(identity.as_bytes()))
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TorClientOptions;

    #[tokio::test]
    async fn circuits_require_a_channel() {
        let manager = CircuitManager::new(
            Arc::new(RwLock::new(RelayManager::new(Vec::new()))),
            Bridge::new(TorClientOptions::snowflake_websocket().bridge, None),
        );
        assert!(manager.channel().await.is_err());
    }
}
