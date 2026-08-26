//! Circuit construction for one anonymous signaling session.
//!
//! Every circuit starts at the Snowflake bridge and passes through one middle
//! relay before its final hop: an HSDir, a rendezvous point or an
//! introduction point. Nothing here ever reaches an exit.

use crate::error::{Result, TorError};
use crate::relay::{Relay, RelayManager};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
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

pub(crate) struct SimpleTimeoutEstimator;

impl TimeoutEstimator for SimpleTimeoutEstimator {
    fn circuit_build_timeout(&self, _length: usize) -> Duration {
        Duration::from_secs(60)
    }
}

#[derive(Clone)]
pub(crate) struct CircuitManager {
    relay_manager: Arc<RwLock<RelayManager>>,
    channel: Arc<RwLock<Option<Arc<Channel>>>>,
}

impl CircuitManager {
    pub(crate) fn new(
        relay_manager: Arc<RwLock<RelayManager>>,
        channel: Arc<RwLock<Option<Arc<Channel>>>>,
    ) -> Self {
        Self {
            relay_manager,
            channel,
        }
    }

    /// Build a fresh three-hop tunnel Snowflake → middle → `target`, choosing
    /// a middle relay that is neither the bridge nor the target. Returns the
    /// tunnel and the middle relay it went through.
    pub(crate) async fn build_tunnel_to<T: CircTarget>(
        &self,
        target: &T,
    ) -> Result<(ClientTunnel, Relay)> {
        let channel = self.channel().await?;
        let bridge_fingerprint = self.bridge_fingerprint().await?;

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
                error!("Circuit reactor finished with error: {}", error);
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

    async fn channel(&self) -> Result<Arc<Channel>> {
        self.channel
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| TorError::Internal("Channel not established".to_string()))
    }

    async fn bridge_fingerprint(&self) -> Result<String> {
        Ok(self
            .channel()
            .await?
            .target()
            .rsa_identity()
            .map(|identity| hex::encode(identity.as_bytes()))
            .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn circuits_require_a_channel() {
        let manager = CircuitManager::new(
            Arc::new(RwLock::new(RelayManager::new(Vec::new()))),
            Arc::new(RwLock::new(None)),
        );
        assert!(manager.channel().await.is_err());
        assert!(manager.bridge_fingerprint().await.is_err());
    }
}
