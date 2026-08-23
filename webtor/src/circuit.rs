//! Single-circuit management for one anonymous signaling session.

use crate::error::{Result, TorError};
use crate::relay::{Relay, RelayManager};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tor_linkspec::HasRelayIds;
use tor_proto::ccparams::{
    Algorithm, CongestionControlParamsBuilder, CongestionWindowParamsBuilder,
    FixedWindowParamsBuilder, RoundTripEstimatorParamsBuilder,
};
use tor_proto::channel::Channel;
use tor_proto::circuit::CircParameters;
use tor_proto::client::circuit::TimeoutEstimator;
use tor_proto::client::stream::DataStream;
use tor_proto::{CellCount, ClientTunnel, FlowCtrlParameters};
use tor_units::Percentage;
use tracing::{debug, error, info};

pub(crate) struct Circuit {
    pub(crate) relays: Vec<Relay>,
    tunnel: Arc<ClientTunnel>,
}

impl Circuit {
    pub(crate) async fn begin_stream(&self, host: &str, port: u16) -> Result<DataStream> {
        debug!("Beginning stream to {}:{}", host, port);
        let stream = self
            .tunnel
            .begin_stream(host, port, None)
            .await
            .map_err(|error| {
                TorError::Internal(format!("Failed to begin stream to {host}:{port}: {error}"))
            })?;
        info!("Stream established to {}:{}", host, port);
        Ok(stream)
    }
}

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
    circuit: Arc<RwLock<Option<Arc<Circuit>>>>,
    relay_manager: Arc<RwLock<RelayManager>>,
    channel: Arc<RwLock<Option<Arc<Channel>>>>,
}

impl CircuitManager {
    pub(crate) fn new(
        relay_manager: Arc<RwLock<RelayManager>>,
        channel: Arc<RwLock<Option<Arc<Channel>>>>,
    ) -> Self {
        Self {
            circuit: Arc::new(RwLock::new(None)),
            relay_manager,
            channel,
        }
    }

    pub(crate) async fn create_circuit(&self) -> Result<Arc<Circuit>> {
        if let Some(circuit) = self.circuit.read().await.as_ref() {
            return Ok(circuit.clone());
        }

        let channel = self
            .channel
            .read()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| TorError::Internal("Channel not established".to_string()))?;

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

        let bridge_fingerprint = channel
            .target()
            .rsa_identity()
            .map(|identity| hex::encode(identity.as_bytes()))
            .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string());

        let relay_manager = self.relay_manager.read().await;
        if relay_manager.relays.is_empty() {
            return Err(TorError::Internal("No relays available".to_string()));
        }

        let middle = relay_manager.select_relay(
            &crate::relay::selection::middle_relays()
                .without_fingerprint(&bridge_fingerprint),
        )?;
        let middle_target = middle.as_circ_target()?;
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

        let exit = relay_manager.select_relay(
            &crate::relay::selection::exit_relays()
                .without_fingerprint(&bridge_fingerprint)
                .without_fingerprint(&middle.fingerprint),
        )?;
        let exit_target = exit.as_circ_target()?;
        info!("Extending to exit relay {}", exit.nickname);
        tunnel
            .as_single_circ()
            .map_err(|error| {
                TorError::Internal(format!("Failed to access exit circuit: {error}"))
            })?
            .extend(&exit_target, make_circ_params()?)
            .await
            .map_err(|error| {
                TorError::Internal(format!("Failed to extend to exit relay: {error}"))
            })?;
        drop(relay_manager);

        let circuit = Arc::new(Circuit {
            relays: vec![middle, exit],
            tunnel: Arc::new(tunnel),
        });
        *self.circuit.write().await = Some(circuit.clone());
        Ok(circuit)
    }

    pub(crate) async fn ready_circuit(&self) -> Result<Arc<Circuit>> {
        match self.circuit.read().await.as_ref() {
            Some(circuit) => Ok(circuit.clone()),
            None => self.create_circuit().await,
        }
    }

    pub(crate) async fn close(&self) {
        *self.circuit.write().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn circuit_requires_a_channel() {
        let manager = CircuitManager::new(
            Arc::new(RwLock::new(RelayManager::new(Vec::new()))),
            Arc::new(RwLock::new(None)),
        );
        assert!(manager.create_circuit().await.is_err());
    }
}
