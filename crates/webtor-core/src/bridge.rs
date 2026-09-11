//! Opening the one channel every circuit rides: to the Snowflake bridge,
//! through whichever transport the options name.

use crate::config::{BridgeType, LogCallback, LogType};
use crate::error::{Result, TorError};
use crate::snowflake_broker::NatPolicy;
use crate::snowflake_webrtc::{SnowflakeWebRtcConfig, SnowflakeWebRtcStream};
use crate::snowflake_ws::SnowflakeWsStream;
use crate::time::system_time_now;
use crate::wasm_runtime::WasmRuntime;
use safelog::MaybeSensitive;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use tor_linkspec::OwnedChanTargetBuilder;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_memquota::MemoryQuotaTracker;
use tor_proto::channel::Channel;
use tor_proto::client::channel::ClientChannelBuilder;
use tor_proto::memquota::{ChannelAccount, SpecificAccount};
use tor_proto::peer::PeerAddr;
use tracing::{error, info, warn};

pub(crate) struct Bridge {
    transport: BridgeType,
    on_log: Option<LogCallback>,
    /// What the webrtc bridge tells the broker about this client's NAT. Kept
    /// for the client's life, since a NAT found to need an open proxy for one
    /// channel still needs one for the next.
    nat_policy: Rc<NatPolicy>,
}

impl Bridge {
    pub(crate) fn new(transport: BridgeType, on_log: Option<LogCallback>) -> Self {
        Self {
            transport,
            on_log,
            nat_policy: Rc::default(),
        }
    }

    /// A new channel to the bridge.
    pub(crate) async fn open(&self) -> Result<Arc<Channel>> {
        self.log("Establishing Snowflake bridge channel", LogType::Info);
        let rsa_identity = parse_snowflake_identity(self.transport.fingerprint())?;

        let channel = match &self.transport {
            BridgeType::SnowflakeWebRtc {
                broker_url,
                stun_urls,
                fingerprint,
                peer_connection,
            } => {
                self.log("Connecting to Snowflake via WebRTC", LogType::Info);
                let stream = SnowflakeWebRtcStream::connect(
                    SnowflakeWebRtcConfig {
                        broker_url: broker_url.clone(),
                        fingerprint: fingerprint.clone(),
                        stun_urls: stun_urls.clone(),
                        peer_connection: peer_connection.clone(),
                    },
                    self.nat_policy.clone(),
                )
                .await?;
                create_channel(stream, rsa_identity).await?
            }
            BridgeType::SnowflakeWebSocket { url, .. } => {
                self.log("Connecting to Snowflake via WebSocket", LogType::Info);
                let stream = SnowflakeWsStream::connect(url).await?;
                create_channel(stream, rsa_identity).await?
            }
        };

        self.log("Snowflake bridge channel established", LogType::Success);
        Ok(channel)
    }

    pub(crate) fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.on_log {
            (callback.0)(message, log_type);
            return;
        }
        match log_type {
            LogType::Info | LogType::Success => info!("{}", message),
            LogType::Warn => warn!("{}", message),
            LogType::Error => error!("{}", message),
        }
    }
}

async fn create_channel<S>(stream: S, rsa_identity: RsaIdentity) -> Result<Arc<Channel>>
where
    S: futures::AsyncRead
        + futures::AsyncWrite
        + Send
        + Unpin
        + tor_rtcompat::StreamOps
        + tor_rtcompat::CertifiedConn
        + 'static,
{
    let peer_certificate = stream
        .peer_certificate()
        .map_err(|error| {
            TorError::Network(format!("Failed to read bridge certificate: {error}"))
        })?
        .ok_or_else(|| TorError::Network("Bridge supplied no certificate".to_string()))?
        .into_owned();

    let quota = MemoryQuotaTracker::new_noop();
    let account = ChannelAccount::new(&quota).map_err(|error| {
        TorError::Internal(format!("Failed to create channel quota account: {error}"))
    })?;
    let handshake = ClientChannelBuilder::new().launch(stream, WasmRuntime::new(), account);
    let unverified = handshake.connect(system_time_now).await.map_err(|error| {
        TorError::Network(format!("Tor channel handshake failed: {error}"))
    })?;

    let mut peer = OwnedChanTargetBuilder::default();
    peer.rsa_identity(rsa_identity);
    let peer = peer
        .build()
        .map_err(|error| TorError::Internal(format!("Invalid bridge target: {error}")))?;
    // The browser transport hides the relay behind a Snowflake proxy, so we
    // have no address for it. An unspecified address makes the NETINFO cell
    // carry 0.0.0.0, which is what Tor clients send when they cannot tell.
    let peer_addr = MaybeSensitive::sensitive(PeerAddr::Direct(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    )));
    let (channel, reactor) = unverified
        .verify(&peer, &peer_certificate, Some(system_time_now()))
        .map_err(|error| {
            TorError::Network(format!("Bridge authentication failed: {error}"))
        })?
        .finish(peer_addr)
        .await
        .map_err(|error| {
            TorError::Network(format!("Tor channel handshake failed: {error}"))
        })?;

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(error) = reactor.run().await {
            // Every circuit rides this one channel, so losing it stops them
            // all until it is reopened. `debug!` is compiled out of a release
            // build, which made that the quietest possible failure.
            warn!(
                "Tor channel reactor stopped: {}",
                crate::error::error_chain(&error)
            );
        }
    });
    Ok(channel)
}

/// The bridge's RSA identity, as the channel handshake wants it.
fn parse_snowflake_identity(fingerprint: &str) -> Result<RsaIdentity> {
    let bytes = hex::decode(fingerprint)
        .map_err(|error| TorError::Configuration(format!("Invalid bridge identity: {error}")))?;
    RsaIdentity::from_bytes(&bytes)
        .ok_or_else(|| TorError::Configuration("Invalid bridge identity length".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TorClientOptions;

    #[test]
    fn snowflake_identity_is_valid() {
        let options = TorClientOptions::snowflake_websocket();
        assert!(parse_snowflake_identity(options.bridge.fingerprint()).is_ok());
    }

    #[test]
    fn a_fingerprint_of_the_wrong_length_is_refused() {
        // Truncated hex parses fine as bytes, so the length check is the only
        // thing standing between a typo and a confusing handshake failure.
        assert!(parse_snowflake_identity("2B280B23E1107BB6").is_err());
    }

    #[test]
    fn a_fingerprint_that_is_not_hex_is_refused() {
        assert!(parse_snowflake_identity("not-a-fingerprint").is_err());
    }
}
