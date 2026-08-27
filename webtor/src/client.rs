//! The browser Tor client.
//!
//! Bootstrapping means opening the Snowflake bridge channel and installing a
//! directory. Every stream after that goes to an onion service on a circuit
//! built for it; nothing this client does reaches a Tor exit.

use crate::circuit::CircuitManager;
use crate::config::{BridgeType, LogType, TorClientOptions};
use crate::directory::DirectoryManager;
use crate::error::{Result, TorError};
use crate::http::{build_request, execute_request, HttpRequest, HttpResponse};
use crate::onion_url::OnionUrl;
use crate::onion::OnionConnector;
use crate::onion_service::{OnionService, OnionServiceOptions};
use crate::relay::RelayManager;
use crate::retry::with_timeout;
use crate::snowflake_webrtc::{SnowflakeWebRtcConfig, SnowflakeWebRtcStream};
use crate::snowflake_ws::SnowflakeWsStream;
use crate::time::system_time_now;
use crate::wasm_runtime::WasmRuntime;
use safelog::MaybeSensitive;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use async_lock::{Mutex, RwLock};
use tor_linkspec::OwnedChanTargetBuilder;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_memquota::MemoryQuotaTracker;
use tor_proto::client::channel::ClientChannelBuilder;
use tor_proto::client::stream::DataStream;
use tor_proto::memquota::{ChannelAccount, SpecificAccount};
use tor_proto::peer::PeerAddr;
use tracing::{error, info, warn};

pub struct TorClient {
    options: TorClientOptions,
    directory_manager: Arc<DirectoryManager>,
    /// Circuit and relay state, shared with the onion client and with any
    /// service this client publishes.
    circuit_manager: Arc<CircuitManager>,
    relay_manager: Arc<RwLock<RelayManager>>,
    onion: OnionConnector,
    initialized: RwLock<bool>,
    bootstrap_lock: Mutex<()>,
    channel: Arc<RwLock<Option<Arc<tor_proto::channel::Channel>>>>,
    /// Encoded directory data to bootstrap from. Downloading the consensus
    /// and the microdescriptors over a single bridge circuit is the least
    /// reliable step of a bootstrap, so a caller-supplied directory is tried
    /// first and the download only runs when there is none or it is rejected.
    directory_seed: RwLock<Option<String>>,
}

impl TorClient {
    pub async fn new(options: TorClientOptions) -> Result<Self> {
        let channel = Arc::new(RwLock::new(None));
        let relay_manager = Arc::new(RwLock::new(RelayManager::new(Vec::new())));
        let directory_manager = Arc::new(DirectoryManager::new(
            relay_manager.clone(),
            options.on_log.clone(),
        ));
        let circuit_manager = Arc::new(CircuitManager::new(
            relay_manager.clone(),
            channel.clone(),
        ));
        let onion = OnionConnector::new(
            circuit_manager.clone(),
            directory_manager.clone(),
            relay_manager.clone(),
            options.on_log.clone(),
        );

        Ok(Self {
            options,
            directory_manager,
            circuit_manager,
            relay_manager,
            onion,
            initialized: RwLock::new(false),
            bootstrap_lock: Mutex::new(()),
            channel,
            directory_seed: RwLock::new(None),
        })
    }

    /// GET an `http://` URL on an onion service and buffer the response.
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::get(OnionUrl::parse(url)?)).await
    }

    /// Issue one plain HTTP/1.1 request to an onion service. The onion
    /// circuit authenticates the service and encrypts the exchange, which is
    /// why only `http://` is accepted: a TLS layer would add nothing.
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        if request.url.scheme() != "http" {
            return Err(TorError::http_request(
                "Onion HTTP requests use http://; the circuit already encrypts them",
            ));
        }
        let wire = build_request(&request, request.url.host())?;
        let mut stream = self.open_stream(&request.url).await?;
        execute_request(&mut stream, &wire).await
    }

    /// Open a raw stream to the URL's onion service and port.
    pub async fn open_stream(&self, url: &OnionUrl) -> Result<DataStream> {
        self.connect_stream(url.host(), url.port()).await
    }

    /// Open a raw stream to an onion address and virtual port, with no
    /// protocol layered on top. This is what talks to a service that speaks
    /// something other than HTTP.
    pub async fn connect_stream(&self, host: &str, port: u16) -> Result<DataStream> {
        self.ensure_ready().await?;
        self.onion.connect(host, port).await
    }

    /// Publish a v3 onion service from this client and start answering
    /// introductions. The identity key is generated here and never stored, so
    /// every call yields a new address that lives as long as the returned
    /// service.
    ///
    /// The descriptor is uploaded for the current onion service time period
    /// and the ones either side of it, and republished every hour or two —
    /// and again shortly after a period turns over, whenever that comes
    /// first. So the address stays reachable until the service is closed or
    /// dropped, including across the turnover that moves every HSDir ring.
    pub async fn publish_onion_service(
        &self,
        options: OnionServiceOptions,
    ) -> Result<OnionService> {
        self.ensure_ready().await?;
        OnionService::launch(
            self.circuit_manager.clone(),
            self.directory_manager.clone(),
            self.relay_manager.clone(),
            options,
            self.options.on_log.clone(),
        )
        .await
    }

    pub async fn ensure_ready(&self) -> Result<()> {
        if *self.initialized.read().await {
            return Ok(());
        }

        let _bootstrap_guard = self.bootstrap_lock.lock().await;
        if *self.initialized.read().await {
            return Ok(());
        }

        with_timeout(
            self.options.connection_timeout(),
            "Tor bootstrap",
            self.establish_channel(),
        )
        .await
    }

    /// Supply directory data for bootstrap to start from. It is validated and
    /// installed before any download; a missing, stale or unusable seed falls
    /// through to downloading the consensus over the bridge channel.
    pub async fn set_directory_seed(&self, encoded: &str) {
        *self.directory_seed.write().await = Some(encoded.to_string());
    }

    pub async fn directory_cache_json(&self) -> Result<Option<String>> {
        self.directory_manager.cache_json().await
    }

    pub async fn close(&self) {
        self.onion.close().await;
        *self.channel.write().await = None;
        *self.initialized.write().await = false;
    }

    async fn establish_channel(&self) -> Result<()> {
        let mut channel = self.open_bridge_channel().await?;

        if !self.install_directory_seed().await {
            self.log("Downloading current Tor directory data", LogType::Info);
            // Snowflake balances one fingerprint over several bridge
            // instances, and a wedged instance answers nothing. Reconnecting
            // is what moves the client to another one, so one directory
            // failure costs a new channel, not the bootstrap.
            if let Err(error) = self
                .directory_manager
                .fetch_and_process_consensus(channel.clone())
                .await
            {
                self.log(
                    &format!("Tor directory download failed ({error}); reconnecting to the bridge"),
                    LogType::Error,
                );
                channel.terminate();
                channel = self.open_bridge_channel().await?;
                self.directory_manager
                    .fetch_and_process_consensus(channel)
                    .await?;
            }
        }

        *self.initialized.write().await = true;
        Ok(())
    }

    async fn open_bridge_channel(&self) -> Result<Arc<tor_proto::channel::Channel>> {
        self.log("Establishing Snowflake bridge channel", LogType::Info);
        let rsa_identity = parse_snowflake_identity(self.options.bridge.fingerprint())?;

        let channel = match &self.options.bridge {
            BridgeType::SnowflakeWebRtc {
                broker_url,
                stun_urls,
                fingerprint,
            } => {
                self.log("Connecting to Snowflake via WebRTC", LogType::Info);
                let stream = SnowflakeWebRtcStream::connect(SnowflakeWebRtcConfig {
                    broker_url: broker_url.clone(),
                    fingerprint: fingerprint.clone(),
                    stun_urls: stun_urls.clone(),
                })
                .await?;
                self.create_channel(stream, rsa_identity).await?
            }
            BridgeType::SnowflakeWebSocket { url, .. } => {
                self.log("Connecting to Snowflake via WebSocket", LogType::Info);
                let stream = SnowflakeWsStream::connect(url).await?;
                self.create_channel(stream, rsa_identity).await?
            }
        };

        *self.channel.write().await = Some(channel.clone());
        self.log("Snowflake bridge channel established", LogType::Success);
        Ok(channel)
    }

    /// Install the caller-supplied directory data, if any. Returns false when
    /// there is none or it cannot be used, leaving the caller to download a
    /// consensus instead. A seed that is merely expired is the normal reason
    /// to fall through, so a rejection is reported and not fatal.
    async fn install_directory_seed(&self) -> bool {
        let Some(encoded) = self.directory_seed.read().await.clone() else {
            return false;
        };

        self.log("Loading the supplied Tor directory data", LogType::Info);
        if let Err(error) = self.directory_manager.load_cache(&encoded).await {
            self.log(
                &format!("Supplied Tor directory data was rejected: {error}"),
                LogType::Error,
            );
            return false;
        }

        true
    }

    async fn create_channel<S>(
        &self,
        stream: S,
        rsa_identity: RsaIdentity,
    ) -> Result<Arc<tor_proto::channel::Channel>>
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
                // Every circuit rides this one channel, so losing it takes the
                // whole client down. `debug!` is compiled out of a release
                // build, which made that the quietest possible failure.
                warn!(
                    "Tor channel reactor stopped: {}",
                    crate::error::error_chain(&error)
                );
            }
        });
        Ok(channel)
    }

    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.options.on_log {
            (callback.0)(message, log_type);
            return;
        }
        match log_type {
            LogType::Info | LogType::Success => info!("{}", message),
            LogType::Error => error!("{}", message),
        }
    }
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
