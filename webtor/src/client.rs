//! Browser Tor client used by anonymous Nostr signaling.

use crate::circuit::CircuitManager;
use crate::config::{BridgeType, LogType, TorClientOptions, SNOWFLAKE_FINGERPRINT};
use crate::directory::DirectoryManager;
use crate::error::{Result, TorError};
use crate::http::{HttpResponse, TorHttpClient};
use crate::relay::RelayManager;
use crate::retry::with_timeout;
use crate::snowflake_webrtc::{SnowflakeWebRtcConfig, SnowflakeWebRtcStream};
use crate::snowflake_ws::SnowflakeWsStream;
use crate::time::system_time_now;
use crate::wasm_runtime::WasmRuntime;

/// Mozilla's CA bundle, republished by the curl project. Its own certificate
/// chains to an embedded root, so fetching it needs no additional trust.
const CA_BUNDLE_URL: &str = "https://curl.se/ca/cacert.pem";
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tor_linkspec::OwnedChanTargetBuilder;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_memquota::MemoryQuotaTracker;
use tor_proto::channel::ChannelBuilder;
use tor_proto::client::stream::DataStream;
use tor_proto::memquota::{ChannelAccount, SpecificAccount};
use tracing::{debug, error, info};
use url::Url;

pub struct TorClient {
    options: TorClientOptions,
    circuit_manager: Arc<CircuitManager>,
    directory_manager: Arc<DirectoryManager>,
    http_client: TorHttpClient,
    initialized: RwLock<bool>,
    bootstrap_lock: Mutex<()>,
    channel: Arc<RwLock<Option<Arc<tor_proto::channel::Channel>>>>,
    /// Encoded directory data to fall back on, used only when the live
    /// download fails. Never validated or installed while a fresh consensus
    /// can be fetched.
    directory_cache_fallback: RwLock<Option<String>>,
}

impl TorClient {
    pub async fn new(options: TorClientOptions) -> Result<Self> {
        let channel = Arc::new(RwLock::new(None));
        let relay_manager = Arc::new(RwLock::new(RelayManager::new(Vec::new())));
        let directory_manager = Arc::new(DirectoryManager::new(
            relay_manager.clone(),
            options.on_log.clone(),
        ));
        let circuit_manager = Arc::new(CircuitManager::new(relay_manager, channel.clone()));

        Ok(Self {
            options,
            http_client: TorHttpClient::new(circuit_manager.clone()),
            circuit_manager,
            directory_manager,
            initialized: RwLock::new(false),
            bootstrap_lock: Mutex::new(()),
            channel,
            directory_cache_fallback: RwLock::new(None),
        })
    }

    /// Fetch the Mozilla CA bundle over Tor and trust its roots.
    ///
    /// subtle-tls embeds only ISRG Root X1/X2 and DigiCert Global Root G2,
    /// which covers Tor Check but rejects entire authorities — a relay behind
    /// Google Trust Services fails verification the moment TLS starts. The
    /// bundle host itself verifies against the embedded roots, so this
    /// bootstraps without a trust cycle.
    ///
    /// Call it after the exit is verified and before any relay connection.
    /// Errors are the caller's to weigh: the embedded roots still work, so a
    /// failed fetch narrows what can be reached rather than breaking Tor.
    pub async fn load_ca_bundle(&self) -> Result<usize> {
        self.log("Downloading the CA bundle over Tor", LogType::Info);
        let response = self.get(CA_BUNDLE_URL).await?;
        if !response.is_success() {
            return Err(TorError::Network(format!(
                "CA bundle request returned HTTP {}",
                response.status
            )));
        }

        let count = subtle_tls::load_extended_roots(&response.text()?)
            .map_err(|error| TorError::tls(format!("CA bundle was unusable: {error}")))?;
        self.log(
            &format!("Trusting {count} additional root CAs"),
            LogType::Success,
        );
        Ok(count)
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.ensure_ready().await?;
        self.http_client.get(Url::parse(url)?).await
    }

    pub async fn open_stream(&self, url: &Url) -> Result<DataStream> {
        self.ensure_ready().await?;
        let host = url
            .host_str()
            .ok_or_else(|| TorError::Configuration("URL has no host".to_string()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TorError::Configuration("URL has no port".to_string()))?;
        self.circuit_manager
            .ready_circuit()
            .await?
            .begin_stream(host, port)
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

    /// Register previously exported directory data as a bootstrap fallback.
    /// Bootstrap always downloads a fresh consensus first and only reaches for
    /// this copy when that download fails.
    pub async fn set_directory_cache_fallback(&self, encoded: &str) {
        *self.directory_cache_fallback.write().await = Some(encoded.to_string());
    }

    pub async fn directory_cache_json(&self) -> Result<Option<String>> {
        self.directory_manager.cache_json().await
    }

    pub async fn close(&self) {
        self.circuit_manager.close().await;
        *self.channel.write().await = None;
        *self.initialized.write().await = false;
    }

    async fn establish_channel(&self) -> Result<()> {
        self.log("Establishing Snowflake bridge channel", LogType::Info);
        let rsa_identity = parse_snowflake_identity()?;

        let channel = match &self.options.bridge {
            BridgeType::SnowflakeWebRtc {
                broker_url,
                stun_urls,
            } => {
                self.log("Connecting to Snowflake via WebRTC", LogType::Info);
                let stream = SnowflakeWebRtcStream::connect(SnowflakeWebRtcConfig {
                    broker_url: broker_url.clone(),
                    fingerprint: SNOWFLAKE_FINGERPRINT.to_string(),
                    stun_urls: stun_urls.clone(),
                })
                .await?;
                self.create_channel(stream, rsa_identity).await?
            }
            BridgeType::SnowflakeWebSocket { url } => {
                self.log("Connecting to Snowflake via WebSocket", LogType::Info);
                let stream = SnowflakeWsStream::connect(url).await?;
                self.create_channel(stream, rsa_identity).await?
            }
        };

        *self.channel.write().await = Some(channel.clone());
        self.log("Snowflake bridge channel established", LogType::Success);

        self.log("Downloading current Tor directory data", LogType::Info);
        if let Err(error) = self
            .directory_manager
            .fetch_and_process_consensus(channel)
            .await
        {
            self.use_directory_cache_fallback(error).await?;
        }

        let circuit = self.circuit_manager.create_circuit().await?;
        let relay_names: Vec<&str> = circuit
            .relays
            .iter()
            .map(|relay| relay.nickname.as_str())
            .collect();
        self.log(
            &format!("Tor circuit created: Snowflake → {}", relay_names.join(" → ")),
            LogType::Success,
        );
        *self.initialized.write().await = true;
        Ok(())
    }

    /// Last resort after a failed directory download. Reports the download
    /// error, not the cache error, since a stale or rejected cache is a
    /// symptom of the download having failed rather than the cause.
    async fn use_directory_cache_fallback(&self, download_error: TorError) -> Result<()> {
        let Some(encoded) = self.directory_cache_fallback.read().await.clone() else {
            return Err(download_error);
        };

        self.log(
            &format!("Tor directory download failed: {download_error}"),
            LogType::Error,
        );
        self.log("Trying the cached Tor directory data", LogType::Info);
        if let Err(cache_error) = self.directory_manager.load_cache(&encoded).await {
            self.log(
                &format!("Cached Tor directory data was rejected: {cache_error}"),
                LogType::Error,
            );
            return Err(download_error);
        }

        self.log("Using validated cached Tor directory data", LogType::Success);
        Ok(())
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
            .ok_or_else(|| TorError::Network("Bridge supplied no certificate".to_string()))?;

        let quota = MemoryQuotaTracker::new_noop();
        let account = ChannelAccount::new(&quota).map_err(|error| {
            TorError::Internal(format!("Failed to create channel quota account: {error}"))
        })?;
        let handshake = ChannelBuilder::new().launch_client(stream, WasmRuntime::new(), account);
        let unverified = handshake.connect(system_time_now).await.map_err(|error| {
            TorError::Network(format!("Tor channel handshake failed: {error}"))
        })?;

        let mut peer = OwnedChanTargetBuilder::default();
        peer.rsa_identity(rsa_identity);
        let peer = peer
            .build()
            .map_err(|error| TorError::Internal(format!("Invalid bridge target: {error}")))?;
        let (channel, reactor) = unverified
            .check(&peer, &peer_certificate, Some(system_time_now()))
            .map_err(|error| {
                TorError::Network(format!("Bridge authentication failed: {error}"))
            })?
            .finish()
            .await
            .map_err(|error| {
                TorError::Network(format!("Tor channel handshake failed: {error}"))
            })?;

        wasm_bindgen_futures::spawn_local(async move {
            if let Err(error) = reactor.run().await {
                debug!("Tor channel reactor stopped: {}", error);
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

fn parse_snowflake_identity() -> Result<RsaIdentity> {
    let bytes = hex::decode(SNOWFLAKE_FINGERPRINT)
        .map_err(|error| TorError::Configuration(format!("Invalid bridge identity: {error}")))?;
    RsaIdentity::from_bytes(&bytes)
        .ok_or_else(|| TorError::Configuration("Invalid bridge identity length".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snowflake_identity_is_valid() {
        assert!(parse_snowflake_identity().is_ok());
    }
}
