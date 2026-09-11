//! The browser Tor client.
//!
//! Bootstrapping means opening the Snowflake bridge channel and installing a
//! directory. Every stream after that goes to an onion service on a circuit
//! built for it; nothing this client does reaches a Tor exit.

use crate::bridge::Bridge;
use crate::circuit::CircuitManager;
use crate::config::{LogType, TorClientOptions};
use crate::directory::DirectoryManager;
use crate::error::{Result, TorError};
use crate::http::{build_request, execute_request, HttpRequest, HttpResponse};
use crate::onion_url::OnionUrl;
use crate::onion::OnionConnector;
use crate::onion_service::{OnionService, OnionServiceOptions};
use crate::relay::RelayManager;
use crate::retry::with_timeout;
use std::rc::Rc;
use std::sync::Arc;
use async_lock::{Mutex, RwLock};
use tor_proto::client::stream::DataStream;
use tracing::{error, info, warn};

pub struct TorClient {
    options: TorClientOptions,
    directory_manager: Rc<DirectoryManager>,
    /// Circuit and relay state, shared with the onion client and with any
    /// service this client publishes.
    circuit_manager: Rc<CircuitManager>,
    relay_manager: Arc<RwLock<RelayManager>>,
    onion: OnionConnector,
    initialized: RwLock<bool>,
    bootstrap_lock: Mutex<()>,
    /// Encoded directory data to bootstrap from. Downloading the consensus
    /// and the microdescriptors over a single bridge circuit is the least
    /// reliable step of a bootstrap, so a caller-supplied directory is tried
    /// first and the download only runs when there is none or it is rejected.
    directory_seed: RwLock<Option<String>>,
}

impl TorClient {
    pub async fn new(options: TorClientOptions) -> Result<Self> {
        let relay_manager = Arc::new(RwLock::new(RelayManager::new(Vec::new())));
        let directory_manager = Rc::new(DirectoryManager::new(
            relay_manager.clone(),
            options.on_log.clone(),
            options.on_directory_change.clone(),
        ));
        let circuit_manager = Rc::new(CircuitManager::new(
            relay_manager.clone(),
            Bridge::new(options.bridge.clone(), options.on_log.clone()),
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
        execute_request(&mut stream, &wire, request.max_response_bytes).await
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
            return self.reopen_if_closed().await;
        }

        let _bootstrap_guard = self.bootstrap_lock.lock().await;
        if *self.initialized.read().await {
            return self.reopen_if_closed().await;
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
        self.circuit_manager.close_channel().await;
        *self.initialized.write().await = false;
    }

    /// A bootstrapped client whose bridge channel has closed, a proxy having
    /// gone for good, opens another before the call that found it closed
    /// starts: that call's own timeouts are for its circuits, and reopening
    /// through the broker can take longer than any of them allows. The
    /// directory it has is kept.
    async fn reopen_if_closed(&self) -> Result<()> {
        with_timeout(
            self.options.connection_timeout(),
            "Reopening the Snowflake bridge channel",
            self.circuit_manager.channel(),
        )
        .await
        .map(|_| ())
    }

    async fn establish_channel(&self) -> Result<()> {
        let mut channel = self.circuit_manager.open_channel().await?;

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
                channel = self.circuit_manager.open_channel().await?;
                self.directory_manager
                    .fetch_and_process_consensus(channel)
                    .await?;
            }
        }

        *self.initialized.write().await = true;
        Ok(())
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

    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.options.on_log {
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
