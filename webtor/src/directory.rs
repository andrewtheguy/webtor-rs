//! Directory management and consensus fetching

use crate::error::{Result, TorError};
use crate::relay::{Relay, RelayManager};
use crate::time::system_time_now;
use futures::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
#[cfg(target_arch = "wasm32")]
use std::io::Read;
use std::sync::Arc;
use tokio::sync::RwLock;
use tor_checkable::Timebound;
use tor_netdoc::doc::microdesc::MicrodescReader;
use tor_netdoc::doc::netstatus::MdConsensus;
use tor_netdoc::AllowAnnotations;
use tor_proto::channel::Channel;
use tor_proto::client::circuit::TimeoutEstimator;
use tracing::{debug, error, info, warn};

/// Bootstrap directory data bundled into the WASM binary.
///
/// A Tor circuit cannot fetch fresh directory data until it has enough relay
/// information to build that first circuit. Embedding the compressed snapshot
/// avoids a cross-origin bootstrap dependency and works from any static host.
#[cfg(target_arch = "wasm32")]
const CACHED_CONSENSUS: &[u8] = include_bytes!("cached/consensus.txt.br");
#[cfg(target_arch = "wasm32")]
const CACHED_MICRODESCRIPTORS: &[u8] = include_bytes!("cached/microdescriptors.txt.br");

/// Directory manager for handling network documents
pub struct DirectoryManager {
    pub relay_manager: Arc<RwLock<RelayManager>>,
}

impl DirectoryManager {
    pub fn new(relay_manager: Arc<RwLock<RelayManager>>) -> Self {
        Self { relay_manager }
    }

    /// Load relays from the bundled cached consensus data.
    /// This is used for WASM builds where we can't fetch consensus before establishing a circuit.
    #[cfg(target_arch = "wasm32")]
    pub async fn load_cached_consensus(&self) -> Result<()> {
        info!("Loading bundled cached consensus...");
        info!(
            "Loaded compressed consensus: {} bytes",
            CACHED_CONSENSUS.len()
        );

        let consensus_body = decompress_brotli(CACHED_CONSENSUS)
            .map_err(|e| TorError::Internal(format!("Failed to decompress consensus: {}", e)))?;
        info!("Decompressed consensus: {} bytes", consensus_body.len());

        info!(
            "Loaded compressed microdescriptors: {} bytes",
            CACHED_MICRODESCRIPTORS.len()
        );

        let microdescs_body = decompress_brotli(CACHED_MICRODESCRIPTORS).map_err(|e| {
            TorError::Internal(format!("Failed to decompress microdescriptors: {}", e))
        })?;
        info!(
            "Decompressed microdescriptors: {} bytes",
            microdescs_body.len()
        );

        // Parse and process
        self.process_consensus_data(&consensus_body, &microdescs_body)
            .await
    }

    /// Load relays from cached consensus - native version (not implemented, use fetch_and_process_consensus)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_cached_consensus(&self) -> Result<()> {
        // For native builds, we don't pre-load cached consensus
        // The circuit will be created after fetching fresh consensus via the Tor network
        info!("Native build: skipping cached consensus (will fetch fresh via Tor)");
        Ok(())
    }

    /// Process consensus and microdescriptor data into relays
    #[cfg(target_arch = "wasm32")]
    async fn process_consensus_data(
        &self,
        consensus_body: &str,
        microdescs_body: &str,
    ) -> Result<()> {
        info!("Parsing consensus...");

        // Parse consensus - for cached data, we skip time validation since it may be stale
        // The daily update job keeps it fresh enough for circuit building
        let (_, _, unvalidated) = MdConsensus::parse(consensus_body)
            .map_err(|e| TorError::serialization(format!("Failed to parse consensus: {}", e)))?;

        // For cached consensus, we use dangerously_assume_timely() to skip time checks
        // This is acceptable because:
        // 1. The cached consensus is updated daily by GitHub Actions
        // 2. We only use it for relay selection, not for security-critical decisions
        // 3. Once connected, we can fetch fresh consensus through the Tor network
        let consensus = unvalidated.dangerously_assume_timely();

        let inner_consensus = &consensus.consensus;
        info!(
            "Parsed consensus with {} relays",
            inner_consensus.relays().len()
        );

        let mut router_statuses = HashMap::new();
        for router in inner_consensus.relays() {
            router_statuses.insert(*router.md_digest(), router.clone());
        }

        let mut relays = Vec::new();
        let reader =
            MicrodescReader::new(microdescs_body, &AllowAnnotations::AnnotationsNotAllowed)?;
        for microdesc in reader {
            let microdesc = match microdesc {
                Ok(md) => md.into_microdesc(),
                Err(e) => {
                    warn!("Failed to parse microdescriptor: {}", e);
                    continue;
                }
            };

            if let Some(router) = router_statuses.get(microdesc.digest()) {
                let nickname = router.nickname().to_string();
                let fingerprint = hex::encode(router.rsa_identity().as_bytes());

                let address = if let Some(addr) = router.addrs().next() {
                    addr.ip().to_string()
                } else {
                    continue;
                };

                let or_port = router.addrs().next().map(|a| a.port()).unwrap_or(0);

                let mut flags = std::collections::HashSet::new();
                if router.is_flagged_fast() {
                    flags.insert("Fast".to_string());
                }
                if router.is_flagged_stable() {
                    flags.insert("Stable".to_string());
                }
                if router.is_flagged_guard() {
                    flags.insert("Guard".to_string());
                }
                if router.is_flagged_exit() {
                    flags.insert("Exit".to_string());
                }
                if router.is_flagged_bad_exit() {
                    flags.insert("BadExit".to_string());
                }
                if router.is_flagged_hsdir() {
                    flags.insert("HSDir".to_string());
                }
                if router.is_flagged_v2dir() {
                    flags.insert("V2Dir".to_string());
                }

                let ntor_onion_key = hex::encode(microdesc.ntor_key().as_bytes());

                let mut relay = Relay::new(
                    fingerprint,
                    nickname,
                    address,
                    or_port,
                    flags,
                    ntor_onion_key,
                );

                relay.ed25519_identity = Some(hex::encode(microdesc.ed25519_id().as_bytes()));

                relays.push(relay);
            }
        }

        let count = relays.len();

        {
            let mut manager = self.relay_manager.write().await;
            manager.update_relays(relays);
        }

        info!("Loaded {} relays from cached consensus", count);

        Ok(())
    }

    pub async fn fetch_and_process_consensus(&self, channel: Arc<Channel>) -> Result<()> {
        let consensus_body = self.fetch_consensus_body(channel.clone()).await?;

        info!("Parsing full consensus");
        let (_, _, unvalidated) = MdConsensus::parse(&consensus_body)
            .map_err(|e| TorError::serialization(format!("Failed to parse consensus: {}", e)))?;
        let consensus = unvalidated
            .check_valid_at(&system_time_now())
            .map_err(|e| {
                TorError::ConsensusFetch(format!("Consensus timeliness check failed: {}", e))
            })?;

        let inner_consensus = &consensus.consensus;

        let digests: Vec<[u8; 32]> = inner_consensus
            .relays()
            .iter()
            .map(|r| *r.md_digest())
            .collect();

        info!("Got {} microdescriptor digests", digests.len());

        let microdescs_body = self.fetch_microdescriptors_body(channel, &digests).await?;
        info!(
            "Fetched microdescriptors body: {} bytes",
            microdescs_body.len()
        );

        let mut router_statuses = HashMap::new();
        for router in inner_consensus.relays() {
            router_statuses.insert(*router.md_digest(), router.clone());
        }

        let mut relays = Vec::new();
        let reader =
            MicrodescReader::new(&microdescs_body, &AllowAnnotations::AnnotationsNotAllowed)?;
        for microdesc in reader {
            let microdesc = match microdesc {
                Ok(md) => md.into_microdesc(),
                Err(e) => {
                    warn!("Failed to parse microdescriptor: {}", e);
                    continue;
                }
            };

            if let Some(router) = router_statuses.get(microdesc.digest()) {
                let nickname = router.nickname().to_string();
                let fingerprint = hex::encode(router.rsa_identity().as_bytes());

                let address = if let Some(addr) = router.addrs().next() {
                    addr.ip().to_string()
                } else {
                    continue;
                };

                let or_port = router.addrs().next().map(|a| a.port()).unwrap_or(0);

                let mut flags = std::collections::HashSet::new();
                if router.is_flagged_fast() {
                    flags.insert("Fast".to_string());
                }
                if router.is_flagged_stable() {
                    flags.insert("Stable".to_string());
                }
                if router.is_flagged_guard() {
                    flags.insert("Guard".to_string());
                }
                if router.is_flagged_exit() {
                    flags.insert("Exit".to_string());
                }
                if router.is_flagged_bad_exit() {
                    flags.insert("BadExit".to_string());
                }
                if router.is_flagged_hsdir() {
                    flags.insert("HSDir".to_string());
                }
                if router.is_flagged_v2dir() {
                    flags.insert("V2Dir".to_string());
                }

                let ntor_onion_key = hex::encode(microdesc.ntor_key().as_bytes());

                let mut relay = Relay::new(
                    fingerprint,
                    nickname,
                    address,
                    or_port,
                    flags,
                    ntor_onion_key,
                );

                relay.ed25519_identity = Some(hex::encode(microdesc.ed25519_id().as_bytes()));

                relays.push(relay);
            }
        }

        let count = relays.len();

        {
            let mut manager = self.relay_manager.write().await;
            manager.update_relays(relays);
        }

        info!("Updated RelayManager with {} relays", count);

        Ok(())
    }

    async fn fetch_consensus_body(&self, channel: Arc<Channel>) -> Result<String> {
        info!("Fetching consensus from bridge...");

        // 1. Create 1-hop circuit (tunnel)
        let (pending_tunnel, reactor) = channel
            .new_tunnel(
                Arc::new(crate::circuit::SimpleTimeoutEstimator) as Arc<dyn TimeoutEstimator>
            )
            .await
            .map_err(|e| {
                TorError::Internal(format!("Failed to create pending tunnel for dir: {}", e))
            })?;

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });

        let params = crate::circuit::make_circ_params()?;
        let tunnel = pending_tunnel
            .create_firsthop_fast(params)
            .await
            .map_err(|e| TorError::Internal(format!("Failed to create dir circuit: {}", e)))?;

        // 2. Open directory stream
        let tunnel_arc = Arc::new(tunnel);
        let mut stream = tunnel_arc
            .begin_dir_stream()
            .await
            .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;

        // 3. Send HTTP GET request for microdescriptor consensus
        let path = "/tor/status-vote/current/consensus-microdesc";
        let request = format!(
            "GET {} HTTP/1.0\r\n\
             Host: directory\r\n\
             Connection: close\r\n\
             \r\n",
            path
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| TorError::Network(format!("Failed to write dir request: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Failed to flush dir request: {}", e)))?;

        // 4. Read response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| TorError::Network(format!("Failed to read dir response: {}", e)))?;

        info!("Received consensus response: {} bytes", response.len());

        // 5. Process response
        let body_start = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(0);

        let body = &response[body_start..];
        Ok(String::from_utf8_lossy(body).to_string())
    }

    async fn fetch_microdescriptors_body(
        &self,
        channel: Arc<Channel>,
        digests: &[[u8; 32]],
    ) -> Result<String> {
        const CHUNK_SIZE: usize = 256;
        const MAX_PARALLEL_CHUNKS: usize = 3;

        info!(
            "Fetching {} microdescriptors in chunks of {} (max {} parallel)...",
            digests.len(),
            CHUNK_SIZE,
            MAX_PARALLEL_CHUNKS
        );

        let chunks: Vec<&[[u8; 32]]> = digests.chunks(CHUNK_SIZE).collect();
        let total_chunks = chunks.len();
        let mut all_results = Vec::new();

        // Process chunks in batches of MAX_PARALLEL_CHUNKS
        for (batch_idx, batch) in chunks.chunks(MAX_PARALLEL_CHUNKS).enumerate() {
            let batch_start = batch_idx * MAX_PARALLEL_CHUNKS;
            info!(
                "Fetching chunk batch {}/{} (chunks {}-{})",
                batch_idx + 1,
                (total_chunks + MAX_PARALLEL_CHUNKS - 1) / MAX_PARALLEL_CHUNKS,
                batch_start + 1,
                (batch_start + batch.len()).min(total_chunks)
            );

            let futures: Vec<_> = batch
                .iter()
                .enumerate()
                .map(|(i, chunk)| {
                    let chunk_idx = batch_start + i;
                    self.fetch_microdescriptors_chunk(
                        channel.clone(),
                        chunk,
                        chunk_idx,
                        total_chunks,
                    )
                })
                .collect();

            let results = futures::future::try_join_all(futures).await?;
            all_results.extend(results);
        }

        let combined = all_results.join("");
        info!(
            "Fetched all microdescriptors: {} bytes total",
            combined.len()
        );
        Ok(combined)
    }

    async fn fetch_microdescriptors_chunk(
        &self,
        channel: Arc<Channel>,
        digests: &[[u8; 32]],
        chunk_idx: usize,
        total_chunks: usize,
    ) -> Result<String> {
        debug!(
            "Fetching chunk {}/{} with {} digests",
            chunk_idx + 1,
            total_chunks,
            digests.len()
        );

        let (pending_tunnel, reactor) = channel
            .new_tunnel(
                Arc::new(crate::circuit::SimpleTimeoutEstimator) as Arc<dyn TimeoutEstimator>
            )
            .await
            .map_err(|e| {
                TorError::Internal(format!("Failed to create pending tunnel for dir: {}", e))
            })?;

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });

        let params = crate::circuit::make_circ_params()?;
        let tunnel = pending_tunnel
            .create_firsthop_fast(params)
            .await
            .map_err(|e| TorError::Internal(format!("Failed to create dir circuit: {}", e)))?;

        let tunnel_arc = Arc::new(tunnel);
        let mut stream = tunnel_arc
            .begin_dir_stream()
            .await
            .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;

        let digests_str: Vec<String> = digests.iter().map(|d| hex::encode_upper(d)).collect();
        let path = format!("/tor/micro/d/{}", digests_str.join("-"));

        let request = format!(
            "GET {} HTTP/1.0\r\n\
             Host: directory\r\n\
             Connection: close\r\n\
             \r\n",
            path
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| TorError::Network(format!("Failed to write dir request: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Failed to flush dir request: {}", e)))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| TorError::Network(format!("Failed to read dir response: {}", e)))?;

        debug!(
            "Chunk {}/{}: received {} bytes",
            chunk_idx + 1,
            total_chunks,
            response.len()
        );

        let body_start = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(0);

        let body = &response[body_start..];
        Ok(String::from_utf8_lossy(body).to_string())
    }
}

/// Decompress brotli-compressed data
#[cfg(target_arch = "wasm32")]
fn decompress_brotli(compressed: &[u8]) -> std::io::Result<String> {
    let mut decompressed = Vec::new();
    let mut decoder = brotli::Decompressor::new(compressed, 4096);
    decoder.read_to_end(&mut decompressed)?;
    String::from_utf8(decompressed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
