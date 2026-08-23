//! Directory management and consensus fetching

use crate::config::{LogCallback, LogType};
use crate::error::{Result, TorError};
use crate::relay::{Relay, RelayManager};
use crate::time::system_time_now;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use flate2::read::ZlibDecoder;
use futures::{AsyncReadExt, AsyncWriteExt};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;
use tokio::sync::RwLock;
use tor_checkable::Timebound;
use tor_netdoc::doc::microdesc::MicrodescReader;
use tor_netdoc::doc::netstatus::{MdConsensus, RelayWeight};
use tor_netdoc::AllowAnnotations;
use tor_proto::channel::Channel;
use tor_proto::client::circuit::TimeoutEstimator;
use tor_proto::client::ClientTunnel;
use tracing::{debug, error, info, warn};

const RELAYS_PER_ROLE: usize = 32;
const MIN_RELAYS_PER_ROLE: usize = 10;
const MICRODESCRIPTOR_CHUNK_SIZE: usize = 16;
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DIRECTORY_CACHE_VERSION: u32 = 1;
const MAX_DIRECTORY_CACHE_BYTES: usize = MAX_DIRECTORY_RESPONSE_BYTES * 2 + 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectoryCache {
    version: u32,
    consensus: String,
    microdescriptors: String,
}

impl DirectoryCache {
    fn decode(encoded: &str) -> Result<Self> {
        if encoded.len() > MAX_DIRECTORY_CACHE_BYTES {
            return Err(TorError::ConsensusFetch(format!(
                "Directory cache exceeded {} bytes",
                MAX_DIRECTORY_CACHE_BYTES
            )));
        }

        let cache: Self = serde_json::from_str(encoded).map_err(|error| {
            TorError::serialization(format!("Directory cache was invalid JSON: {}", error))
        })?;
        if cache.version != DIRECTORY_CACHE_VERSION {
            return Err(TorError::ConsensusFetch(format!(
                "Directory cache version {} is unsupported",
                cache.version
            )));
        }
        if cache.consensus.len() > MAX_DIRECTORY_RESPONSE_BYTES
            || cache.microdescriptors.len() > MAX_DIRECTORY_RESPONSE_BYTES
        {
            return Err(TorError::ConsensusFetch(
                "Directory cache contained an oversized document".to_string(),
            ));
        }

        Ok(cache)
    }

    fn encode(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|error| {
            TorError::serialization(format!("Failed to serialize directory cache: {}", error))
        })
    }
}

#[derive(Debug)]
struct ProcessedDirectory {
    relays: Vec<Relay>,
    middle_count: usize,
    exit_count: usize,
}

/// Directory manager for handling network documents
pub struct DirectoryManager {
    pub relay_manager: Arc<RwLock<RelayManager>>,
    on_log: Option<LogCallback>,
    cache: Arc<RwLock<Option<DirectoryCache>>>,
}

impl DirectoryManager {
    pub fn new(relay_manager: Arc<RwLock<RelayManager>>, on_log: Option<LogCallback>) -> Self {
        Self {
            relay_manager,
            on_log,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.on_log {
            (callback.0)(message, log_type);
        }
    }

    pub async fn fetch_and_process_consensus(&self, channel: Arc<Channel>) -> Result<()> {
        self.log("Creating a Tor directory circuit...", LogType::Info);
        let tunnel = self.create_directory_tunnel(channel).await?;
        self.log("Tor directory circuit established", LogType::Success);

        self.log("Downloading the current Tor consensus...", LogType::Info);
        let consensus_body = self.fetch_consensus_body(tunnel.clone()).await?;
        let digests = select_microdescriptor_digests(&consensus_body)?;

        self.log(
            &format!(
                "Current Tor consensus loaded; downloading {} relay descriptors...",
                digests.len()
            ),
            LogType::Info,
        );
        info!("Selected {} microdescriptor digests", digests.len());

        let microdescs_body = self.fetch_microdescriptors_body(tunnel, &digests).await?;
        info!(
            "Fetched microdescriptors body: {} bytes",
            microdescs_body.len()
        );

        let processed = process_directory_documents(&consensus_body, &microdescs_body)?;
        self.install_directory(processed, false).await;
        *self.cache.write().await = Some(DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: consensus_body,
            microdescriptors: microdescs_body,
        });

        Ok(())
    }

    pub async fn load_cache(&self, encoded: &str) -> Result<()> {
        self.log("Validating cached Tor directory data...", LogType::Info);
        let cache = DirectoryCache::decode(encoded)?;
        let processed = process_directory_documents(&cache.consensus, &cache.microdescriptors)?;
        self.install_directory(processed, true).await;
        *self.cache.write().await = Some(cache);
        Ok(())
    }

    pub async fn cache_json(&self) -> Result<Option<String>> {
        let cache = self.cache.read().await;
        cache.as_ref().map(DirectoryCache::encode).transpose()
    }

    pub async fn has_directory_data(&self) -> bool {
        !self.relay_manager.read().await.relays.is_empty()
    }

    async fn install_directory(&self, processed: ProcessedDirectory, from_cache: bool) {
        let count = processed.relays.len();
        {
            let mut manager = self.relay_manager.write().await;
            manager.update_relays(processed.relays);
        }

        info!("Updated RelayManager with {} relays", count);
        let source = if from_cache { "cached" } else { "current" };
        self.log(
            &format!(
                "Loaded {} {} Tor relays ({} middle, {} HTTPS exit)",
                count, source, processed.middle_count, processed.exit_count
            ),
            LogType::Success,
        );
    }

    async fn create_directory_tunnel(&self, channel: Arc<Channel>) -> Result<Arc<ClientTunnel>> {
        let (pending_tunnel, reactor) = channel
            .new_tunnel(
                Arc::new(crate::circuit::SimpleTimeoutEstimator) as Arc<dyn TimeoutEstimator>
            )
            .await
            .map_err(|e| {
                TorError::Internal(format!("Failed to create pending tunnel for dir: {}", e))
            })?;

        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });

        let params = crate::circuit::make_circ_params()?;
        let tunnel = pending_tunnel
            .create_firsthop_fast(params)
            .await
            .map_err(|e| TorError::Internal(format!("Failed to create dir circuit: {}", e)))?;

        Ok(Arc::new(tunnel))
    }

    async fn fetch_consensus_body(&self, tunnel: Arc<ClientTunnel>) -> Result<String> {
        info!("Fetching consensus from bridge...");

        let mut stream = tunnel
            .begin_dir_stream()
            .await
            .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;

        let path = "/tor/status-vote/current/consensus-microdesc";
        let request = format!(
            "GET {} HTTP/1.0\r\n\
             Host: directory\r\n\
             Accept-Encoding: deflate\r\n\
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

        // Read and decode the response. Stop at Content-Length rather than
        // waiting indefinitely for the directory stream to close.
        let response = read_directory_response(&mut stream).await?;

        info!("Received consensus response: {} bytes", response.len());

        // 5. Process response
        let body = decode_directory_response(&response)?;
        String::from_utf8(body).map_err(|e| {
            TorError::serialization(format!("Directory consensus is not UTF-8: {}", e))
        })
    }

    async fn fetch_microdescriptors_body(
        &self,
        tunnel: Arc<ClientTunnel>,
        digests: &[[u8; 32]],
    ) -> Result<String> {
        const MAX_PARALLEL_CHUNKS: usize = 1;

        info!(
            "Fetching {} microdescriptors in chunks of {} (max {} parallel)...",
            digests.len(),
            MICRODESCRIPTOR_CHUNK_SIZE,
            MAX_PARALLEL_CHUNKS
        );

        let chunks: Vec<&[[u8; 32]]> = digests.chunks(MICRODESCRIPTOR_CHUNK_SIZE).collect();
        let total_chunks = chunks.len();
        let mut all_results = Vec::new();

        // Process chunks in batches of MAX_PARALLEL_CHUNKS
        for (batch_idx, batch) in chunks.chunks(MAX_PARALLEL_CHUNKS).enumerate() {
            let batch_start = batch_idx * MAX_PARALLEL_CHUNKS;
            info!(
                "Fetching chunk batch {}/{} (chunks {}-{})",
                batch_idx + 1,
                total_chunks.div_ceil(MAX_PARALLEL_CHUNKS),
                batch_start + 1,
                (batch_start + batch.len()).min(total_chunks)
            );
            self.log(
                &format!(
                    "Downloading Tor relay descriptors (batch {}/{})...",
                    batch_idx + 1,
                    total_chunks.div_ceil(MAX_PARALLEL_CHUNKS)
                ),
                LogType::Info,
            );

            let futures: Vec<_> = batch
                .iter()
                .enumerate()
                .map(|(i, chunk)| {
                    let chunk_idx = batch_start + i;
                    self.fetch_microdescriptors_chunk(
                        tunnel.clone(),
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
        tunnel: Arc<ClientTunnel>,
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

        let mut stream = tunnel
            .begin_dir_stream()
            .await
            .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;

        let digests_str: Vec<String> = digests
            .iter()
            .map(encode_microdescriptor_digest)
            .collect();
        let path = format!("/tor/micro/d/{}", digests_str.join("-"));

        let request = format!(
            "GET {} HTTP/1.0\r\n\
             Host: directory\r\n\
             Accept-Encoding: deflate\r\n\
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

        let response = read_directory_response(&mut stream).await?;

        debug!(
            "Chunk {}/{}: received {} bytes",
            chunk_idx + 1,
            total_chunks,
            response.len()
        );

        let body = decode_directory_response(&response)?;
        String::from_utf8(body).map_err(|e| {
            TorError::serialization(format!("Microdescriptor response is not UTF-8: {}", e))
        })
    }
}

fn select_microdescriptor_digests(consensus_body: &str) -> Result<Vec<[u8; 32]>> {
    info!("Parsing full consensus");
    let (_, _, unvalidated) = MdConsensus::parse(consensus_body)
        .map_err(|error| TorError::serialization(format!("Failed to parse consensus: {}", error)))?;
    let consensus = unvalidated
        .check_valid_at(&system_time_now())
        .map_err(|error| {
            TorError::ConsensusFetch(format!(
                "Consensus timeliness check failed: {}",
                error
            ))
        })?;
    let inner_consensus = &consensus.consensus;

    let mut middle_digests: Vec<[u8; 32]> = inner_consensus
        .relays()
        .iter()
        .filter(|router| {
            router.is_flagged_fast()
                && router.is_flagged_stable()
                && router.is_flagged_v2dir()
                && router.weight().is_nonzero()
        })
        .map(|router| *router.md_digest())
        .collect();
    let mut exit_digests: Vec<[u8; 32]> = inner_consensus
        .relays()
        .iter()
        .filter(|router| {
            router.is_flagged_fast()
                && router.is_flagged_stable()
                && router.is_flagged_exit()
                && !router.is_flagged_bad_exit()
                && router.weight().is_nonzero()
        })
        .map(|router| *router.md_digest())
        .collect();

    let mut rng = rand::thread_rng();
    middle_digests.shuffle(&mut rng);
    exit_digests.shuffle(&mut rng);
    middle_digests.truncate(RELAYS_PER_ROLE);
    exit_digests.truncate(RELAYS_PER_ROLE);

    if middle_digests.len() < MIN_RELAYS_PER_ROLE {
        return Err(TorError::ConsensusFetch(format!(
            "Consensus has only {} eligible middle relays",
            middle_digests.len()
        )));
    }
    if exit_digests.len() < MIN_RELAYS_PER_ROLE {
        return Err(TorError::ConsensusFetch(format!(
            "Consensus has only {} eligible exit relays",
            exit_digests.len()
        )));
    }

    let mut seen = HashSet::new();
    Ok(middle_digests
        .into_iter()
        .chain(exit_digests)
        .filter(|digest| seen.insert(*digest))
        .collect())
}

fn process_directory_documents(
    consensus_body: &str,
    microdescriptors_body: &str,
) -> Result<ProcessedDirectory> {
    if consensus_body.len() > MAX_DIRECTORY_RESPONSE_BYTES
        || microdescriptors_body.len() > MAX_DIRECTORY_RESPONSE_BYTES
    {
        return Err(TorError::ConsensusFetch(
            "Directory document exceeded the cache size limit".to_string(),
        ));
    }

    let (_, _, unvalidated) = MdConsensus::parse(consensus_body)
        .map_err(|error| TorError::serialization(format!("Failed to parse consensus: {}", error)))?;
    let consensus = unvalidated
        .check_valid_at(&system_time_now())
        .map_err(|error| {
            TorError::ConsensusFetch(format!(
                "Consensus timeliness check failed: {}",
                error
            ))
        })?;
    let inner_consensus = &consensus.consensus;

    let mut router_statuses = HashMap::new();
    for router in inner_consensus.relays() {
        router_statuses.insert(*router.md_digest(), router.clone());
    }

    let mut relays = Vec::new();
    let mut seen_microdescriptors = HashSet::new();
    let reader = MicrodescReader::new(
        microdescriptors_body,
        &AllowAnnotations::AnnotationsNotAllowed,
    )?;
    for microdescriptor in reader {
        let microdescriptor = match microdescriptor {
            Ok(document) => document.into_microdesc(),
            Err(error) => {
                warn!("Failed to parse microdescriptor: {}", error);
                continue;
            }
        };
        if !seen_microdescriptors.insert(*microdescriptor.digest()) {
            continue;
        }

        if let Some(router) = router_statuses.get(microdescriptor.digest()) {
            let nickname = router.nickname().to_string();
            let fingerprint = hex::encode(router.rsa_identity().as_bytes());
            let address = if let Some(address) = router.addrs().next() {
                address.ip().to_string()
            } else {
                continue;
            };
            let or_port = router.addrs().next().map(|address| address.port()).unwrap_or(0);

            let mut flags = HashSet::new();
            if router.is_flagged_fast() {
                flags.insert("Fast".to_string());
            }
            if router.is_flagged_stable() {
                flags.insert("Stable".to_string());
            }
            if router.is_flagged_guard() {
                flags.insert("Guard".to_string());
            }
            if router.is_flagged_exit() && microdescriptor.ipv4_policy().allows_port(443) {
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

            let ntor_onion_key = hex::encode(microdescriptor.ntor_key().as_bytes());
            let mut relay = Relay::new(
                fingerprint,
                nickname,
                address,
                or_port,
                flags,
                ntor_onion_key,
            );
            relay.ed25519_identity = Some(hex::encode(microdescriptor.ed25519_id().as_bytes()));
            relay.consensus_weight = relay_weight_value(router.weight());
            relays.push(relay);
        }
    }

    let middle_count = relays
        .iter()
        .filter(|relay| {
            relay.flags.contains("Fast")
                && relay.flags.contains("Stable")
                && relay.flags.contains("V2Dir")
        })
        .count();
    let exit_count = relays
        .iter()
        .filter(|relay| {
            relay.flags.contains("Fast")
                && relay.flags.contains("Stable")
                && relay.flags.contains("Exit")
                && !relay.flags.contains("BadExit")
        })
        .count();

    if middle_count < MIN_RELAYS_PER_ROLE || exit_count < MIN_RELAYS_PER_ROLE {
        return Err(TorError::ConsensusFetch(format!(
            "Directory returned insufficient usable relays (middle: {}, HTTPS exit: {})",
            middle_count, exit_count
        )));
    }

    Ok(ProcessedDirectory {
        relays,
        middle_count,
        exit_count,
    })
}

fn relay_weight_value(weight: &RelayWeight) -> u32 {
    match weight {
        RelayWeight::Unmeasured(value) | RelayWeight::Measured(value) => *value,
        _ => 0,
    }
}

fn encode_microdescriptor_digest(digest: &[u8; 32]) -> String {
    STANDARD_NO_PAD.encode(digest)
}

async fn read_directory_response<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: futures::AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut metadata = None;

    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|e| TorError::Network(format!("Failed to read directory response: {}", e)))?;
        if read == 0 {
            break;
        }

        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_DIRECTORY_RESPONSE_BYTES {
            return Err(TorError::ConsensusFetch(format!(
                "Directory response exceeded {} bytes",
                MAX_DIRECTORY_RESPONSE_BYTES
            )));
        }

        if metadata.is_none() {
            metadata = directory_response_metadata(&response)?;
        }
        if let Some((body_start, Some(content_length))) = metadata {
            let expected_length = body_start.checked_add(content_length).ok_or_else(|| {
                TorError::ConsensusFetch("Directory Content-Length overflowed".to_string())
            })?;
            if response.len() >= expected_length {
                response.truncate(expected_length);
                break;
            }
        }
    }

    let (body_start, content_length) = directory_response_metadata(&response)?.ok_or_else(|| {
        TorError::ConsensusFetch("Directory response had incomplete HTTP headers".to_string())
    })?;
    if let Some(content_length) = content_length {
        let actual_length = response.len().saturating_sub(body_start);
        if actual_length != content_length {
            return Err(TorError::ConsensusFetch(format!(
                "Directory response body was truncated (expected {}, received {})",
                content_length, actual_length
            )));
        }
    }

    Ok(response)
}

fn directory_response_metadata(response: &[u8]) -> Result<Option<(usize, Option<usize>)>> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        if response.len() > 64 * 1024 {
            return Err(TorError::ConsensusFetch(
                "Directory response headers exceeded 64 KiB".to_string(),
            ));
        }
        return Ok(None);
    };
    let body_start = header_end + 4;
    let header_text = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        TorError::ConsensusFetch(format!("Directory response headers are not UTF-8: {}", e))
    })?;
    let content_length = header_text.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });

    Ok(Some((body_start, content_length)))
}

fn decode_directory_response(response: &[u8]) -> Result<Vec<u8>> {
    let (body_start, content_length) = directory_response_metadata(response)?.ok_or_else(|| {
        TorError::ConsensusFetch("Directory response had incomplete HTTP headers".to_string())
    })?;
    let header_text = std::str::from_utf8(&response[..body_start - 4]).map_err(|e| {
        TorError::ConsensusFetch(format!("Directory response headers are not UTF-8: {}", e))
    })?;
    let mut lines = header_text.lines();
    let status_line = lines.next().ok_or_else(|| {
        TorError::ConsensusFetch("Directory response had no HTTP status".to_string())
    })?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            TorError::ConsensusFetch("Directory response had an invalid HTTP status".to_string())
        })?
        .parse::<u16>()
        .map_err(|e| {
            TorError::ConsensusFetch(format!("Directory response status was invalid: {}", e))
        })?;
    if status != 200 {
        return Err(TorError::ConsensusFetch(format!(
            "Directory request returned HTTP {}",
            status
        )));
    }

    let mut content_encoding = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-encoding") {
                content_encoding = Some(value.trim().to_ascii_lowercase());
            }
        }
    }

    let body_end = content_length
        .and_then(|length| body_start.checked_add(length))
        .unwrap_or(response.len());
    if body_end > response.len() {
        return Err(TorError::ConsensusFetch(
            "Directory response body was truncated".to_string(),
        ));
    }
    let encoded_body = &response[body_start..body_end];

    match content_encoding.as_deref() {
        None | Some("identity") => Ok(encoded_body.to_vec()),
        Some("deflate") => {
            let mut decoded = Vec::new();
            ZlibDecoder::new(encoded_body)
                .take((MAX_DIRECTORY_RESPONSE_BYTES + 1) as u64)
                .read_to_end(&mut decoded)
                .map_err(|e| {
                    TorError::ConsensusFetch(format!(
                        "Failed to decompress directory response: {}",
                        e
                    ))
                })?;
            if decoded.len() > MAX_DIRECTORY_RESPONSE_BYTES {
                return Err(TorError::ConsensusFetch(format!(
                    "Decompressed directory response exceeded {} bytes",
                    MAX_DIRECTORY_RESPONSE_BYTES
                )));
            }
            Ok(decoded)
        }
        Some(encoding) => Err(TorError::ConsensusFetch(format!(
            "Directory returned unsupported Content-Encoding {}",
            encoding
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn directory_cache_round_trips() {
        let cache = DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: "consensus".to_string(),
            microdescriptors: "microdescriptors".to_string(),
        };

        let decoded = DirectoryCache::decode(&cache.encode().unwrap()).unwrap();

        assert_eq!(decoded.version, DIRECTORY_CACHE_VERSION);
        assert_eq!(decoded.consensus, "consensus");
        assert_eq!(decoded.microdescriptors, "microdescriptors");
    }

    #[test]
    fn directory_cache_rejects_unknown_versions() {
        let encoded = serde_json::json!({
            "version": DIRECTORY_CACHE_VERSION + 1,
            "consensus": "consensus",
            "microdescriptors": "microdescriptors"
        })
        .to_string();

        let error = DirectoryCache::decode(&encoded).unwrap_err();

        assert!(error.to_string().contains("unsupported"));
    }

    #[test]
    fn microdescriptor_digest_uses_unpadded_standard_base64() {
        let digest = [0xff; 32];
        let encoded = encode_microdescriptor_digest(&digest);

        assert_eq!(encoded.len(), 43);
        assert!(encoded.contains('/'));
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('-'));
        assert_eq!(STANDARD_NO_PAD.decode(encoded).unwrap(), digest);
    }

    #[test]
    fn directory_response_decodes_deflate_content() {
        let expected = b"network-status-version 3 microdesc\n";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(expected).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut response = format!(
            "HTTP/1.0 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        response.extend_from_slice(&compressed);

        assert_eq!(decode_directory_response(&response).unwrap(), expected);
    }

    #[test]
    fn directory_response_rejects_http_errors() {
        let response = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let error = decode_directory_response(response).unwrap_err();

        assert!(error.to_string().contains("HTTP 404"));
    }
}
