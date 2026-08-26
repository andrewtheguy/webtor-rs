//! Directory management and consensus fetching

use crate::authority::{authority_certs_path, parse_authority_certs, UncheckedConsensus};
use crate::config::{LogCallback, LogType};
use crate::error::{Result, TorError};
use crate::onion::HsDirParams;
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
use std::time::Duration;
use async_lock::RwLock;
use tor_netdoc::doc::microdesc::MicrodescReader;
use tor_netdoc::doc::netstatus::{MdConsensus, RelayWeight};
use tor_netdoc::AllowAnnotations;
use tor_proto::channel::Channel;
use tor_proto::client::circuit::TimeoutEstimator;
use tor_proto::client::ClientTunnel;
use tracing::{debug, error, info, warn};

const RELAYS_PER_ROLE: usize = 32;
const MIN_RELAYS_PER_ROLE: usize = 10;
/// Every HSDir is needed to place an onion service on its hash ring, so a
/// directory downloaded in the browser carries thousands of microdescriptors.
/// Requests of 92 digests (what C Tor sends) and several streams at once both
/// got the bridge circuit torn down, so this stays at the small sequential
/// batches that are known to work; a caller-supplied directory seed skips
/// the download entirely and is the intended path.
const MICRODESCRIPTOR_CHUNK_SIZE: usize = 46;
const MAX_PARALLEL_CHUNKS: usize = 1;
const MIN_HSDIR_RELAYS: usize = 100;
/// Bounds what one directory response off a Tor stream may buffer. The bridge
/// serving it is untrusted, so this caps an endless stream and a decompression
/// bomb; it does not bound directory data supplied by the embedding page.
const MAX_DIRECTORY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DIRECTORY_CACHE_VERSION: u32 = 3;
/// Bounds on the bridge's directory service. `tor-proto` has none of its
/// own, and an instance behind the Snowflake fingerprint sometimes takes a
/// CREATE_FAST or a BEGIN_DIR and never answers; a bounded failure lets the
/// client reconnect and land on another instance.
const DIRECTORY_CIRCUIT_TIMEOUT: Duration = Duration::from_secs(30);
const CONSENSUS_TIMEOUT: Duration = Duration::from_secs(90);
/// All nine authority certificates come back in about 20 KB, so this is far
/// more than the transfer needs. It is generous anyway because failing costs
/// a full bridge reconnect, and an instance that has just served a 3.6 MB
/// consensus can still take tens of seconds over the next stream.
const CERTIFICATE_TIMEOUT: Duration = Duration::from_secs(60);
const MICRODESCRIPTOR_BATCH_TIMEOUT: Duration = Duration::from_secs(40);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectoryCache {
    version: u32,
    consensus: String,
    /// The authority certificates that check `consensus`. A seed carries its
    /// own, because nothing checks it before it is installed.
    certificates: String,
    microdescriptors: String,
}

impl DirectoryCache {
    fn decode(encoded: &str) -> Result<Self> {
        let cache: Self = serde_json::from_str(encoded).map_err(|error| {
            TorError::serialization(format!("Directory cache was invalid JSON: {}", error))
        })?;
        if cache.version != DIRECTORY_CACHE_VERSION {
            return Err(TorError::ConsensusFetch(format!(
                "Directory cache version {} is unsupported",
                cache.version
            )));
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
    hsdir_count: usize,
    hsdir_params: HsDirParams,
}

/// Directory manager for handling network documents
pub struct DirectoryManager {
    pub relay_manager: Arc<RwLock<RelayManager>>,
    on_log: Option<LogCallback>,
    cache: Arc<RwLock<Option<DirectoryCache>>>,
    hsdir_params: Arc<RwLock<Option<HsDirParams>>>,
    /// Microdescriptors from a supplied directory whose consensus was
    /// rejected, keyed by digest. Microdescriptors carry no lifetime of
    /// their own — the consensus names each one by digest — so a download
    /// after a stale seed fetches only the digests not held here. Indexed
    /// before any directory circuit exists: the bridge destroys a one-hop
    /// circuit that carries no stream for 60 seconds, so the work between
    /// the consensus response and the first descriptor request must stay
    /// small.
    retained_microdescriptors: RwLock<HashMap<[u8; 32], String>>,
}

impl DirectoryManager {
    pub fn new(relay_manager: Arc<RwLock<RelayManager>>, on_log: Option<LogCallback>) -> Self {
        Self {
            relay_manager,
            on_log,
            cache: Arc::new(RwLock::new(None)),
            hsdir_params: Arc::new(RwLock::new(None)),
            retained_microdescriptors: RwLock::new(HashMap::new()),
        }
    }

    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.on_log {
            (callback.0)(message, log_type);
        }
    }

    pub async fn fetch_and_process_consensus(&self, channel: Arc<Channel>) -> Result<()> {
        self.log("Creating a Tor directory circuit...", LogType::Info);
        let tunnel = self.create_directory_tunnel(channel.clone()).await?;
        self.log("Tor directory circuit established", LogType::Success);

        self.log("Downloading the current Tor consensus...", LogType::Info);
        let consensus_body = self.fetch_consensus_body(tunnel.clone()).await?;
        let now = system_time_now();
        let unchecked = UncheckedConsensus::parse(&consensus_body, now)?;
        let certificates_body = self.fetch_authority_certificates(&tunnel, &unchecked).await?;
        let consensus = unchecked.validate(&parse_authority_certs(&certificates_body, now)?)?;
        self.log(
            "Tor consensus signatures verified against the directory authorities",
            LogType::Success,
        );
        let digests = select_microdescriptor_digests(&consensus)?;
        info!("Selected {} microdescriptor digests", digests.len());

        let mut microdescs_body = String::new();
        let mut missing = Vec::new();
        {
            let known = self.retained_microdescriptors.read().await;
            for digest in &digests {
                match known.get(digest) {
                    Some(text) => microdescs_body.push_str(text),
                    None => missing.push(*digest),
                }
            }
        }

        self.log(
            &format!(
                "Current Tor consensus loaded; {} relay descriptors retained, downloading {}...",
                digests.len() - missing.len(),
                missing.len()
            ),
            LogType::Info,
        );
        if !missing.is_empty() {
            microdescs_body.push_str(
                &self
                    .fetch_microdescriptors_body(channel, tunnel, &missing)
                    .await?,
            );
        }
        info!(
            "Microdescriptors body: {} bytes ({} downloaded)",
            microdescs_body.len(),
            missing.len()
        );

        let processed = process_directory_documents(&consensus, &microdescs_body)?;
        self.install_directory(processed, false).await;
        self.retained_microdescriptors.write().await.clear();
        *self.cache.write().await = Some(DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: consensus_body,
            certificates: certificates_body,
            microdescriptors: microdescs_body,
        });

        Ok(())
    }

    pub async fn load_cache(&self, encoded: &str) -> Result<()> {
        self.log("Validating cached Tor directory data...", LogType::Info);
        let cache = DirectoryCache::decode(encoded)?;
        let processed = match validate_directory_documents(
            &cache.consensus,
            &cache.certificates,
            &cache.microdescriptors,
        ) {
            Ok(processed) => processed,
            Err(error) => {
                let known = index_microdescriptors(&cache.microdescriptors);
                info!("Retained {} microdescriptors from the rejected directory", known.len());
                *self.retained_microdescriptors.write().await = known;
                return Err(error);
            }
        };
        self.install_directory(processed, true).await;
        *self.cache.write().await = Some(cache);
        Ok(())
    }

    /// The onion-service placement parameters of the installed consensus.
    pub(crate) async fn hsdir_params(&self) -> Result<HsDirParams> {
        self.hsdir_params
            .read()
            .await
            .clone()
            .ok_or_else(|| TorError::Onion("No Tor directory is installed".to_string()))
    }

    pub async fn cache_json(&self) -> Result<Option<String>> {
        let cache = self.cache.read().await;
        cache.as_ref().map(DirectoryCache::encode).transpose()
    }

    async fn install_directory(&self, processed: ProcessedDirectory, from_cache: bool) {
        let count = processed.relays.len();
        {
            let mut manager = self.relay_manager.write().await;
            manager.update_relays(processed.relays);
        }
        *self.hsdir_params.write().await = Some(processed.hsdir_params);

        info!("Updated RelayManager with {} relays", count);
        let source = if from_cache { "supplied" } else { "downloaded" };
        self.log(
            &format!(
                "Loaded {} {} Tor relays ({} middle, {} HSDir)",
                count, source, processed.middle_count, processed.hsdir_count
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
        let tunnel = crate::retry::with_timeout(
            DIRECTORY_CIRCUIT_TIMEOUT,
            "Creating the directory circuit",
            async {
                pending_tunnel.create_firsthop_fast(params).await.map_err(|e| {
                    TorError::Internal(format!("Failed to create dir circuit: {}", e))
                })
            },
        )
        .await?;

        Ok(Arc::new(tunnel))
    }

    async fn fetch_consensus_body(&self, tunnel: Arc<ClientTunnel>) -> Result<String> {
        info!("Fetching consensus from bridge...");
        let body = crate::retry::with_timeout(
            CONSENSUS_TIMEOUT,
            "Consensus download",
            fetch_directory_document(&tunnel, "/tor/status-vote/current/consensus-microdesc"),
        )
        .await?;
        info!("Received consensus: {} bytes", body.len());
        Ok(body)
    }

    /// Download the authority certificates that `consensus`'s signatures
    /// name. The bridge serving them is untrusted, which is the whole point:
    /// a certificate it substitutes fails its own self-signature check, and
    /// one it omits leaves the consensus short of a majority.
    async fn fetch_authority_certificates(
        &self,
        tunnel: &Arc<ClientTunnel>,
        consensus: &UncheckedConsensus,
    ) -> Result<String> {
        let ids = consensus.required_cert_ids();
        if ids.is_empty() {
            return Err(TorError::ConsensusFetch(
                "Consensus carries no signature from a known directory authority".to_string(),
            ));
        }
        info!("Fetching {} authority certificates from bridge...", ids.len());
        self.log(
            "Downloading Tor directory authority certificates...",
            LogType::Info,
        );
        let body = crate::retry::with_timeout(
            CERTIFICATE_TIMEOUT,
            "Authority certificate download",
            fetch_directory_document(tunnel, &authority_certs_path(&ids)),
        )
        .await?;
        info!("Received authority certificates: {} bytes", body.len());
        Ok(body)
    }

    /// Download `digests` from the bridge in sequential chunks. A chunk the
    /// bridge answers with an HTTP error is skipped: right after a consensus
    /// switch a bridge instance can name microdescriptors it has not fetched
    /// yet, and a ring missing a few relays still works. Some bridge
    /// instances instead destroy the directory circuit on such a request, so
    /// a chunk that fails any other way is retried once on a fresh circuit
    /// over the same channel.
    async fn fetch_microdescriptors_body(
        &self,
        channel: Arc<Channel>,
        mut tunnel: Arc<ClientTunnel>,
        digests: &[[u8; 32]],
    ) -> Result<String> {
        info!(
            "Fetching {} microdescriptors in chunks of {} (max {} parallel)...",
            digests.len(),
            MICRODESCRIPTOR_CHUNK_SIZE,
            MAX_PARALLEL_CHUNKS
        );

        let chunks: Vec<&[[u8; 32]]> = digests.chunks(MICRODESCRIPTOR_CHUNK_SIZE).collect();
        let total_chunks = chunks.len();
        let total_batches = total_chunks.div_ceil(MAX_PARALLEL_CHUNKS);
        let mut all_results = Vec::new();

        for (batch_idx, batch) in chunks.chunks(MAX_PARALLEL_CHUNKS).enumerate() {
            let batch_start = batch_idx * MAX_PARALLEL_CHUNKS;
            self.log(
                &format!(
                    "Downloading Tor relay descriptors (batch {}/{})...",
                    batch_idx + 1,
                    total_batches
                ),
                LogType::Info,
            );

            let mut result = self
                .fetch_microdescriptor_batch(&tunnel, batch, batch_start, total_chunks)
                .await;
            if let Err(error) = &result {
                // A timeout means this bridge instance is not answering; a
                // new circuit there fares no better, so let the caller
                // reconnect instead.
                if !matches!(error, TorError::DirectoryStatus(_) | TorError::Timeout(_)) {
                    warn!("Microdescriptor batch failed ({error}); retrying on a new directory circuit");
                    self.log(
                        "Tor directory circuit failed; opening another...",
                        LogType::Info,
                    );
                    tunnel = self.create_directory_tunnel(channel.clone()).await?;
                    result = self
                        .fetch_microdescriptor_batch(&tunnel, batch, batch_start, total_chunks)
                        .await;
                }
            }
            match result {
                Ok(results) => all_results.extend(results),
                Err(TorError::DirectoryStatus(status)) => warn!(
                    "Bridge answered HTTP {status} for a microdescriptor batch; continuing without it"
                ),
                Err(error) => return Err(error),
            }
        }

        let combined = all_results.join("");
        info!(
            "Fetched all microdescriptors: {} bytes total",
            combined.len()
        );
        Ok(combined)
    }

    async fn fetch_microdescriptor_batch(
        &self,
        tunnel: &Arc<ClientTunnel>,
        batch: &[&[[u8; 32]]],
        batch_start: usize,
        total_chunks: usize,
    ) -> Result<Vec<String>> {
        let futures: Vec<_> = batch
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                self.fetch_microdescriptors_chunk(
                    tunnel.clone(),
                    chunk,
                    batch_start + i,
                    total_chunks,
                )
            })
            .collect();
        crate::retry::with_timeout(
            MICRODESCRIPTOR_BATCH_TIMEOUT,
            "Microdescriptor download",
            futures::future::try_join_all(futures),
        )
        .await
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
        let digests_str: Vec<String> = digests
            .iter()
            .map(encode_microdescriptor_digest)
            .collect();
        let path = format!("/tor/micro/d/{}", digests_str.join("-"));
        let body = fetch_directory_document(&tunnel, &path).await?;
        debug!(
            "Chunk {}/{}: received {} bytes",
            chunk_idx + 1,
            total_chunks,
            body.len()
        );
        Ok(body)
    }
}

/// GET one document from the directory cache at the end of `tunnel`, with
/// the request shape Tor clients use, and return the decoded body.
pub(crate) async fn fetch_directory_document(
    tunnel: &Arc<ClientTunnel>,
    path: &str,
) -> Result<String> {
    let mut stream = tunnel
        .clone()
        .begin_dir_stream()
        .await
        .map_err(|e| TorError::Internal(format!("Failed to begin dir stream: {}", e)))?;
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
    let body = decode_directory_response(&response)?;
    String::from_utf8(body)
        .map_err(|e| TorError::serialization(format!("Directory document is not UTF-8: {}", e)))
}

fn select_microdescriptor_digests(consensus: &MdConsensus) -> Result<Vec<[u8; 32]>> {
    let mut middle_digests: Vec<[u8; 32]> = consensus
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
    let hsdir_digests: Vec<[u8; 32]> = consensus
        .relays()
        .iter()
        .filter(|router| router.is_flagged_hsdir())
        .map(|router| *router.md_digest())
        .collect();

    let mut rng = rand::rng();
    middle_digests.shuffle(&mut rng);
    middle_digests.truncate(RELAYS_PER_ROLE);

    if middle_digests.len() < MIN_RELAYS_PER_ROLE {
        return Err(TorError::ConsensusFetch(format!(
            "Consensus has only {} eligible middle relays",
            middle_digests.len()
        )));
    }
    if hsdir_digests.len() < MIN_HSDIR_RELAYS {
        return Err(TorError::ConsensusFetch(format!(
            "Consensus has only {} HSDir relays",
            hsdir_digests.len()
        )));
    }

    let mut seen = HashSet::new();
    Ok(middle_digests
        .into_iter()
        .chain(hsdir_digests)
        .filter(|digest| seen.insert(*digest))
        .collect())
}

/// Check `consensus_body` against `certificates_body` and turn the result,
/// with `microdescriptors_body`, into the relays to install. This is the only
/// way a supplied directory reaches [`RelayManager`]: a seed arrives with no
/// circuit behind it, so it carries the certificates that vouch for it.
fn validate_directory_documents(
    consensus_body: &str,
    certificates_body: &str,
    microdescriptors_body: &str,
) -> Result<ProcessedDirectory> {
    let now = system_time_now();
    let consensus = UncheckedConsensus::parse(consensus_body, now)?
        .validate(&parse_authority_certs(certificates_body, now)?)?;
    process_directory_documents(&consensus, microdescriptors_body)
}

fn process_directory_documents(
    consensus: &MdConsensus,
    microdescriptors_body: &str,
) -> Result<ProcessedDirectory> {
    let hsdir_params = HsDirParams::from_consensus(consensus)?;

    let mut router_statuses = HashMap::new();
    for router in consensus.relays() {
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
    let hsdir_count = relays
        .iter()
        .filter(|relay| relay.flags.contains("HSDir"))
        .count();
    if middle_count < MIN_RELAYS_PER_ROLE || hsdir_count < MIN_HSDIR_RELAYS {
        return Err(TorError::ConsensusFetch(format!(
            "Directory returned insufficient usable relays (middle: {}, HSDir: {})",
            middle_count, hsdir_count
        )));
    }

    Ok(ProcessedDirectory {
        relays,
        middle_count,
        hsdir_count,
        hsdir_params,
    })
}

/// Every parseable microdescriptor in `body`, keyed by digest, as the text
/// the consensus digest covers (each ending in a newline so they concatenate
/// back into a document `MicrodescReader` accepts).
fn index_microdescriptors(body: &str) -> HashMap<[u8; 32], String> {
    let mut known = HashMap::new();
    let Ok(reader) = MicrodescReader::new(body, &AllowAnnotations::AnnotationsNotAllowed) else {
        return known;
    };
    for annotated in reader.flatten() {
        let Some(text) = annotated.within(body) else {
            continue;
        };
        let mut text = text.to_string();
        if !text.ends_with('\n') {
            text.push('\n');
        }
        known.insert(*annotated.md().digest(), text);
    }
    known
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
        return Err(TorError::DirectoryStatus(status));
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
            certificates: "certificates".to_string(),
            microdescriptors: "microdescriptors".to_string(),
        };

        let decoded = DirectoryCache::decode(&cache.encode().unwrap()).unwrap();

        assert_eq!(decoded.version, DIRECTORY_CACHE_VERSION);
        assert_eq!(decoded.consensus, "consensus");
        assert_eq!(decoded.certificates, "certificates");
        assert_eq!(decoded.microdescriptors, "microdescriptors");
    }

    #[test]
    fn directory_cache_rejects_a_seed_without_certificates() {
        let encoded = serde_json::json!({
            "version": DIRECTORY_CACHE_VERSION,
            "consensus": "consensus",
            "microdescriptors": "microdescriptors"
        })
        .to_string();

        let error = DirectoryCache::decode(&encoded).unwrap_err();

        assert!(error.to_string().contains("certificates"), "{}", error);
    }

    #[test]
    fn directory_cache_rejects_unknown_versions() {
        let encoded = serde_json::json!({
            "version": DIRECTORY_CACHE_VERSION + 1,
            "consensus": "consensus",
            "certificates": "certificates",
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

        assert!(matches!(error, TorError::DirectoryStatus(404)));
    }
}

#[cfg(test)]
mod microdescriptor_index_tests {
    use super::*;

    const TWO: &str = include_str!("../testdata/two-microdescriptors.txt");

    #[test]
    fn indexed_microdescriptors_splice_back_into_a_parseable_document() {
        let known = index_microdescriptors(TWO);
        assert_eq!(known.len(), 2);

        let spliced: String = known.values().cloned().collect();
        let reader =
            MicrodescReader::new(&spliced, &AllowAnnotations::AnnotationsNotAllowed).unwrap();
        let digests: HashSet<[u8; 32]> = reader
            .map(|md| *md.unwrap().md().digest())
            .collect();
        assert_eq!(digests, known.keys().copied().collect());
    }

    #[test]
    fn indexing_skips_unparseable_text() {
        assert!(index_microdescriptors("not a microdescriptor\n").is_empty());
    }
}

