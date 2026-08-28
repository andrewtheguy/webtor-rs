//! The directory this client builds circuits from.
//!
//! One directory is a consensus, the authority certificates that sign it, and
//! the microdescriptors it names. This module gets those — downloaded over a
//! bridge, or supplied by the caller as a seed — checks them against the
//! pinned authorities, and turns them into the relays and onion service rings
//! everything else selects from. Speaking HTTP to a directory cache to get
//! them is [`crate::dir_http`].

use crate::authority::{authority_certs_path, parse_authority_certs, UncheckedConsensus};
use crate::config::{DirectoryCallback, LogCallback, LogType};
use crate::dir_http::fetch_directory_document;
use crate::error::{Result, TorError};
use crate::onion::{HsDirParams, HsDirPlacement, HsDirRings};
use crate::relay::{Relay, RelayManager};
use crate::time::system_time_now;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_lock::RwLock;
use tor_netdoc::doc::microdesc::MicrodescReader;
use tor_checkable::{ExternallySigned, Timebound};
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

/// What a directory says about itself: the window its consensus covers, and
/// where that consensus places onion service descriptors.
///
/// Whether a directory is *good enough* is the caller's question — a seed can
/// be perfectly valid and still sit in the period the network has just left,
/// which is a policy call about how much slack an application will accept. But
/// answering it means reading a consensus, and there is no reason for every
/// caller to learn the document format to do that. This is the reading; the
/// judgement stays outside.
#[derive(Clone, Copy, Debug)]
pub struct DirectoryDescription {
    valid_after: SystemTime,
    valid_until: SystemTime,
    time_period: u64,
    placement: HsDirPlacement,
}

impl DirectoryDescription {
    /// When the consensus became valid.
    pub fn valid_after(&self) -> SystemTime {
        self.valid_after
    }

    /// When the consensus expires. A client refuses to install a seed past
    /// this, so it is the deadline a caller has to beat.
    pub fn valid_until(&self) -> SystemTime {
        self.valid_until
    }

    /// The onion service time period the consensus itself falls in — the ring
    /// this directory would place every descriptor on.
    pub fn time_period(&self) -> u64 {
        self.time_period
    }

    /// The time period `at` falls in, by this consensus's own division of
    /// time. A caller compares it with [`Self::time_period`] to see whether
    /// the directory still describes the ring the network is using.
    pub fn time_period_at(&self, at: SystemTime) -> Result<u64> {
        Ok(self.placement.period_at(at)?.interval_num())
    }
}

/// Read what a `directory_cache_json` seed says about itself, without
/// installing it or touching the network.
///
/// This checks nothing: the consensus is read as it is written, signatures
/// and timeliness unexamined, because a description makes no claim that the
/// directory is genuine. Only [`DirectoryManager::load_cache`] does, against
/// the pinned authorities, and it does so whatever a caller concluded here.
pub fn describe_directory(encoded: &str) -> Result<DirectoryDescription> {
    let cache = DirectoryCache::decode(encoded)?;
    let (_, _, timebound) = MdConsensus::parse(&cache.consensus).map_err(|error| {
        TorError::serialization(format!("Failed to parse consensus: {}", error))
    })?;
    let consensus = timebound
        .dangerously_assume_timely()
        .dangerously_assume_wellsigned();

    let lifetime = consensus.lifetime();
    let placement = HsDirPlacement::of(&consensus);
    Ok(DirectoryDescription {
        valid_after: lifetime.valid_after(),
        valid_until: lifetime.valid_until(),
        time_period: placement.period_at(lifetime.valid_after())?.interval_num(),
        placement,
    })
}

#[derive(Debug)]
struct ProcessedDirectory {
    relays: Vec<Relay>,
    middle_count: usize,
    hsdir_count: usize,
    hsdir_params: HsDirRings,
}

/// The directory in force, and what it took to get it: one of these holds
/// the installed consensus, the relays it named, and the seed a caller can
/// store to skip the download next time.
pub struct DirectoryManager {
    relay_manager: Arc<RwLock<RelayManager>>,
    on_log: Option<LogCallback>,
    /// Told about every directory this manager downloads. Nothing here stores
    /// a seed anywhere but in memory; keeping one is the caller's business,
    /// and this is how a caller hears there is a newer one to keep.
    on_directory_change: Option<DirectoryCallback>,
    cache: Arc<RwLock<Option<DirectoryCache>>>,
    hsdir_params: Arc<RwLock<Option<HsDirRings>>>,
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
    pub fn new(
        relay_manager: Arc<RwLock<RelayManager>>,
        on_log: Option<LogCallback>,
        on_directory_change: Option<DirectoryCallback>,
    ) -> Self {
        Self {
            relay_manager,
            on_log,
            on_directory_change,
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
        // Relays turn over slowly, so nearly every microdescriptor a new
        // consensus names is one this client already holds. Keeping them turns
        // a refresh from thousands of downloads over a single bridge circuit
        // into a handful, which is what makes refreshing affordable at all.
        let retained_is_empty = self.retained_microdescriptors.read().await.is_empty();
        if retained_is_empty {
            let installed = self
                .cache
                .read()
                .await
                .as_ref()
                .map(|cache| index_microdescriptors(&cache.microdescriptors));
            if let Some(installed) = installed {
                *self.retained_microdescriptors.write().await = installed;
            }
        }

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
        let cache = DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: consensus_body,
            certificates: certificates_body,
            microdescriptors: microdescs_body,
        };
        self.announce(&cache);
        *self.cache.write().await = Some(cache);

        Ok(())
    }

    /// Offer a downloaded directory to whoever asked to be told about one.
    ///
    /// Only downloads reach here. A seed the caller supplied is already in its
    /// hands, and announcing it back would report a change that never
    /// happened.
    fn announce(&self, cache: &DirectoryCache) {
        let Some(callback) = &self.on_directory_change else {
            return;
        };
        match cache.encode() {
            Ok(encoded) => (callback.0)(&encoded),
            Err(error) => warn!("Could not offer the refreshed directory to the caller: {error}"),
        }
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
    pub(crate) async fn hsdir_params(&self) -> Result<HsDirRings> {
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
    let hsdir_params = HsDirParams::compute(consensus)?;

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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A consensus with no relays in it, dated long enough ago that nothing
    /// could mistake it for a timely one.
    const CONSENSUS: &str = include_str!("../testdata/microdesc-consensus.txt");

    fn seed_carrying(consensus: &str) -> String {
        DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: consensus.to_string(),
            certificates: String::new(),
            microdescriptors: String::new(),
        }
        .encode()
        .unwrap()
    }

    fn at(unix_seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix_seconds)
    }

    /// 2020-08-27 13:00:00 UTC, the fixture's `valid-after`.
    const VALID_AFTER: u64 = 1_598_533_200;

    #[test]
    fn a_seed_describes_the_window_its_consensus_covers() {
        let described = describe_directory(&seed_carrying(CONSENSUS)).unwrap();

        assert_eq!(described.valid_after(), at(VALID_AFTER));
        assert_eq!(described.valid_until(), at(VALID_AFTER + 3 * 60 * 60));
    }

    /// The fixture names no `hsdir_interval` and votes hourly, so its periods
    /// are a day long and begin at noon UTC. That boundary is the whole reason
    /// a caller asks: a seed from 11:00 places descriptors on the ring the
    /// network left at noon, while still being a valid consensus.
    #[test]
    fn a_seed_places_descriptors_by_the_noon_boundary() {
        let described = describe_directory(&seed_carrying(CONSENSUS)).unwrap();
        let period = described.time_period();

        assert_eq!(described.time_period_at(at(VALID_AFTER)).unwrap(), period);
        assert_eq!(
            described.time_period_at(at(VALID_AFTER + 10 * 60 * 60)).unwrap(),
            period,
            "23:00 the same day is still the period that began at noon"
        );
        assert_eq!(
            described.time_period_at(at(VALID_AFTER - 2 * 60 * 60)).unwrap(),
            period - 1,
            "11:00 the same day is the period before it"
        );
        assert_eq!(
            described.time_period_at(at(VALID_AFTER + 24 * 60 * 60)).unwrap(),
            period + 1
        );
    }

    /// Describing checks nothing, which is what makes it useful: a caller
    /// deciding whether to keep a stored seed is holding an expired one more
    /// often than not, and it still needs to say why it is throwing it away.
    #[test]
    fn a_long_expired_seed_still_describes_itself() {
        assert!(describe_directory(&seed_carrying(CONSENSUS)).is_ok());
    }

    #[test]
    fn a_seed_that_carries_no_consensus_cannot_be_described() {
        let error = describe_directory(&seed_carrying("not a consensus\n")).unwrap_err();

        assert!(error.to_string().contains("parse consensus"), "{}", error);
    }

    #[test]
    fn a_seed_of_an_unknown_version_cannot_be_described() {
        let encoded = serde_json::json!({
            "version": DIRECTORY_CACHE_VERSION + 1,
            "consensus": CONSENSUS,
            "certificates": "",
            "microdescriptors": ""
        })
        .to_string();

        let error = describe_directory(&encoded).unwrap_err();

        assert!(error.to_string().contains("unsupported"), "{}", error);
    }

    fn recording_manager() -> (DirectoryManager, Arc<std::sync::Mutex<Vec<String>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let manager = DirectoryManager::new(
            Arc::new(RwLock::new(RelayManager::new(Vec::new()))),
            None,
            Some(DirectoryCallback(Arc::new(move |encoded: &str| {
                recorder.lock().unwrap().push(encoded.to_string());
            }))),
        );
        (manager, seen)
    }

    fn cache_of(consensus: &str) -> DirectoryCache {
        DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: consensus.to_string(),
            certificates: "certificates".to_string(),
            microdescriptors: "microdescriptors".to_string(),
        }
    }

    /// What a caller is handed has to be the same thing `directory_cache_json`
    /// hands it, or storing one and seeding from the other would not work.
    #[test]
    fn a_downloaded_directory_reaches_the_caller_as_a_seed() {
        let (manager, seen) = recording_manager();

        manager.announce(&cache_of("consensus"));

        let announced = seen.lock().unwrap();
        assert_eq!(announced.len(), 1);
        assert_eq!(DirectoryCache::decode(&announced[0]).unwrap().consensus, "consensus");
    }

    /// The push and the pull have to agree: a caller that stores what it is
    /// handed and one that exports the cache itself must end up with the same
    /// seed, or only one of the two ways of keeping a directory would work.
    #[tokio::test]
    async fn what_is_announced_is_what_the_cache_exports() {
        let (manager, seen) = recording_manager();
        let cache = cache_of("consensus");

        manager.announce(&cache);
        *manager.cache.write().await = Some(cache);

        let exported = manager.cache_json().await.unwrap().unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), [exported]);
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

