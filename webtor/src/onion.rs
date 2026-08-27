//! Onion service (v3) client.
//!
//! Connecting to a `.onion` address has three network phases, each on its own
//! three-hop circuit from the Snowflake bridge:
//!
//! 1. fetch the service descriptor from an HSDir chosen from the hash ring
//!    the consensus defines for the current time period;
//! 2. establish a rendezvous point and send an INTRODUCE1 through one of the
//!    descriptor's introduction points;
//! 3. finish the hs-ntor handshake with the RENDEZVOUS2 the service sends to
//!    the rendezvous point and extend that circuit by a virtual hop.
//!
//! Streams then begin on the virtual hop. The onion address commits to the
//! service key, so the circuit is authenticated end to end without TLS.

use crate::circuit::{make_circ_params, CircuitManager};
use crate::config::{LogCallback, LogType};
use crate::directory::{fetch_directory_document, DirectoryManager};
use crate::error::{Result, TorError};
use crate::relay::{selection, Relay, RelayManager};
use crate::retry::with_timeout;
use crate::time::system_time_now;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use digest::Digest;
use futures::channel::oneshot;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::ops::Range;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use async_lock::RwLock;
use tor_bytes::Writeable;
use tor_cell::relaycell::hs::intro_payload::{IntroduceHandshakePayload, OnionKey};
use tor_cell::relaycell::hs::{
    AuthKeyType, EstablishRendezvous, Introduce1, IntroduceAck, Rendezvous2,
};
use tor_cell::relaycell::msg::{AnyRelayMsg, Body};
use tor_cell::relaycell::RelayMsg;
use tor_checkable::Timebound;
use tor_hscrypto::pk::{HsBlindId, HsId, HsIdKey};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::{RendCookie, Subcredential};
use tor_linkspec::decode::Strictness;
use tor_linkspec::verbatim::VerbatimLinkSpecCircTarget;
use tor_linkspec::{CircTarget, OwnedChanTargetBuilder, OwnedCircTarget};
use tor_llcrypto::d::Sha3_256;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_netdoc::doc::hsdesc::{HsDesc, IntroPointDesc};
use tor_netdoc::doc::netstatus::MdConsensus;
use tor_proto::client::circuit::handshake::{hs_ntor, HandshakeRole, RelayProtocol};
use tor_proto::client::stream::DataStream;
use tor_proto::{ClientTunnel, MetaCellDisposition, MsgHandler, TargetHop};
use tor_protover::Protocols;
use tracing::{debug, info};

/// Consensus parameter `hsdir_interval` default and bounds, in minutes.
const HSDIR_INTERVAL_DEFAULT_MINUTES: i32 = 1440;
const HSDIR_INTERVAL_BOUNDS: (i32, i32) = (30, 14400);
/// Consensus `hsdir_n_replicas` and `hsdir_spread_fetch` defaults.
const HSDIR_N_REPLICAS: u8 = 2;
const HSDIR_SPREAD_FETCH: usize = 3;
/// Time periods start this many voting periods after the epoch.
const VOTING_PERIODS_IN_OFFSET: u32 = 12;
/// A shared random value lives this many voting periods.
const VOTING_PERIODS_IN_SRV_ROUND: u32 = 24;
const ONE_DAY: Duration = Duration::from_secs(24 * 60 * 60);

const MAX_HSDIR_ATTEMPTS: usize = 4;
const MAX_INTRO_ATTEMPTS: usize = 3;
const DESCRIPTOR_TIMEOUT: Duration = Duration::from_secs(90);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(90);
const INTRODUCE_TIMEOUT: Duration = Duration::from_secs(90);
const RENDEZVOUS_COMPLETION_TIMEOUT: Duration = Duration::from_secs(90);

/// What the consensus says about where descriptors live right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HsDirParams {
    time_period: TimePeriod,
    shared_rand: [u8; 32],
}

impl HsDirParams {
    /// Derive the current time period and its shared random value.
    ///
    /// Mirrors `tor-netdir`'s `HsDirParams::compute` for the current period
    /// only: a client needs the period the consensus is in, not the
    /// neighbouring ones a service also publishes to.
    pub(crate) fn from_consensus(consensus: &MdConsensus) -> Result<Self> {
        let minutes = consensus
            .params()
            .get("hsdir_interval")
            .copied()
            .unwrap_or(HSDIR_INTERVAL_DEFAULT_MINUTES)
            .clamp(HSDIR_INTERVAL_BOUNDS.0, HSDIR_INTERVAL_BOUNDS.1);
        let length = Duration::from_secs(u64::from(minutes.unsigned_abs()) * 60);

        let lifetime = consensus.lifetime();
        let valid_after = lifetime.valid_after();
        let voting_period = lifetime.voting_period();
        let offset = voting_period * VOTING_PERIODS_IN_OFFSET;
        let time_period = TimePeriod::new(length, valid_after, offset).map_err(|error| {
            TorError::Onion(format!(
                "Consensus valid-after does not fall in a time period: {error}"
            ))
        })?;
        let period_start = time_period
            .range()
            .map_err(|error| TorError::Onion(format!("Time period is unrepresentable: {error}")))?
            .start;

        let current = consensus.shared_rand_cur();
        let previous = consensus.shared_rand_prev();
        let srv_interval = match (current, previous) {
            (Some(current), Some(previous)) => match (current.timestamp(), previous.timestamp()) {
                (Some(current_at), Some(previous_at)) => current_at
                    .duration_since(previous_at)
                    .unwrap_or(voting_period * VOTING_PERIODS_IN_SRV_ROUND),
                _ => voting_period * VOTING_PERIODS_IN_SRV_ROUND,
            },
            _ => voting_period * VOTING_PERIODS_IN_SRV_ROUND,
        };

        let mut values: Vec<([u8; 32], Range<SystemTime>)> = Vec::new();
        if let Some(current) = current {
            let begin = current
                .timestamp()
                .unwrap_or_else(|| start_of_day_containing(valid_after));
            values.push(((*current.value()).into(), begin..begin + srv_interval));
        }
        if let Some(previous) = previous {
            let begin = previous
                .timestamp()
                .unwrap_or_else(|| start_of_day_containing(valid_after) - ONE_DAY);
            values.push(((*previous.value()).into(), begin..begin + srv_interval));
        }

        let shared_rand = values
            .iter()
            .find(|(_, lifespan)| lifespan.contains(&period_start))
            .map(|(value, _)| *value)
            .unwrap_or_else(|| disaster_shared_rand(time_period));

        Ok(Self {
            time_period,
            shared_rand,
        })
    }

    pub(crate) fn time_period(&self) -> TimePeriod {
        self.time_period
    }
}

fn start_of_day_containing(when: SystemTime) -> SystemTime {
    let since_epoch = when
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(since_epoch - since_epoch % ONE_DAY.as_secs())
}

/// The value clients and services fall back to when the consensus carries no
/// shared random value covering the period.
fn disaster_shared_rand(period: TimePeriod) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"shared-random-disaster");
    hasher.update(u64::from(period.length().as_minutes()).to_be_bytes());
    hasher.update(period.interval_num().to_be_bytes());
    hasher.finalize().into()
}

fn relay_hsdir_index(identity: &Ed25519Identity, params: &HsDirParams) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"node-idx");
    hasher.update(identity.as_bytes());
    hasher.update(params.shared_rand);
    hasher.update(params.time_period.interval_num().to_be_bytes());
    hasher.update(u64::from(params.time_period.length().as_minutes()).to_be_bytes());
    hasher.finalize().into()
}

fn service_hsdir_index(blind_id: &HsBlindId, replica: u8, params: &HsDirParams) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"store-at-idx");
    hasher.update(blind_id.as_ref());
    hasher.update(u64::from(replica).to_be_bytes());
    hasher.update(u64::from(params.time_period.length().as_minutes()).to_be_bytes());
    hasher.update(params.time_period.interval_num().to_be_bytes());
    hasher.finalize().into()
}

/// The HSDirs responsible for `blind_id`, in random order.
///
/// Every relay with the HSDir flag sits on a ring ordered by a hash of its
/// ed25519 identity and the period's shared random value; each replica of the
/// descriptor is stored at the `HSDIR_SPREAD_FETCH` relays after the
/// service's own position on that ring.
pub(crate) fn select_hsdirs(
    relays: &[Relay],
    blind_id: &HsBlindId,
    params: &HsDirParams,
) -> Vec<Relay> {
    // Which replica a relay came from does not matter to a client: it asks
    // them one after another until one serves the descriptor.
    let mut flattened: Vec<Relay> =
        select_hsdirs_with_spread(relays, blind_id, params, HSDIR_SPREAD_FETCH)
            .into_iter()
            .flatten()
            .collect();
    flattened.shuffle(&mut rand::rng());
    flattened
}

/// The HSDirs responsible for `blind_id`, one group per replica, taking
/// `spread` of them in each: a service stores to `hsdir_spread_store` of
/// them, one more than the `hsdir_spread_fetch` a client reads from, so that
/// a client still finds the descriptor when one of the relays it asks has
/// dropped it.
///
/// The groups are kept apart because a service is reachable as soon as one
/// relay in a replica holds the descriptor, and it has no reason to wait for
/// the rest.
pub(crate) fn select_hsdirs_with_spread(
    relays: &[Relay],
    blind_id: &HsBlindId,
    params: &HsDirParams,
    spread: usize,
) -> Vec<Vec<Relay>> {
    let mut ring: Vec<([u8; 32], &Relay)> = relays
        .iter()
        .filter(|relay| relay.flags.contains("HSDir"))
        .filter_map(|relay| {
            let identity = relay.ed25519_identity.as_deref()?;
            let bytes = hex::decode(identity).ok()?;
            let identity = Ed25519Identity::from_bytes(&bytes)?;
            Some((relay_hsdir_index(&identity, params), relay))
        })
        .collect();
    ring.sort_by_key(|(index, _)| *index);

    let mut chosen = HashSet::new();
    let mut replicas = Vec::new();
    for replica in 1..=HSDIR_N_REPLICAS {
        let index = service_hsdir_index(blind_id, replica, params);
        let position = ring
            .binary_search_by_key(&index, |(index, _)| *index)
            .unwrap_or_else(|position| position);
        let picked: Vec<([u8; 32], &Relay)> = ring[position..]
            .iter()
            .chain(&ring[..position])
            .filter(|(index, _)| !chosen.contains(index))
            .take(spread)
            .copied()
            .collect();
        let mut selected = Vec::new();
        for (index, relay) in picked {
            chosen.insert(index);
            selected.push(relay.clone());
        }
        if !selected.is_empty() {
            replicas.push(selected);
        }
    }
    replicas
}

/// A rendezvous point that has acknowledged our cookie and is waiting for
/// the service.
struct Rendezvous {
    tunnel: ClientTunnel,
    cookie: RendCookie,
    target: OwnedCircTarget,
    rendezvous2: oneshot::Receiver<Rendezvous2>,
}

/// Handles the rendezvous point's two replies: RENDEZVOUS_ESTABLISHED for
/// our cookie, then the RENDEZVOUS2 the service delivers through it.
struct RendezvousHandler {
    established: Option<oneshot::Sender<()>>,
    rendezvous2: Option<oneshot::Sender<Rendezvous2>>,
}

impl MsgHandler for RendezvousHandler {
    fn handle_msg(&mut self, msg: AnyRelayMsg) -> tor_proto::Result<MetaCellDisposition> {
        match msg {
            AnyRelayMsg::RendezvousEstablished(_) => match self.established.take() {
                Some(sender) => {
                    let _ = sender.send(());
                    Ok(MetaCellDisposition::Consumed)
                }
                None => Err(tor_proto::Error::CircProto(
                    "duplicate RENDEZVOUS_ESTABLISHED".to_string(),
                )),
            },
            AnyRelayMsg::Rendezvous2(message) => {
                if self.established.is_some() {
                    return Err(tor_proto::Error::CircProto(
                        "RENDEZVOUS2 before RENDEZVOUS_ESTABLISHED".to_string(),
                    ));
                }
                match self.rendezvous2.take() {
                    Some(sender) => {
                        let _ = sender.send(message);
                        Ok(MetaCellDisposition::ConversationFinished)
                    }
                    None => Err(tor_proto::Error::CircProto(
                        "duplicate RENDEZVOUS2".to_string(),
                    )),
                }
            }
            other => Err(tor_proto::Error::CircProto(format!(
                "unexpected {} on a rendezvous circuit",
                other.cmd()
            ))),
        }
    }
}

struct IntroduceHandler {
    ack: Option<oneshot::Sender<IntroduceAck>>,
}

impl MsgHandler for IntroduceHandler {
    fn handle_msg(&mut self, msg: AnyRelayMsg) -> tor_proto::Result<MetaCellDisposition> {
        match msg {
            AnyRelayMsg::IntroduceAck(message) => match self.ack.take() {
                Some(sender) => {
                    let _ = sender.send(message);
                    Ok(MetaCellDisposition::ConversationFinished)
                }
                None => Err(tor_proto::Error::CircProto(
                    "duplicate INTRODUCE_ACK".to_string(),
                )),
            },
            other => Err(tor_proto::Error::CircProto(format!(
                "unexpected {} on an introduction circuit",
                other.cmd()
            ))),
        }
    }
}

pub(crate) struct OnionConnector {
    circuit_manager: Arc<CircuitManager>,
    directory_manager: Arc<DirectoryManager>,
    relay_manager: Arc<RwLock<RelayManager>>,
    /// Rendezvous tunnels with live streams. A tunnel's reactor stops when
    /// its last handle is dropped, so these are held until the client closes.
    tunnels: RwLock<Vec<Arc<ClientTunnel>>>,
    on_log: Option<LogCallback>,
}

impl OnionConnector {
    pub(crate) fn new(
        circuit_manager: Arc<CircuitManager>,
        directory_manager: Arc<DirectoryManager>,
        relay_manager: Arc<RwLock<RelayManager>>,
        on_log: Option<LogCallback>,
    ) -> Self {
        Self {
            circuit_manager,
            directory_manager,
            relay_manager,
            tunnels: RwLock::new(Vec::new()),
            on_log,
        }
    }

    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.on_log {
            (callback.0)(message, log_type);
            return;
        }
        info!("{}", message);
    }

    /// Open a stream to `host:port`, where `host` is a v3 onion address.
    pub(crate) async fn connect(&self, host: &str, port: u16) -> Result<DataStream> {
        let hsid = HsId::from_str(host)
            .map_err(|error| TorError::Onion(format!("Invalid onion address {host}: {error}")))?;
        let id_key = HsIdKey::try_from(hsid)
            .map_err(|error| TorError::Onion(format!("Invalid onion address {host}: {error}")))?;

        let params = self.directory_manager.hsdir_params().await?;
        let (blind_key, subcredential) = id_key
            .compute_blinded_key(params.time_period())
            .map_err(|error| TorError::Onion(format!("Key blinding failed: {error}")))?;
        let blind_id: HsBlindId = blind_key.id();

        let relays = self.relay_manager.read().await.relays.clone();
        let hsdirs = select_hsdirs(&relays, &blind_id, &params);
        if hsdirs.is_empty() {
            return Err(TorError::Onion(
                "The directory has no HSDir relays to fetch the descriptor from".to_string(),
            ));
        }

        self.log(
            &format!("Fetching the onion service descriptor for {host}"),
            LogType::Info,
        );
        let descriptor = self
            .fetch_descriptor(&hsdirs, &blind_id, &subcredential)
            .await?;
        if descriptor.requires_intro_authentication() {
            return Err(TorError::Onion(
                "The onion service requires client authorization".to_string(),
            ));
        }
        let mut intro_points: Vec<&IntroPointDesc> = descriptor.intro_points().iter().collect();
        if intro_points.is_empty() {
            return Err(TorError::Onion(
                "The onion service descriptor lists no introduction points".to_string(),
            ));
        }
        intro_points.shuffle(&mut rand::rng());
        self.log(
            &format!(
                "Onion service descriptor loaded with {} introduction points",
                intro_points.len()
            ),
            LogType::Success,
        );

        let mut last_error = None;
        for (attempt, intro_point) in intro_points
            .iter()
            .cycle()
            .take(MAX_INTRO_ATTEMPTS)
            .enumerate()
        {
            match self
                .rendezvous_with(host, port, intro_point, subcredential)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    self.log(
                        &format!(
                            "Onion rendezvous attempt {} failed: {error}",
                            attempt + 1
                        ),
                        LogType::Error,
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            TorError::Onion("No introduction point could be used".to_string())
        }))
    }

    pub(crate) async fn close(&self) {
        self.tunnels.write().await.clear();
    }

    async fn fetch_descriptor(
        &self,
        hsdirs: &[Relay],
        blind_id: &HsBlindId,
        subcredential: &Subcredential,
    ) -> Result<HsDesc> {
        let path = format!("/tor/hs/3/{}", STANDARD_NO_PAD.encode(blind_id.as_ref()));
        let mut last_error = None;
        for hsdir in hsdirs.iter().take(MAX_HSDIR_ATTEMPTS) {
            debug!("Fetching onion descriptor from HSDir {}", hsdir.nickname);
            let attempt = async {
                let (tunnel, _) = self
                    .circuit_manager
                    .build_tunnel_to(&hsdir.as_circ_target()?)
                    .await?;
                let text = fetch_directory_document(&Arc::new(tunnel), &path).await?;
                let now = system_time_now();
                let descriptor =
                    HsDesc::parse_decrypt_validate(&text, blind_id, subcredential, None)
                        .map_err(|error| {
                            TorError::Onion(format!("Descriptor was rejected: {error}"))
                        })?;
                descriptor.if_valid_at(&now).map_err(|error| {
                    TorError::Onion(format!("Descriptor is not currently valid: {error}"))
                })
            };
            match with_timeout(DESCRIPTOR_TIMEOUT, "Onion descriptor fetch", attempt).await {
                Ok(descriptor) => return Ok(descriptor),
                Err(error) => {
                    self.log(
                        &format!(
                            "HSDir {} did not serve the descriptor: {error}",
                            hsdir.nickname
                        ),
                        LogType::Error,
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| TorError::Onion("No HSDir was reachable".to_string())))
    }

    /// One complete attempt: a fresh rendezvous point, an introduction
    /// through `intro_point`, and the stream on the resulting circuit.
    async fn rendezvous_with(
        &self,
        host: &str,
        port: u16,
        intro_point: &IntroPointDesc,
        subcredential: Subcredential,
    ) -> Result<DataStream> {
        self.log("Establishing an onion rendezvous point", LogType::Info);
        let rendezvous = with_timeout(
            RENDEZVOUS_TIMEOUT,
            "Onion rendezvous setup",
            self.establish_rendezvous(),
        )
        .await?;

        self.log("Introducing to the onion service", LogType::Info);
        let handshake = with_timeout(
            INTRODUCE_TIMEOUT,
            "Onion introduction",
            self.introduce(intro_point, &rendezvous, subcredential),
        )
        .await?;

        self.log("Waiting for the onion service at the rendezvous point", LogType::Info);
        let Rendezvous {
            tunnel,
            rendezvous2,
            ..
        } = rendezvous;
        let rendezvous2 = with_timeout(RENDEZVOUS_COMPLETION_TIMEOUT, "Onion rendezvous", async {
            rendezvous2.await.map_err(|_| {
                TorError::Onion("Rendezvous circuit closed before RENDEZVOUS2".to_string())
            })
        })
        .await?;

        let keygen = handshake
            .client_receive_rend(rendezvous2.handshake_info())
            .map_err(|error| TorError::Onion(format!("hs-ntor handshake failed: {error}")))?;
        tunnel
            .as_single_circ()
            .map_err(|error| TorError::Internal(format!("Rendezvous circuit unusable: {error}")))?
            .extend_virtual(
                RelayProtocol::HsV3,
                HandshakeRole::Initiator,
                keygen,
                &make_circ_params()?,
                &Protocols::default(),
            )
            .await
            .map_err(|error| {
                TorError::Onion(format!("Failed to add the onion service hop: {error}"))
            })?;
        self.log("Onion service circuit established", LogType::Success);

        let tunnel = Arc::new(tunnel);
        let stream = tunnel
            .begin_stream(host, port, None)
            .await
            .map_err(|error| {
                TorError::Onion(format!("Failed to begin stream to {host}:{port}: {error}"))
            })?;
        self.tunnels.write().await.push(tunnel);
        Ok(stream)
    }

    async fn establish_rendezvous(&self) -> Result<Rendezvous> {
        let rendezvous_relay = self
            .relay_manager
            .read()
            .await
            .select_relay(&selection::middle_relays())?;
        let target = rendezvous_relay.as_circ_target()?;
        info!("Using {} as the rendezvous point", rendezvous_relay.nickname);
        let (tunnel, _) = self.circuit_manager.build_tunnel_to(&target).await?;

        let cookie: RendCookie = rand::random();
        let (established_sender, established) = oneshot::channel();
        let (rendezvous2_sender, rendezvous2) = oneshot::channel();
        tunnel
            .start_conversation(
                Some(EstablishRendezvous::new(cookie).into()),
                RendezvousHandler {
                    established: Some(established_sender),
                    rendezvous2: Some(rendezvous2_sender),
                },
                TargetHop::LastHop,
            )
            .await
            .map_err(|error| {
                TorError::Onion(format!("Failed to send ESTABLISH_RENDEZVOUS: {error}"))
            })?;
        established.await.map_err(|_| {
            TorError::Onion("Rendezvous point closed the circuit before acknowledging".to_string())
        })?;
        debug!("Rendezvous point acknowledged the cookie");

        Ok(Rendezvous {
            tunnel,
            cookie,
            target,
            rendezvous2,
        })
    }

    async fn introduce(
        &self,
        intro_point: &IntroPointDesc,
        rendezvous: &Rendezvous,
        subcredential: Subcredential,
    ) -> Result<hs_ntor::HsNtorClientState> {
        let target = intro_point_target(intro_point)?;
        let (tunnel, _) = self.circuit_manager.build_tunnel_to(&target).await?;

        let auth_key = intro_point.ipt_sid_key().as_bytes().to_vec();
        let header = {
            let mut encoded = Vec::new();
            Body::encode_onto(
                Introduce1::new(AuthKeyType::ED25519_SHA3_256, auth_key.clone(), Vec::new()),
                &mut encoded,
            )
            .map_err(|error| {
                    TorError::Internal(format!("Failed to encode INTRODUCE1 header: {error}"))
                })?;
            encoded
        };
        let payload = {
            let link_specifiers = rendezvous.target.linkspecs().map_err(|error| {
                TorError::Internal(format!("Failed to encode rendezvous link specifiers: {error}"))
            })?;
            let payload = IntroduceHandshakePayload::new(
                rendezvous.cookie,
                OnionKey::NtorOnionKey(*rendezvous.target.ntor_onion_key()),
                link_specifiers,
                None,
            );
            let mut encoded = Vec::new();
            payload.write_onto(&mut encoded).map_err(|error| {
                TorError::Internal(format!("Failed to encode INTRODUCE1 payload: {error}"))
            })?;
            encoded
        };

        let service_info = hs_ntor::HsNtorServiceInfo::new(
            intro_point.svc_ntor_key().clone(),
            intro_point.ipt_sid_key().clone(),
            subcredential,
        );
        let handshake = hs_ntor::HsNtorClientState::new(&mut rand::rng(), service_info);
        let encrypted = handshake
            .client_send_intro(&header, &payload)
            .map_err(|error| TorError::Onion(format!("hs-ntor handshake failed: {error}")))?;

        let (ack_sender, ack) = oneshot::channel();
        tunnel
            .start_conversation(
                Some(Introduce1::new(AuthKeyType::ED25519_SHA3_256, auth_key, encrypted).into()),
                IntroduceHandler {
                    ack: Some(ack_sender),
                },
                TargetHop::LastHop,
            )
            .await
            .map_err(|error| TorError::Onion(format!("Failed to send INTRODUCE1: {error}")))?;
        let ack = ack.await.map_err(|_| {
            TorError::Onion("Introduction point closed the circuit before answering".to_string())
        })?;
        ack.success().map_err(|status| {
            TorError::Onion(format!("Introduction point refused the introduction: {status:?}"))
        })?;
        debug!("Introduction acknowledged");
        Ok(handshake)
    }
}

/// Build a circuit target for an introduction point from the descriptor's
/// link specifiers, which are sent to the middle relay verbatim.
fn intro_point_target(
    intro_point: &IntroPointDesc,
) -> Result<VerbatimLinkSpecCircTarget<OwnedCircTarget>> {
    verbatim_target(
        intro_point.link_specifiers(),
        intro_point.ipt_ntor_key(),
        "Introduction point",
    )
}

/// Build a circuit target from link specifiers that came from a peer, which
/// the middle relay is asked to forward verbatim. A client does this for a
/// descriptor's introduction points; a service does it for the rendezvous
/// point an INTRODUCE2 names.
pub(crate) fn verbatim_target(
    link_specifiers: &[tor_linkspec::EncodedLinkSpec],
    ntor_onion_key: &tor_llcrypto::pk::curve25519::PublicKey,
    what: &str,
) -> Result<VerbatimLinkSpecCircTarget<OwnedCircTarget>> {
    let chan_target =
        OwnedChanTargetBuilder::from_encoded_linkspecs(Strictness::Standard, link_specifiers)
            .map_err(|error| {
                TorError::Onion(format!("{what} is not a valid target: {error}"))
            })?;
    let mut builder = OwnedCircTarget::builder();
    *builder.chan_target() = chan_target;
    builder
        .ntor_onion_key(*ntor_onion_key)
        .protocols(Protocols::default());
    let target = builder
        .build()
        .map_err(|error| TorError::Onion(format!("{what} is not a valid target: {error}")))?;
    Ok(VerbatimLinkSpecCircTarget::new(
        target,
        link_specifiers.to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> HsDirParams {
        let time_period = TimePeriod::new(
            Duration::from_secs(24 * 3600),
            SystemTime::UNIX_EPOCH + Duration::from_secs(43 * 24 * 3600 + 3600),
            Duration::from_secs(12 * 3600),
        )
        .unwrap();
        assert_eq!(time_period.interval_num(), 42);
        HsDirParams {
            time_period,
            shared_rand: [0x43; 32],
        }
    }

    /// The index vectors `tor-netdir` checks its ring against.
    #[test]
    fn hsdir_indexes_match_arti() {
        let params = params();
        let blind_id = HsBlindId::from([0x42; 32]);
        assert_eq!(
            hex::encode(service_hsdir_index(&blind_id, 1, &params)),
            "37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a"
        );
        let identity = Ed25519Identity::from_bytes(&[0x42; 32]).unwrap();
        assert_eq!(
            hex::encode(relay_hsdir_index(&identity, &params)),
            "db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5"
        );
    }

    #[test]
    fn selects_spread_per_replica_without_repeats() {
        let params = params();
        let relays: Vec<Relay> = (0u8..40)
            .map(|n| {
                let mut relay = Relay::new(
                    hex::encode([n; 20]),
                    format!("hsdir{n}"),
                    "127.0.0.1".to_string(),
                    9001,
                    ["HSDir".to_string()].into_iter().collect(),
                    hex::encode([n; 32]),
                );
                relay.ed25519_identity = Some(hex::encode([n; 32]));
                relay
            })
            .collect();
        let selected = select_hsdirs(&relays, &HsBlindId::from([0x42; 32]), &params);
        assert_eq!(
            selected.len(),
            usize::from(HSDIR_N_REPLICAS) * HSDIR_SPREAD_FETCH
        );
        let unique: HashSet<&str> = selected
            .iter()
            .map(|relay| relay.fingerprint.as_str())
            .collect();
        assert_eq!(unique.len(), selected.len());
    }

    #[test]
    fn spread_selection_keeps_the_replicas_apart() {
        let params = params();
        let relays: Vec<Relay> = (0u8..40)
            .map(|n| {
                let mut relay = Relay::new(
                    hex::encode([n; 20]),
                    format!("hsdir{n}"),
                    "127.0.0.1".to_string(),
                    9001,
                    ["HSDir".to_string()].into_iter().collect(),
                    hex::encode([n; 32]),
                );
                relay.ed25519_identity = Some(hex::encode([n; 32]));
                relay
            })
            .collect();
        let replicas = select_hsdirs_with_spread(&relays, &HsBlindId::from([0x42; 32]), &params, 4);
        assert_eq!(replicas.len(), usize::from(HSDIR_N_REPLICAS));
        for replica in &replicas {
            assert_eq!(replica.len(), 4);
        }
        // A relay in two replicas would make one of them look covered when
        // only the other one is.
        let unique: HashSet<&str> = replicas
            .iter()
            .flatten()
            .map(|relay| relay.fingerprint.as_str())
            .collect();
        assert_eq!(unique.len(), usize::from(HSDIR_N_REPLICAS) * 4);
    }

    #[test]
    fn relays_without_the_flag_are_not_on_the_ring() {
        let params = params();
        let mut relay = Relay::new(
            hex::encode([1; 20]),
            "middle".to_string(),
            "127.0.0.1".to_string(),
            9001,
            ["Fast".to_string()].into_iter().collect(),
            hex::encode([1; 32]),
        );
        relay.ed25519_identity = Some(hex::encode([1; 32]));
        assert!(select_hsdirs(&[relay], &HsBlindId::from([0x42; 32]), &params).is_empty());
    }

    #[test]
    fn start_of_day_floors_to_midnight_utc() {
        let noon = SystemTime::UNIX_EPOCH + Duration::from_secs(3 * 86400 + 12 * 3600);
        assert_eq!(
            start_of_day_containing(noon),
            SystemTime::UNIX_EPOCH + Duration::from_secs(3 * 86400)
        );
    }
}
