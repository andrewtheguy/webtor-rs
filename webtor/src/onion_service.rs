//! Onion service (v3) host: publishing a service *from* the browser.
//!
//! This is the mirror image of [`crate::onion`]. Instead of looking a
//! descriptor up and introducing itself to somebody else's service, the page
//! runs one:
//!
//! 1. generate an identity keypair, whose public half *is* the `.onion`
//!    address, and blind it for the current time period and its neighbours;
//! 2. build a circuit to each of a few middle relays and send `ESTABLISH_INTRO`
//!    there, so they become introduction points for this service;
//! 3. sign a descriptor naming those introduction points and POST it to the
//!    HSDirs the hash ring makes responsible for the blinded identity;
//! 4. for every `INTRODUCE2` an introduction point forwards, finish the
//!    hs-ntor handshake as the responder, build a circuit to the rendezvous
//!    point the client named, add the virtual hop and answer with
//!    `RENDEZVOUS1`;
//! 5. accept the `BEGIN` messages that arrive on that virtual hop and hand
//!    each resulting stream to the caller.
//!
//! Everything lives in memory: the identity key is generated per call and
//! never written anywhere, so every launch is a new address and closing the
//! page ends the service.

use crate::circuit::{make_circ_params, CircuitManager};
use crate::config::{LogCallback, LogType};
use crate::dir_http::post_directory_document;
use crate::directory::DirectoryManager;
use crate::error::{Result, TorError};
use crate::onion::{select_hsdirs_with_spread, verbatim_target, HsDirParams};
use crate::relay::{selection, Relay, RelayManager};
use crate::retry::with_timeout;
use crate::time::system_time_now;
use async_lock::{Mutex, RwLock};
use futures::channel::{mpsc, oneshot};
use futures::future::{AbortHandle, Abortable};
use futures::{SinkExt, StreamExt};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use safelog::DisplayRedacted;
use std::time::{Duration, SystemTime};
use tor_cell::chancell::msg::HandshakeType;
use tor_cell::relaycell::hs::est_intro::EstablishIntroDetails;
use tor_cell::relaycell::hs::intro_payload::{IntroduceHandshakePayload, OnionKey};
use tor_cell::relaycell::hs::{Introduce2, Rendezvous1};
use tor_cell::relaycell::msg::{AnyRelayMsg, Unrecognized};
use tor_cell::relaycell::{RelayCmd, RelayMsg};
use tor_hscrypto::pk::{
    HsBlindId, HsId, HsIdKey, HsIdKeypair, HsIntroPtSessionIdKey, HsIntroPtSessionIdKeypair,
    HsSvcNtorKeypair,
};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_linkspec::CircTarget;
use tor_llcrypto::pk::ed25519;
use tor_netdoc::doc::hsdesc::{create_desc_sign_key_cert, HsDescBuilder, IntroPointDesc};
use tor_netdoc::NetdocBuilder;
use tor_proto::client::circuit::handshake::{hs_ntor, HandshakeRole, RelayProtocol};
use tor_proto::client::stream::DataStream;
use tor_proto::stream::{
    IncomingStreamRequestContext, IncomingStreamRequestDisposition, IncomingStreamRequestFilter,
};
use tor_proto::{ClientTunnel, MetaCellDisposition, MsgHandler, TargetHop};
use tor_protover::Protocols;
use tracing::{debug, info, warn};

/// How many introduction points a service establishes. Three is what C tor
/// and Arti both use.
const DEFAULT_INTRO_POINTS: usize = 3;
/// `hsdir_spread_store`: a service uploads to one more HSDir per replica than
/// a client reads from, so a client still finds the descriptor when one of
/// the relays it asks has forgotten it.
const HSDIR_SPREAD_STORE: usize = 4;
/// How long a published descriptor claims to be good for.
const DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(3 * 60 * 60);
/// Lifetime of the certificates inside the descriptor. C tor uses 54 hours:
/// a descriptor can live 48, plus room for a consensus that turns over late.
const CERT_LIFETIME: Duration = Duration::from_secs(54 * 60 * 60);
/// The CREATE handshake a client may use on the rendezvous circuit.
const CREATE2_FORMATS: &[HandshakeType] = &[HandshakeType::NTOR];

/// How long after publishing the descriptor is published again, drawn from
/// this window. The same 60-to-120-minute range Arti's publisher uses, and
/// randomised for the same reason: services should not all upload at once.
const REPUBLISH_INTERVAL: (u64, u64) = (60 * 60, 120 * 60);
/// How long after a time period turns over the descriptor is published for
/// the rings that turnover created, when that comes first. Not zero, so that
/// the consensus naming the new period has had time to be voted on, and so
/// that services waiting on the same boundary do not all upload together.
const TRANSITION_DELAY: (u64, u64) = (5 * 60, 15 * 60);
/// The shortest wait between publications, whatever the rings say. Without it
/// a consensus stuck before the period boundary — one that cannot be
/// refreshed — would put this in a loop.
const MIN_REPUBLISH_INTERVAL: Duration = Duration::from_secs(15 * 60);

const ESTABLISH_INTRO_TIMEOUT: Duration = Duration::from_secs(90);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(90);
/// Streams a single client circuit may have open at once.
const MAX_CONCURRENT_STREAMS: usize = 16;
/// Depth of the queues between the reactors and the service task.
const CHANNEL_DEPTH: usize = 8;

/// What [`OnionService::launch`] was asked for.
#[derive(Clone, Copy, Debug)]
pub struct OnionServiceOptions {
    /// How many introduction points to establish.
    pub intro_points: usize,
}

impl Default for OnionServiceOptions {
    fn default() -> Self {
        Self {
            intro_points: DEFAULT_INTRO_POINTS,
        }
    }
}

/// The per-introduction-point keys. A service uses a different pair with each
/// introduction point so that one of them cannot recognise its traffic at
/// another.
struct IntroPointKeys {
    /// `KS_hs_ipt_sid`: identifies this service to this introduction point,
    /// and signs the ESTABLISH_INTRO.
    session_id: HsIntroPtSessionIdKeypair,
    /// The public half of `session_id`, as the hs-ntor handshake wants it.
    session_id_key: HsIntroPtSessionIdKey,
    /// `KS_hss_ntor`: the key a client encrypts its INTRODUCE1 to.
    ntor: HsSvcNtorKeypair,
}

/// One signed descriptor, and where it belongs.
///
/// A service publishes the same introduction points under a different blinded
/// identity in each time period it covers, so each period has a descriptor and
/// a set of HSDirs of its own.
struct Publication {
    period: TimePeriod,
    blind_id: HsBlindId,
    descriptor: String,
    /// The HSDirs to store it at, grouped by replica.
    replicas: Vec<Vec<Relay>>,
}

/// An introduction point that has acknowledged our ESTABLISH_INTRO.
struct EstablishedIntroPoint {
    /// Held so the circuit's reactor keeps running; INTRODUCE2 arrives here.
    tunnel: Arc<ClientTunnel>,
    /// What the descriptor says about this introduction point.
    descriptor: IntroPointDesc,
}

/// A published onion service.
///
/// Dropping it, or calling [`OnionService::close`], stops the republishing
/// and tears down the introduction points; the descriptor then expires on its
/// own.
///
/// The descriptor is published for the current time period and the ones either
/// side of it, and republished on a timer for as long as the service is up, so
/// the address survives both the descriptor expiring and the rings rotating.
pub struct OnionService {
    address: String,
    incoming: Mutex<mpsc::Receiver<DataStream>>,
    /// A sender kept only so that [`OnionService::close`] can close the
    /// channel from this side. Closing it through the receiver would mean
    /// taking `incoming`'s lock, which an `accept` that is waiting for a
    /// client holds for as long as it waits.
    streams: mpsc::Sender<DataStream>,
    state: Arc<ServiceState>,
}

/// The parts of a running service that its background tasks share.
struct ServiceState {
    circuit_manager: Arc<CircuitManager>,
    /// Held for republishing: every time period needs the identity blinded
    /// again, so this key lives as long as the service does rather than being
    /// dropped once the first descriptor is signed.
    identity: HsIdKeypair,
    directory_manager: Arc<DirectoryManager>,
    relay_manager: Arc<RwLock<RelayManager>>,
    /// What every descriptor advertises. Established once at launch.
    intro_points: RwLock<Vec<IntroPointDesc>>,
    /// One per time period the descriptor has been published for, newest
    /// periods last. A client encrypts its INTRODUCE2 to the subcredential of
    /// the period it found the descriptor under, so every one still in reach
    /// of a live consensus has to be tried.
    subcredentials: RwLock<Vec<(TimePeriod, Subcredential)>>,
    on_log: Option<LogCallback>,
    /// Introduction circuits and live client circuits. A tunnel's reactor
    /// stops when its last handle is dropped, so they are held here.
    tunnels: RwLock<Vec<Arc<ClientTunnel>>>,
    /// Aborts the background tasks when the service is closed or dropped.
    ///
    /// A `std` lock rather than an async one because [`Drop`] has to take it,
    /// and nothing holds it across an await.
    aborts: StdMutex<Vec<AbortHandle>>,
    /// Aborts the descriptor uploads of the most recent publication, which
    /// outlive the call that started them. Republishing replaces the list:
    /// keeping every round's handles for the life of the service would grow
    /// without bound, and an upload from a previous round is long since over.
    upload_aborts: StdMutex<Vec<AbortHandle>>,
}

/// Take one of the abort lists, ignoring a poisoned lock: the handles are
/// worth aborting whatever panicked while the list was held.
fn aborts_of(lock: &StdMutex<Vec<AbortHandle>>) -> std::sync::MutexGuard<'_, Vec<AbortHandle>> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Abort everything in one of the lists and empty it.
fn abort_all(lock: &StdMutex<Vec<AbortHandle>>) {
    for abort in aborts_of(lock).drain(..) {
        abort.abort();
    }
}

impl ServiceState {
    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.on_log {
            (callback.0)(message, log_type);
            return;
        }
        info!("{}", message);
    }

    /// Sign a descriptor for every time period the directory currently names,
    /// and start accepting introductions under each.
    ///
    /// The descriptor goes to the ring of the period this consensus is in and
    /// to the rings either side of it. A peer whose own consensus has not
    /// turned over yet — or has turned over already — computes one of those
    /// neighbouring rings, and publishing to the current one alone would leave
    /// it looking at HSDirs that hold nothing.
    ///
    /// The current period comes first: it is the one that decides whether the
    /// address works for a peer reading the same consensus as this service.
    async fn prepare_publications(&self) -> Result<Vec<Publication>> {
        let rings = self.directory_manager.hsdir_params().await?;
        let intro_points = self.intro_points.read().await.clone();
        let relays = self.relay_manager.read().await.relays.clone();
        let now = system_time_now();
        let mut rng = rand::rng();

        let mut publications = Vec::with_capacity(1 + rings.secondary.len());
        let mut fresh = Vec::with_capacity(publications.capacity());
        for params in std::iter::once(&rings.current).chain(rings.secondary.iter()) {
            let period = params.time_period();
            let (blind_key, blind_keypair, subcredential) = self
                .identity
                .compute_blinded_key(period)
                .map_err(|error| TorError::Onion(format!("Key blinding failed: {error}")))?;
            let descriptor = build_descriptor(
                &blind_key,
                &blind_keypair,
                &subcredential,
                &intro_points,
                params,
                now,
                &mut rng,
            )?;
            let blind_id: HsBlindId = blind_key.id();
            let replicas =
                select_hsdirs_with_spread(&relays, &blind_id, params, HSDIR_SPREAD_STORE);
            if replicas.is_empty() {
                return Err(TorError::Onion(
                    "The directory has no HSDir relays to publish the descriptor to".to_string(),
                ));
            }
            publications.push(Publication {
                period,
                blind_id,
                descriptor,
                replicas,
            });
            fresh.push((period, subcredential));
        }

        // Accepted before the descriptors naming them are stored, never after:
        // a client that finds one must not be turned away because this side is
        // not yet willing to decrypt what it sends.
        //
        // Periods drop out only once they are two intervals behind, which no
        // live consensus can still place a client in.
        let oldest = rings
            .current
            .time_period()
            .prev()
            .unwrap_or_else(|| rings.current.time_period())
            .interval_num();
        let mut held = self.subcredentials.write().await;
        for (period, subcredential) in fresh {
            if !held.iter().any(|(known, _)| *known == period) {
                held.push((period, subcredential));
            }
        }
        held.retain(|(period, _)| period.interval_num() >= oldest);

        Ok(publications)
    }
}

/// Publish the descriptor again, for as long as the service is up.
///
/// A descriptor expires after `DESCRIPTOR_LIFETIME`, and the rings it sits on
/// rotate with the onion service time period, so a service that uploads once
/// stops being reachable a few hours later while still looking healthy from
/// the inside. C tor and Arti both republish on a timer for this reason.
async fn republish_forever(state: Arc<ServiceState>) {
    loop {
        let delay = republish_delay(&state).await;
        crate::retry::sleep(delay).await;
        if let Err(error) = republish(&state).await {
            state.log(
                &format!("Could not republish the descriptor: {error}"),
                LogType::Error,
            );
        }
    }
}

/// How long to wait before publishing again.
///
/// The interval alone is only enough while a time period outlasts it. Periods
/// can be as short as half an hour, and a publication covers the current one
/// and its neighbours, so a service that always slept the full interval could
/// wake two periods on with clients already asking rings it never uploaded
/// to. Waking shortly after the boundary instead keeps every ring a client
/// might compute covered, whatever `hsdir_interval` the consensus sets.
async fn republish_delay(state: &ServiceState) -> Duration {
    let (interval, transition) = {
        use rand::RngExt as _;
        let mut rng = rand::rng();
        (
            Duration::from_secs(rng.random_range(REPUBLISH_INTERVAL.0..=REPUBLISH_INTERVAL.1)),
            Duration::from_secs(rng.random_range(TRANSITION_DELAY.0..=TRANSITION_DELAY.1)),
        )
    };
    let Some(period_end) = state
        .directory_manager
        .hsdir_params()
        .await
        .ok()
        .and_then(|rings| rings.current.time_period().range().ok())
        .map(|range| range.end)
    else {
        return interval;
    };
    let until_transition = period_end
        .duration_since(system_time_now())
        .unwrap_or_default();
    capped_republish_delay(interval, transition, until_transition)
}

/// The delay itself, given how long the current period has left: whichever of
/// the interval and the boundary comes first, and never less than
/// [`MIN_REPUBLISH_INTERVAL`].
fn capped_republish_delay(
    interval: Duration,
    transition: Duration,
    until_transition: Duration,
) -> Duration {
    interval
        .min(until_transition + transition)
        .max(MIN_REPUBLISH_INTERVAL)
}

/// One republication: a current directory, then a descriptor on every ring it
/// names.
async fn republish(state: &Arc<ServiceState>) -> Result<()> {
    // Whatever is left of the previous round's uploads has either finished or
    // run out its timeout many times over by now.
    abort_all(&state.upload_aborts);

    // The rings come from the consensus, so republishing against the one this
    // service started with would put the descriptor straight back onto the
    // ring the network is leaving. A refresh that fails is not fatal — the
    // directory in hand is still signed and still timely, and republishing
    // onto its rings beats letting the descriptor expire.
    match state.circuit_manager.channel().await {
        Ok(channel) => {
            if let Err(error) = state
                .directory_manager
                .fetch_and_process_consensus(channel)
                .await
            {
                state.log(
                    &format!(
                        "Could not refresh the Tor directory before republishing, so the \
                         descriptor goes back on the rings already in hand: {error}"
                    ),
                    LogType::Error,
                );
            }
        }
        Err(error) => {
            state.log(
                &format!("No Tor channel to refresh the directory on: {error}"),
                LogType::Error,
            );
        }
    }

    let publications = state.prepare_publications().await?;
    let outcomes = futures::future::join_all(
        publications
            .iter()
            .map(|publication| publish_descriptor(state, publication)),
    )
    .await;

    // Unlike the first publication, none of these decides whether the service
    // exists: it is already running, and a period that fails now is retried at
    // the next interval.
    let mut stored = 0_usize;
    for (publication, outcome) in publications.iter().zip(outcomes) {
        match outcome {
            Ok(()) => stored += 1,
            Err(error) => state.log(
                &format!(
                    "The descriptor for time period {} was not republished: {error}",
                    publication.period.interval_num()
                ),
                LogType::Error,
            ),
        }
    }
    if stored == 0 {
        return Err(TorError::Onion(
            "No time period accepted the republished descriptor".to_string(),
        ));
    }
    Ok(())
}

impl OnionService {
    /// Publish a new service and start answering introductions.
    ///
    /// Resolves once at least one HSDir has accepted the descriptor, which is
    /// the point at which a client can reach the address.
    pub(crate) async fn launch(
        circuit_manager: Arc<CircuitManager>,
        directory_manager: Arc<DirectoryManager>,
        relay_manager: Arc<RwLock<RelayManager>>,
        options: OnionServiceOptions,
        on_log: Option<LogCallback>,
    ) -> Result<Self> {
        let mut rng = rand::rng();

        // The identity key never leaves this function's memory, so the
        // address is good for exactly as long as the page is open.
        let identity = HsIdKeypair::from(ed25519::ExpandedKeypair::from(
            &ed25519::Keypair::generate(&mut rng),
        ));
        let address = HsId::from(HsIdKey::from(&identity))
            .display_unredacted()
            .to_string();

        // The descriptor goes to the ring of the period this consensus is in
        // and to the rings either side of it. A peer whose own consensus has
        // not turned over yet — or has turned over already — computes one of
        // those neighbouring rings, and publishing to the current one alone
        // would leave it looking at HSDirs that hold nothing.
        let state = Arc::new(ServiceState {
            circuit_manager,
            identity,
            directory_manager,
            relay_manager: relay_manager.clone(),
            intro_points: RwLock::new(Vec::new()),
            subcredentials: RwLock::new(Vec::new()),
            on_log,
            tunnels: RwLock::new(Vec::new()),
            aborts: StdMutex::new(Vec::new()),
            upload_aborts: StdMutex::new(Vec::new()),
        });
        state.log(
            &format!("Publishing onion service {address}"),
            LogType::Info,
        );

        let (introduce_tx, introduce_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (streams, stream_rx) = mpsc::channel(CHANNEL_DEPTH);
        let stream_tx = streams.clone();

        let established = establish_intro_points(
            &state,
            &relay_manager,
            options.intro_points,
            introduce_tx,
        )
        .await?;
        let descriptors: Vec<IntroPointDesc> = established
            .iter()
            .map(|point| point.descriptor.clone())
            .collect();
        {
            let mut tunnels = state.tunnels.write().await;
            for point in established {
                tunnels.push(point.tunnel);
            }
        }

        *state.intro_points.write().await = descriptors;

        // The first publication is the one that decides whether the address
        // works at all, so unlike a republish it is allowed to fail the launch.
        let publications = state.prepare_publications().await?;
        let (current, neighbours) = publications
            .split_first()
            .expect("the current period is always published");
        let (current_outcome, neighbour_outcomes) = futures::join!(
            publish_descriptor(&state, current),
            futures::future::join_all(
                neighbours
                    .iter()
                    .map(|publication| publish_descriptor(&state, publication))
            )
        );
        current_outcome?;
        for (publication, outcome) in neighbours.iter().zip(neighbour_outcomes) {
            if let Err(error) = outcome {
                state.log(
                    &format!(
                        "The descriptor for time period {} was not published, so a client an \
                         interval out of step will not find this service: {error}",
                        publication.period.interval_num()
                    ),
                    LogType::Error,
                );
            }
        }

        // Keep it published. A descriptor expires, and the rings it sits on
        // rotate, so a service that uploads once quietly stops being reachable
        // while still looking healthy from the inside.
        let (republish_abort, republish_registration) = AbortHandle::new_pair();
        aborts_of(&state.aborts).push(republish_abort);
        let republish_state = state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = Abortable::new(republish_forever(republish_state), republish_registration).await;
        });

        // From here on the service answers introductions on its own.
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        aborts_of(&state.aborts).push(abort_handle);
        let loop_state = state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = Abortable::new(
                answer_introductions(loop_state, introduce_rx, stream_tx),
                abort_registration,
            )
            .await;
        });

        state.log(
            &format!("Onion service {address} is reachable"),
            LogType::Success,
        );
        Ok(Self {
            address,
            incoming: Mutex::new(stream_rx),
            streams,
            state,
        })
    }

    /// The `<base32>.onion` address clients connect to.
    pub fn onion_address(&self) -> &str {
        &self.address
    }

    /// Wait for the next stream a client has opened to this service.
    ///
    /// Resolves to `None` once the service is closed.
    pub async fn accept(&self) -> Option<DataStream> {
        let mut incoming = self.incoming.lock().await;
        incoming.next().await
    }

    /// Stop answering introductions and drop every circuit.
    pub async fn close(&self) {
        // First, so that an `accept` waiting for the next client wakes up and
        // gives up the lock it is holding on the receiver.
        self.shutdown();
        self.state.tunnels.write().await.clear();
    }

    /// Everything [`OnionService::close`] does that needs no await: stop the
    /// background tasks, and wake an `accept` that is waiting for a client.
    ///
    /// Exposed because the last thing holding a service is often a task of
    /// its own — a pending `accept`, an upload still in flight — so a caller
    /// letting go of its handle cannot rely on `Drop` running. Calling this
    /// is what lets those tasks finish, and the state goes with the last of
    /// them.
    pub fn shutdown(&self) {
        // First, so that an `accept` waiting for the next client wakes up.
        self.streams.clone().close_channel();
        abort_all(&self.state.aborts);
        abort_all(&self.state.upload_aborts);
    }
}

impl Drop for OnionService {
    /// The same teardown as [`OnionService::close`], minus the part that has
    /// to await.
    ///
    /// Dropping this handle does not by itself drop the state the background
    /// tasks share, because each of those tasks holds it too: aborting them
    /// is what lets the last reference go, and the introduction points and
    /// circuits go with it. Without this, a dropped service would keep
    /// answering introductions and republishing its descriptor for as long as
    /// the page was open.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Build circuits to `count` distinct relays and establish an introduction
/// point at each. Relays that fail are skipped; one working introduction
/// point is enough to publish.
async fn establish_intro_points(
    state: &Arc<ServiceState>,
    relay_manager: &Arc<RwLock<RelayManager>>,
    count: usize,
    introduce_tx: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
) -> Result<Vec<EstablishedIntroPoint>> {
    let mut established = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut last_error = None;

    for _ in 0..count {
        let relay = {
            let manager = relay_manager.read().await;
            let mut criteria = selection::middle_relays();
            for fingerprint in &used {
                criteria = criteria.without_fingerprint(fingerprint);
            }
            match manager.select_relay(&criteria) {
                Ok(relay) => relay,
                Err(error) => {
                    last_error = Some(error);
                    break;
                }
            }
        };
        used.insert(relay.fingerprint.clone());

        let attempt = with_timeout(
            ESTABLISH_INTRO_TIMEOUT,
            "Introduction point setup",
            establish_intro_point(state, &relay, introduce_tx.clone()),
        )
        .await;
        match attempt {
            Ok(point) => {
                state.log(
                    &format!("Introduction point established at {}", relay.nickname),
                    LogType::Success,
                );
                established.push(point);
            }
            Err(error) => {
                state.log(
                    &format!("Relay {} refused to be an introduction point: {error}", relay.nickname),
                    LogType::Error,
                );
                last_error = Some(error);
            }
        }
    }

    if established.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            TorError::Onion("No relay would act as an introduction point".to_string())
        }));
    }
    Ok(established)
}

/// One introduction point: a circuit to `relay`, an ESTABLISH_INTRO signed
/// with a fresh session key, and a handler that forwards every INTRODUCE2.
async fn establish_intro_point(
    state: &Arc<ServiceState>,
    relay: &Relay,
    introduce_tx: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
) -> Result<EstablishedIntroPoint> {
    let mut rng = rand::rng();
    let session_id = HsIntroPtSessionIdKeypair::from(ed25519::Keypair::generate(&mut rng));
    let session_id_key = HsIntroPtSessionIdKey::from(session_id.as_ref().verifying_key());
    let ntor = HsSvcNtorKeypair::generate(&mut rng);
    let keys = Arc::new(IntroPointKeys {
        session_id,
        session_id_key,
        ntor,
    });

    let target = relay.as_circ_target()?;
    let (tunnel, _) = state.circuit_manager.build_tunnel_to(&target).await?;
    let tunnel = Arc::new(tunnel);

    // The ESTABLISH_INTRO signature covers the circuit's binding key, which
    // is what stops it being replayed onto another circuit.
    let binding = tunnel
        .as_single_circ()
        .map_err(|error| TorError::Internal(format!("Introduction circuit unusable: {error}")))?
        .binding_key(TargetHop::LastHop)
        .await
        .map_err(|error| TorError::Onion(format!("Introduction circuit has no state: {error}")))?
        .ok_or_else(|| {
            TorError::Onion("Introduction circuit has no binding key".to_string())
        })?;
    let body = EstablishIntroDetails::new(ed25519::Ed25519Identity::from(
        keys.session_id.as_ref().verifying_key(),
    ))
    .sign_and_encode(keys.session_id.as_ref(), binding.hs_mac())
    .map_err(|error| TorError::Onion(format!("Failed to sign ESTABLISH_INTRO: {error}")))?;

    let (established_sender, established) = oneshot::channel();
    tunnel
        .start_conversation(
            Some(AnyRelayMsg::Unrecognized(Unrecognized::new(
                RelayCmd::ESTABLISH_INTRO,
                body,
            ))),
            IntroPointHandler {
                established: Some(established_sender),
                keys: keys.clone(),
                introduce: introduce_tx,
            },
            TargetHop::LastHop,
        )
        .await
        .map_err(|error| TorError::Onion(format!("Failed to send ESTABLISH_INTRO: {error}")))?;
    established.await.map_err(|_| {
        TorError::Onion("Introduction point closed the circuit before acknowledging".to_string())
    })?;

    let link_specifiers = target.linkspecs().map_err(|error| {
        TorError::Internal(format!("Failed to encode introduction point link specifiers: {error}"))
    })?;
    let descriptor = IntroPointDesc::builder()
        .link_specifiers(link_specifiers)
        .ipt_kp_ntor(*target.ntor_onion_key())
        .kp_hs_ipt_sid(keys.session_id_key.clone())
        .kp_hss_ntor(keys.ntor.public().clone())
        .build()
        .map_err(|error| {
            TorError::Internal(format!("Failed to describe the introduction point: {error}"))
        })?;

    Ok(EstablishedIntroPoint { tunnel, descriptor })
}

/// Encode and sign the descriptor that advertises `intro_points`.
#[allow(clippy::too_many_arguments)]
fn build_descriptor<R: rand::Rng + rand::CryptoRng>(
    blind_key: &tor_hscrypto::pk::HsBlindIdKey,
    blind_keypair: &tor_hscrypto::pk::HsBlindIdKeypair,
    subcredential: &Subcredential,
    intro_points: &[IntroPointDesc],
    params: &HsDirParams,
    now: SystemTime,
    rng: &mut R,
) -> Result<String> {
    let signing_key = ed25519::Keypair::generate(rng);
    let certificate = create_desc_sign_key_cert(
        &signing_key.verifying_key(),
        blind_keypair,
        now + CERT_LIFETIME,
    )
    .map_err(|error| {
        TorError::Onion(format!("Failed to certify the descriptor signing key: {error}"))
    })?;

    // Descriptors for the same blinded identity are ordered by this counter,
    // and an HSDir keeps the copy it already holds unless a new one raises it,
    // so it has to grow across every republication.
    //
    // Seconds since the *time period* began cannot do that for the period
    // ahead, which is published before it starts: every upload until then
    // would count zero and none of them could replace the first, leaving that
    // ring holding an expired descriptor by the time clients move onto it.
    // The shared random value the ring is built from is already in force
    // whenever a ring exists at all, so seconds since that rise from the
    // first publication onwards. Arti counts from the same instant, though it
    // encrypts the result to keep the upload time off the HSDir.
    let revision = now
        .duration_since(params.srv_start())
        .unwrap_or_default()
        .as_secs();

    HsDescBuilder::default()
        .blinded_id(blind_key)
        .hs_desc_sign(&signing_key)
        .hs_desc_sign_cert(certificate)
        .create2_formats(CREATE2_FORMATS)
        .auth_required(None)
        .is_single_onion_service(false)
        .intro_points(intro_points)
        .intro_auth_key_cert_expiry(now + CERT_LIFETIME)
        .intro_enc_key_cert_expiry(now + CERT_LIFETIME)
        .lifetime(((DESCRIPTOR_LIFETIME.as_secs() / 60) as u16).into())
        .revision_counter(RevisionCounter::from(revision))
        .subcredential(*subcredential)
        .auth_clients(None)
        .build_sign(rng)
        .map_err(|error| TorError::Onion(format!("Failed to sign the descriptor: {error}")))
}

/// Store the descriptor at every HSDir responsible for it, resolving as soon
/// as each replica holds a copy.
///
/// A client asks the relays of one replica after another until one serves the
/// descriptor, so a single relay per replica is what makes the address
/// reachable. The remaining uploads are still worth making — they are what a
/// client falls back on when the relay it asked has dropped its copy — but
/// nothing needs to wait for them, and one unreachable HSDir would otherwise
/// hold publishing up for the whole of `UPLOAD_TIMEOUT`.
async fn publish_descriptor(state: &Arc<ServiceState>, publication: &Publication) -> Result<()> {
    let Publication {
        period,
        blind_id,
        descriptor,
        replicas,
    } = publication;
    let total: usize = replicas.iter().map(Vec::len).sum();
    debug!(
        "Publishing a {} byte descriptor for {} to {} HSDirs across {} replicas",
        descriptor.len(),
        hex::encode(blind_id.as_ref()),
        total,
        replicas.len()
    );

    // Every upload on its own task, so that the ones still running when this
    // returns carry on. `close` aborts whatever is left.
    let (outcome_tx, mut outcomes) = mpsc::channel(total);
    let mut aborts = Vec::with_capacity(total);
    for (replica, hsdirs) in replicas.iter().enumerate() {
        for hsdir in hsdirs {
            let (abort_handle, abort_registration) = AbortHandle::new_pair();
            aborts.push(abort_handle);
            let state = state.clone();
            let hsdir = hsdir.clone();
            let descriptor = descriptor.to_string();
            let mut outcome_tx = outcome_tx.clone();
            wasm_bindgen_futures::spawn_local(async move {
                let upload = async {
                    let attempt = async {
                        let (tunnel, _) = state
                            .circuit_manager
                            .build_tunnel_to(&hsdir.as_circ_target()?)
                            .await?;
                        post_directory_document(&Arc::new(tunnel), "/tor/hs/3/publish", &descriptor)
                            .await
                    };
                    let outcome = with_timeout(UPLOAD_TIMEOUT, "Descriptor upload", attempt).await;
                    match &outcome {
                        Ok(()) => debug!("HSDir {} stored the descriptor", hsdir.nickname),
                        Err(error) => state.log(
                            &format!("HSDir {} rejected the descriptor: {error}", hsdir.nickname),
                            LogType::Error,
                        ),
                    }
                    // Fails once publishing has moved on without this upload,
                    // which is the point of running it out here.
                    let _ = outcome_tx.send((replica, outcome)).await;
                };
                let _ = Abortable::new(upload, abort_registration).await;
            });
        }
    }
    // Otherwise the receiver below would never see the end of the uploads.
    drop(outcome_tx);
    aborts_of(&state.upload_aborts).append(&mut aborts);

    let mut stored = vec![0_usize; replicas.len()];
    let mut accepted = 0_usize;
    let mut last_error = None;
    while stored.contains(&0) {
        let Some((replica, outcome)) = outcomes.next().await else {
            // Every upload has reported, so nothing more is coming.
            break;
        };
        match outcome {
            Ok(()) => {
                stored[replica] += 1;
                accepted += 1;
            }
            Err(error) => last_error = Some(error),
        }
    }

    if accepted == 0 {
        return Err(last_error
            .unwrap_or_else(|| TorError::Onion("No HSDir accepted the descriptor".to_string())));
    }
    let ready = stored.iter().filter(|count| **count > 0).count();
    state.log(
        &format!(
            "Descriptor for time period {} stored on {ready} of {} replicas ({accepted} of \
             {total} HSDirs so far)",
            period.interval_num(),
            replicas.len()
        ),
        LogType::Success,
    );
    Ok(())
}

/// Take each INTRODUCE2 as it arrives and serve it on its own task, so a slow
/// rendezvous never holds up the next client.
async fn answer_introductions(
    state: Arc<ServiceState>,
    mut introductions: mpsc::Receiver<(Arc<IntroPointKeys>, Introduce2)>,
    streams: mpsc::Sender<DataStream>,
) {
    while let Some((keys, message)) = introductions.next().await {
        let state = state.clone();
        let streams = streams.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(error) = serve_introduction(&state, &keys, message, streams).await {
                state.log(
                    &format!("Introduction from a client failed: {error}"),
                    LogType::Error,
                );
            }
        });
    }
}

/// Finish one client's handshake: answer at its rendezvous point and pass on
/// every stream it opens.
async fn serve_introduction(
    state: &Arc<ServiceState>,
    keys: &IntroPointKeys,
    message: Introduce2,
    mut streams: mpsc::Sender<DataStream>,
) -> Result<()> {
    let subcredentials: Vec<Subcredential> = state
        .subcredentials
        .read()
        .await
        .iter()
        .map(|(_, subcredential)| *subcredential)
        .collect();
    let (keygen, rendezvous1_body, payload) = hs_ntor::server_receive_intro(
        &mut rand::rng(),
        &keys.ntor,
        &keys.session_id_key,
        &subcredentials,
        message.encoded_header(),
        message.encrypted_body(),
    )
    .map_err(|error| TorError::Onion(format!("hs-ntor handshake failed: {error}")))?;

    let payload: IntroduceHandshakePayload = {
        let mut reader = tor_bytes::Reader::from_slice(&payload);
        // Not `should_be_exhausted`: the payload is padded to hide its size.
        reader.extract().map_err(|error| {
            TorError::Onion(format!("INTRODUCE2 payload could not be parsed: {error}"))
        })?
    };
    let OnionKey::NtorOnionKey(ntor_key) = payload.onion_key() else {
        return Err(TorError::Onion(
            "Client named a rendezvous point with an unsupported onion key".to_string(),
        ));
    };
    let rendezvous_point = verbatim_target(
        payload.link_specifiers(),
        ntor_key,
        "Client's rendezvous point",
    )?;

    state.log("Answering a client at its rendezvous point", LogType::Info);
    let (tunnel, _) = with_timeout(
        RENDEZVOUS_TIMEOUT,
        "Rendezvous circuit",
        state.circuit_manager.build_tunnel_to(&rendezvous_point),
    )
    .await?;
    let tunnel = Arc::new(tunnel);

    let rendezvous_hop = tunnel
        .last_hop()
        .map_err(|error| TorError::Internal(format!("Rendezvous circuit has no hop: {error}")))?;
    tunnel
        .as_single_circ()
        .map_err(|error| TorError::Internal(format!("Rendezvous circuit unusable: {error}")))?
        .extend_virtual(
            RelayProtocol::HsV3,
            HandshakeRole::Responder,
            keygen,
            &make_circ_params()?,
            &Protocols::default(),
        )
        .await
        .map_err(|error| TorError::Onion(format!("Failed to add the client hop: {error}")))?;
    let client_hop = tunnel.last_hop().map_err(|error| {
        TorError::Internal(format!("Rendezvous circuit has no virtual hop: {error}"))
    })?;

    // Ask for BEGIN before RENDEZVOUS1 goes out, so the first request cannot
    // arrive before anything is listening for it.
    let mut requests = tunnel
        .allow_stream_requests(
            &[RelayCmd::BEGIN],
            client_hop,
            AcceptBegin {
                max_streams: MAX_CONCURRENT_STREAMS,
            },
        )
        .await
        .map_err(|error| TorError::Onion(format!("Failed to accept client streams: {error}")))?
        .boxed_local();

    tunnel
        .send_raw_msg(
            Rendezvous1::new(*payload.cookie(), rendezvous1_body).into(),
            rendezvous_hop,
        )
        .await
        .map_err(|error| TorError::Onion(format!("Failed to send RENDEZVOUS1: {error}")))?;
    state.log("A client circuit is open", LogType::Success);
    state.tunnels.write().await.push(tunnel.clone());

    while let Some(request) = requests.next().await {
        let stream = match request
            .accept_data(tor_cell::relaycell::msg::Connected::new_empty())
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                warn!("Client stream could not be accepted: {}", error);
                continue;
            }
        };
        if streams.send(stream).await.is_err() {
            // Nobody is accepting any more; the service is closing.
            break;
        }
    }

    // This client is done, so stop holding its circuit open: a service that
    // kept every one of them would collect them for as long as it ran.
    {
        let mut tunnels = state.tunnels.write().await;
        if let Some(index) = tunnels.iter().position(|held| Arc::ptr_eq(held, &tunnel)) {
            tunnels.swap_remove(index);
        }
    }
    Ok(())
}

/// Accepts BEGIN until a client has too many streams open at once.
#[derive(Clone, Debug)]
struct AcceptBegin {
    max_streams: usize,
}

impl IncomingStreamRequestFilter for AcceptBegin {
    fn disposition(
        &mut self,
        _context: &IncomingStreamRequestContext<'_>,
        circuit: &tor_proto::circuit::CircHopSyncView<'_>,
    ) -> tor_proto::Result<IncomingStreamRequestDisposition> {
        if circuit.n_open_streams() >= self.max_streams {
            Ok(IncomingStreamRequestDisposition::CloseCircuit)
        } else {
            Ok(IncomingStreamRequestDisposition::Accept)
        }
    }
}

/// Handles what an introduction point sends back: one INTRO_ESTABLISHED, then
/// an INTRODUCE2 for every client that asks for us there.
struct IntroPointHandler {
    established: Option<oneshot::Sender<()>>,
    keys: Arc<IntroPointKeys>,
    introduce: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
}

impl MsgHandler for IntroPointHandler {
    fn handle_msg(&mut self, msg: AnyRelayMsg) -> tor_proto::Result<MetaCellDisposition> {
        match msg {
            AnyRelayMsg::IntroEstablished(_) => match self.established.take() {
                Some(sender) => {
                    let _ = sender.send(());
                    Ok(MetaCellDisposition::Consumed)
                }
                None => Err(tor_proto::Error::CircProto(
                    "duplicate INTRO_ESTABLISHED".to_string(),
                )),
            },
            AnyRelayMsg::Introduce2(message) => {
                if self.established.is_some() {
                    return Err(tor_proto::Error::CircProto(
                        "INTRODUCE2 before INTRO_ESTABLISHED".to_string(),
                    ));
                }
                match self.introduce.try_send((self.keys.clone(), message)) {
                    Ok(()) => Ok(MetaCellDisposition::Consumed),
                    // A full queue means the service is already busy; dropping
                    // the introduction leaves the client to retry, which is
                    // what it does anyway when a service is overloaded.
                    Err(error) if error.is_full() => {
                        warn!("Dropped an INTRODUCE2: the service is busy");
                        Ok(MetaCellDisposition::Consumed)
                    }
                    Err(_) => Ok(MetaCellDisposition::CloseCirc),
                }
            }
            other => Err(tor_proto::Error::CircProto(format!(
                "unexpected {} on an introduction circuit",
                other.cmd()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(90 * 60);
    const TRANSITION: Duration = Duration::from_secs(10 * 60);

    /// A day-long period outlasts the interval many times over, so nothing is
    /// gained by waking any earlier than usual.
    #[test]
    fn a_long_period_leaves_the_interval_alone() {
        let delay = capped_republish_delay(INTERVAL, TRANSITION, Duration::from_secs(20 * 3600));
        assert_eq!(delay, INTERVAL);
    }

    /// With `hsdir_interval` at its floor of half an hour, sleeping the whole
    /// interval would skip past periods clients are already asking about.
    #[test]
    fn a_short_period_is_woken_just_after_its_boundary() {
        let delay = capped_republish_delay(INTERVAL, TRANSITION, Duration::from_secs(12 * 60));
        assert_eq!(delay, Duration::from_secs(22 * 60));
        assert!(delay < INTERVAL);
    }

    /// A directory that cannot be refreshed leaves the boundary in the past.
    /// Publishing again is still worth doing — the attempt starts by trying
    /// the refresh again — but not in a tight loop.
    #[test]
    fn a_boundary_already_passed_still_waits() {
        let delay = capped_republish_delay(INTERVAL, TRANSITION, Duration::ZERO);
        assert_eq!(delay, MIN_REPUBLISH_INTERVAL);
    }
}
