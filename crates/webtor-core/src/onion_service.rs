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
//! The introduction points are maintained rather than established once: one
//! whose circuit ends, or whose relay leaves the consensus, is dropped, a
//! replacement is established elsewhere, and the descriptor is published
//! again naming the points that are actually answering.
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
use std::sync::atomic::{AtomicBool, Ordering};
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
/// How long the maintainer waits before trying again to reach the target
/// number of introduction points, and how far that wait grows while it keeps
/// failing. A service short of a point is still reachable through the ones it
/// has, and a network with no relay to spare will not have one a second
/// later, so retrying at the shortest interval forever would only add load.
const INTRO_RETRY_DELAY: (Duration, Duration) =
    (Duration::from_secs(30), Duration::from_secs(10 * 60));
/// The least time between two descriptor uploads. Arti's publisher holds the
/// same line at the same minute: without it a relay that takes an
/// ESTABLISH_INTRO and drops the circuit straight back would turn one flapping
/// point into a run of uploads to every HSDir.
const UPLOAD_RATE_LIMIT: Duration = Duration::from_secs(60);

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
    /// Never read: retiring the point drops it, and that is what stops the
    /// reactor and withdraws the introduction point.
    #[allow(dead_code)]
    tunnel: Arc<ClientTunnel>,
    /// The relay carrying it: what a replacement avoids picking again, and
    /// what a fresh consensus is checked against to see whether the relay is
    /// still there at all.
    relay: Relay,
    /// What the descriptor says about this introduction point.
    descriptor: IntroPointDesc,
    /// Set by the watcher when this point's circuit has ended.
    ///
    /// A flag of our own rather than the circuit's `is_closed`, because the
    /// watcher sets it before it wakes the maintainer: whatever the reactor
    /// has published about itself by the time the maintainer runs, the point
    /// that woke it is already marked.
    ended: Arc<AtomicBool>,
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
///
/// The introduction points named in it are watched for the same reason: one
/// that stops answering is retired, replaced, and published again, so the
/// address does not decay one point at a time behind a descriptor that still
/// looks healthy.
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
    /// What every descriptor advertises, and the circuits the introductions
    /// arrive on. Kept up to strength by [`reconcile_intro_points`].
    intro_points: RwLock<Vec<EstablishedIntroPoint>>,
    /// How many introduction points to keep established.
    target_intro_points: usize,
    /// Where INTRODUCE2 goes. Held so that a point established long after
    /// launch feeds the same queue as the ones launch established.
    introduce_tx: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
    /// Wakes the maintainer when an introduction point's circuit has ended.
    maintenance_tx: mpsc::Sender<()>,
    /// One per time period the descriptor has been published for, newest
    /// periods last. A client encrypts its INTRODUCE2 to the subcredential of
    /// the period it found the descriptor under, so every one still in reach
    /// of a live consensus has to be tried.
    subcredentials: RwLock<Vec<(TimePeriod, Subcredential)>>,
    on_log: Option<LogCallback>,
    /// Live client circuits. A tunnel's reactor stops when its last handle is
    /// dropped, so they are held here. The introduction circuits are not
    /// among them: those belong to `intro_points`, so that retiring a point
    /// is what drops its circuit.
    tunnels: RwLock<Vec<Arc<ClientTunnel>>>,
    /// Serialises the two things that change what the HSDirs hold — the
    /// republish timer and introduction point maintenance — so a replacement
    /// and a scheduled republication cannot upload descriptors out of order.
    publishing: Mutex<()>,
    /// Whether what the HSDirs hold has fallen behind what this service is
    /// answering on: an introduction point retired or replaced, or a
    /// publication that did not reach every time period the directory names.
    ///
    /// Shared rather than owned by the maintainer, because both background
    /// loops change what a descriptor should say — the republish timer
    /// reconciles too, on the fresh consensus it just downloaded — and only
    /// one of them has a retry timer to come back on.
    unpublished_change: AtomicBool,
    /// When the descriptor last went up, which is what [`UPLOAD_RATE_LIMIT`]
    /// is measured from.
    ///
    /// A `std` lock rather than an async one because nothing holds it across
    /// an await.
    last_publication: StdMutex<Option<SystemTime>>,
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
    /// Note that a descriptor has just gone up, for [`UPLOAD_RATE_LIMIT`].
    fn record_publication(&self) {
        *self
            .last_publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(system_time_now());
    }

    /// Whether the maintainer has nothing left to come back to.
    async fn settled(&self) -> bool {
        intro_points_settled(
            self.unpublished_change.load(Ordering::Relaxed),
            self.intro_points.read().await.len(),
            self.target_intro_points,
        )
    }

    /// How long a publication that is not on the republish timer has to wait,
    /// so that uploads stay at most one a minute.
    fn wait_before_publishing(&self) -> Duration {
        let last = *self
            .last_publication
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        wait_before_publishing(last, system_time_now())
    }

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
        let intro_points: Vec<IntroPointDesc> = self
            .intro_points
            .read()
            .await
            .iter()
            .map(|point| point.descriptor.clone())
            .collect();
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

/// One republication: a current directory, introduction points that are still
/// answering, then a descriptor on every ring the directory names.
async fn republish(state: &Arc<ServiceState>) -> Result<()> {
    let _publishing = state.publishing.lock().await;

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

    // The consensus that just arrived is also what says whether each
    // introduction point is still a relay, so this is the moment to notice one
    // that has left it — and the last moment before a descriptor goes out
    // naming it.
    reconcile_intro_points(state).await?;

    let published = publish_everywhere(state).await;
    // Retrying belongs to the maintainer: it is the loop with a timer short
    // enough to matter, where this one sleeps another interval. Its own wait
    // is on the nudges alone whenever nothing is owed, so a change made here
    // and not published has to wake it.
    if state.unpublished_change.load(Ordering::Relaxed) {
        let mut nudge = state.maintenance_tx.clone();
        let _ = nudge.try_send(());
    }
    published
}

/// Sign the descriptor for every time period the directory names and store it
/// on all of their rings.
///
/// Unlike the first publication at launch, no single period decides whether
/// the service exists: it is already running, and a period that fails here
/// leaves `unpublished_change` set for the maintainer to come back to.
/// Failing all of them is still worth saying.
async fn publish_everywhere(state: &Arc<ServiceState>) -> Result<()> {
    // Whatever is left of the previous round's uploads has either finished or
    // run out its timeout many times over by now.
    abort_all(&state.upload_aborts);

    let publications = state.prepare_publications().await?;
    state.record_publication();
    let outcomes = futures::future::join_all(
        publications
            .iter()
            .map(|publication| publish_descriptor(state, publication)),
    )
    .await;

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
    // Only a round that reached every period leaves nothing owed. A ring that
    // was missed still holds whatever it held before — which, after a point
    // has been retired, names one that no longer answers.
    state
        .unpublished_change
        .store(stored < publications.len(), Ordering::Relaxed);

    if stored == 0 {
        return Err(TorError::Onion(
            "No time period accepted the republished descriptor".to_string(),
        ));
    }
    Ok(())
}

/// Watch the introduction points and keep the target number of them
/// answering, for as long as the service is up.
///
/// A point whose circuit has ended wakes this through `nudges`; a shortfall
/// that cannot be made up on the spot, or an upload that did not go through,
/// is retried on a growing delay, since what stopped a relay from taking an
/// ESTABLISH_INTRO or an HSDir from storing a descriptor a moment ago is
/// usually still true.
async fn maintain_intro_points(state: Arc<ServiceState>, mut nudges: mpsc::Receiver<()>) {
    use futures::future::{select, Either};

    let (min_delay, max_delay) = INTRO_RETRY_DELAY;
    let mut delay = min_delay;
    loop {
        // A shortfall or a descriptor the HSDirs have not been given is
        // something to come back to on the retry timer. With neither, there
        // is nothing to do until a point ends — but a point can end while
        // either is being waited out, so the nudges are watched throughout.
        if state.settled().await {
            if nudges.next().await.is_none() {
                // The service has closed the channel; nothing left to maintain.
                return;
            }
        } else {
            let retry = Box::pin(crate::retry::sleep(delay));
            if let Either::Left((None, _)) = select(nudges.next(), retry).await {
                return;
            }
        }

        let outcome = {
            let _publishing = state.publishing.lock().await;
            match reconcile_intro_points(&state).await {
                // Whether this reconcile changed anything or a previous round
                // left the last change unpublished, the answer is the same
                // descriptor: whatever is answering now, on every ring.
                Ok(()) if state.unpublished_change.load(Ordering::Relaxed) => {
                    // The wait comes after the reconcile, not before it: a
                    // point that has stopped answering is retired and
                    // replaced straight away, and it is only the upload that
                    // announces it which is held to one a minute. Anything
                    // that ends during the wait has already queued its nudge
                    // and is dealt with on the next turn of this loop.
                    crate::retry::sleep(state.wait_before_publishing()).await;
                    publish_everywhere(&state).await
                }
                // Every stored descriptor names exactly what is answering, so
                // there is nothing to tell the HSDirs.
                Ok(()) => Ok(()),
                Err(error) => Err(error),
            }
        };
        if let Err(error) = outcome {
            state.log(
                &format!("Could not restore the introduction points: {error}"),
                LogType::Error,
            );
        }

        delay = if state.settled().await {
            min_delay
        } else {
            grown_retry_delay(delay, max_delay)
        };
    }
}

/// Whether the maintainer has nothing left to come back to: the target number
/// of introduction points is answering *and* the HSDirs have been told about
/// them. Only then is waiting on the nudges alone the whole of the job.
fn intro_points_settled(pending: bool, established: usize, target: usize) -> bool {
    !pending && established >= target
}

/// The next retry delay after one that left the service still short.
fn grown_retry_delay(delay: Duration, max_delay: Duration) -> Duration {
    (delay * 2).min(max_delay)
}

/// What is left of [`UPLOAD_RATE_LIMIT`] since the last publication.
///
/// A clock that has gone backwards since then counts as no wait at all: the
/// limit is there to stop a flapping relay from generating uploads, and a
/// service that stalled on a clock adjustment instead would be the worse
/// failure.
fn wait_before_publishing(last: Option<SystemTime>, now: SystemTime) -> Duration {
    let Some(last) = last else {
        return Duration::ZERO;
    };
    UPLOAD_RATE_LIMIT.saturating_sub(now.duration_since(last).unwrap_or(UPLOAD_RATE_LIMIT))
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

        let (introduce_tx, introduce_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (streams, stream_rx) = mpsc::channel(CHANNEL_DEPTH);
        let stream_tx = streams.clone();
        // One nudge is as good as several: the maintainer looks at every point
        // whenever it wakes, so a second one queued behind the first would
        // find nothing left to do.
        let (maintenance_tx, maintenance_rx) = mpsc::channel(1);

        let state = Arc::new(ServiceState {
            circuit_manager,
            identity,
            directory_manager,
            relay_manager,
            intro_points: RwLock::new(Vec::new()),
            target_intro_points: options.intro_points,
            introduce_tx,
            maintenance_tx,
            subcredentials: RwLock::new(Vec::new()),
            on_log,
            tunnels: RwLock::new(Vec::new()),
            publishing: Mutex::new(()),
            unpublished_change: AtomicBool::new(false),
            last_publication: StdMutex::new(None),
            aborts: StdMutex::new(Vec::new()),
            upload_aborts: StdMutex::new(Vec::new()),
        });
        state.log(
            &format!("Publishing onion service {address}"),
            LogType::Info,
        );

        // Establishing the first points is the same operation as replacing one
        // later, and it fails the launch for the same reason the maintainer
        // logs it: a service with no introduction point has nothing to put in
        // a descriptor. Anything short of the target is left to the maintainer.
        reconcile_intro_points(&state).await?;

        // The descriptor goes to the ring of the period this consensus is in
        // and to the rings either side of it. A peer whose own consensus has
        // not turned over yet — or has turned over already — computes one of
        // those neighbouring rings, and publishing to the current one alone
        // would leave it looking at HSDirs that hold nothing.
        //
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
        state.record_publication();
        let mut stored = 1_usize;
        for (publication, outcome) in neighbours.iter().zip(neighbour_outcomes) {
            match outcome {
                Ok(()) => stored += 1,
                Err(error) => state.log(
                    &format!(
                        "The descriptor for time period {} was not published, so a client an \
                         interval out of step will not find this service: {error}",
                        publication.period.interval_num()
                    ),
                    LogType::Error,
                ),
            }
        }
        // A period the launch could not reach is the maintainer's to retry,
        // in minutes rather than at the next republish.
        state
            .unpublished_change
            .store(stored < publications.len(), Ordering::Relaxed);

        // Keep the introduction points answering. A relay that goes down, or
        // leaves the consensus, stays in every descriptor until something
        // notices: reachability then decays one point at a time with nothing
        // to see from the inside.
        let (maintain_abort, maintain_registration) = AbortHandle::new_pair();
        aborts_of(&state.aborts).push(maintain_abort);
        let maintain_state = state.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let _ = Abortable::new(
                maintain_intro_points(maintain_state, maintenance_rx),
                maintain_registration,
            )
            .await;
        });

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
        self.state.intro_points.write().await.clear();
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

/// Bring the introduction points back up to strength.
///
/// Retires the ones this service can no longer be reached through — a circuit
/// that has ended, a relay that has left the consensus — and establishes
/// replacements at relays none of the survivors are on. Both halves are
/// idempotent, so launch, a failed point and the republish timer can all call
/// it and get the set the service should be advertising.
///
/// A set that changed leaves `unpublished_change` set: what the HSDirs hold
/// now names something other than what answers, and whichever loop gets there
/// first owes them a descriptor.
///
/// Fails only when the service is left with no introduction point at all: the
/// one state it cannot describe in a descriptor, and so the one worth failing
/// a launch over.
///
/// A retired point's circuit is dropped with it, where Arti keeps a retired
/// one answering until the last descriptor that named it has expired. What
/// that costs is one wasted introduction attempt for a client still holding
/// the old descriptor, which then tries one of the two other points that
/// descriptor names — the same thing that client does when a relay simply
/// fails.
async fn reconcile_intro_points(state: &Arc<ServiceState>) -> Result<()> {
    let known: HashSet<String> = state
        .relay_manager
        .read()
        .await
        .relays
        .iter()
        .map(|relay| relay.fingerprint.clone())
        .collect();

    let mut changed = false;
    // Fingerprints a replacement must not pick again: two of a service's
    // introduction points on one relay would fail together, which is the
    // thing this whole loop exists to spread out.
    let mut used: HashSet<String> = HashSet::new();
    {
        let mut points = state.intro_points.write().await;
        points.retain(|point| {
            let ended = point.ended.load(Ordering::Relaxed);
            if intro_point_is_usable(ended, &point.relay.fingerprint, &known) {
                used.insert(point.relay.fingerprint.clone());
                return true;
            }
            state.log(
                &format!(
                    "Introduction point {} is no longer advertised: {}",
                    point.relay.nickname,
                    if ended {
                        "its circuit ended"
                    } else {
                        "its relay has left the consensus"
                    }
                ),
                LogType::Warn,
            );
            changed = true;
            false
        });
    }

    let mut last_error = None;
    let established = state.intro_points.read().await.len();
    for _ in established..state.target_intro_points {
        let relay = {
            let manager = state.relay_manager.read().await;
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
            establish_intro_point(state, &relay),
        )
        .await;
        match attempt {
            Ok(point) => {
                state.log(
                    &format!("Introduction point established at {}", relay.nickname),
                    LogType::Success,
                );
                state.intro_points.write().await.push(point);
                changed = true;
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

    if changed {
        state.unpublished_change.store(true, Ordering::Relaxed);
    }
    if state.intro_points.read().await.is_empty() {
        return Err(last_error.unwrap_or_else(|| {
            TorError::Onion("No relay would act as an introduction point".to_string())
        }));
    }
    Ok(())
}

/// Whether an established introduction point is still worth advertising.
///
/// `known` is every relay the consensus lists. An empty one means the
/// directory is what has gone missing rather than the relays, and retiring
/// every point on that would be a service taking itself down over a refresh
/// that failed.
fn intro_point_is_usable(ended: bool, fingerprint: &str, known: &HashSet<String>) -> bool {
    !ended && (known.is_empty() || known.contains(fingerprint))
}

/// One introduction point: a circuit to `relay`, an ESTABLISH_INTRO signed
/// with a fresh session key, a handler that forwards every INTRODUCE2, and a
/// watcher that reports the circuit's end.
async fn establish_intro_point(
    state: &Arc<ServiceState>,
    relay: &Relay,
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
                introduce: state.introduce_tx.clone(),
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

    // Without this the circuit would just stop: the relay's own end of it —
    // a DESTROY, a channel that dropped, a protocol error the handler
    // returned — reaches nothing that could act on it, and the descriptor
    // would go on naming this point for as long as the service ran.
    //
    // The watcher holds no handle on the tunnel, so it cannot be what keeps
    // the reactor alive: when the point is retired the circuit closes, and
    // the watcher's own future is what resolves.
    let ended = Arc::new(AtomicBool::new(false));
    {
        let closed = tunnel.wait_for_close();
        let ended = ended.clone();
        let mut nudge = state.maintenance_tx.clone();
        let nickname = relay.nickname.clone();
        wasm_bindgen_futures::spawn_local(async move {
            closed.await;
            debug!("Introduction circuit to {} ended", nickname);
            ended.store(true, Ordering::Relaxed);
            // Full means the maintainer has already been woken and has not
            // run yet, and it will see this point when it does.
            let _ = nudge.try_send(());
        });
    }

    Ok(EstablishedIntroPoint {
        tunnel,
        relay: relay.clone(),
        descriptor,
        ended,
    })
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

    fn consensus_of(fingerprints: &[&str]) -> HashSet<String> {
        fingerprints.iter().map(|id| id.to_string()).collect()
    }

    /// The circuit ending is the signal the descriptor was missing: a point
    /// that has stopped answering stops being advertised.
    #[test]
    fn an_introduction_point_whose_circuit_ended_is_retired() {
        let consensus = consensus_of(&["aaaa", "bbbb"]);
        assert!(!intro_point_is_usable(true, "aaaa", &consensus));
    }

    /// The other way an introduction point stops working without saying so:
    /// the relay is still holding the circuit up but no client will build one
    /// to it, because the consensus no longer lists it.
    #[test]
    fn an_introduction_point_off_the_consensus_is_retired() {
        let consensus = consensus_of(&["aaaa", "bbbb"]);
        assert!(intro_point_is_usable(false, "aaaa", &consensus));
        assert!(!intro_point_is_usable(false, "cccc", &consensus));
    }

    /// A relay list this service could not refresh says nothing about its
    /// introduction points, and a service that retired all of them over it
    /// would take itself down for a failed download.
    #[test]
    fn an_empty_consensus_retires_nothing() {
        let consensus = HashSet::new();
        assert!(intro_point_is_usable(false, "aaaa", &consensus));
        assert!(!intro_point_is_usable(true, "aaaa", &consensus));
    }

    /// The whole job is done only when the points are up and the HSDirs have
    /// been told: a replacement established but not published leaves the
    /// maintainer on its retry timer, because the reconcile that follows has
    /// nothing left to change and would report no change at all.
    #[test]
    fn an_unpublished_change_is_not_settled() {
        assert!(intro_points_settled(false, 3, 3));
        assert!(!intro_points_settled(true, 3, 3));
        assert!(!intro_points_settled(false, 2, 3));
    }

    /// A network with no relay to spare is asked less and less often, up to a
    /// ceiling: a service short of a point is still reachable through the
    /// ones it has.
    #[test]
    fn retries_back_off_to_a_ceiling() {
        let (min_delay, max_delay) = INTRO_RETRY_DELAY;
        let mut delay = min_delay;
        for _ in 0..20 {
            let grown = grown_retry_delay(delay, max_delay);
            assert!(grown > delay || grown == max_delay);
            delay = grown;
        }
        assert_eq!(delay, max_delay);
    }

    #[test]
    fn the_first_publication_waits_for_nothing() {
        assert_eq!(
            wait_before_publishing(None, SystemTime::UNIX_EPOCH),
            Duration::ZERO
        );
    }

    /// Two introduction points failing one after the other are one upload, not
    /// two: the second waits out what is left of the minute.
    #[test]
    fn a_second_publication_waits_out_the_limit() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(
            wait_before_publishing(Some(last), last + Duration::from_secs(20)),
            Duration::from_secs(40)
        );
        assert_eq!(
            wait_before_publishing(Some(last), last + UPLOAD_RATE_LIMIT),
            Duration::ZERO
        );
    }

    /// A clock that has gone backwards must not stall the maintainer: the
    /// limit exists to keep a flapping relay from generating uploads, not to
    /// hold a descriptor back.
    #[test]
    fn a_clock_that_went_backwards_waits_for_nothing() {
        let last = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(
            wait_before_publishing(Some(last), last - Duration::from_secs(30)),
            Duration::ZERO
        );
    }
}
