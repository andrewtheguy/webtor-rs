//! Onion service (v3) host: publishing a service *from* the browser.
//!
//! This is the mirror image of [`crate::onion`]. Instead of looking a
//! descriptor up and introducing itself to somebody else's service, the page
//! runs one:
//!
//! 1. generate an identity keypair, whose public half *is* the `.onion`
//!    address, and blind it for the current time period;
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
use crate::directory::{post_directory_document, DirectoryManager};
use crate::error::{Result, TorError};
use crate::onion::{select_hsdirs_with_spread, verbatim_target};
use crate::relay::{selection, Relay, RelayManager};
use crate::retry::with_timeout;
use crate::time::system_time_now;
use async_lock::{Mutex, RwLock};
use futures::channel::{mpsc, oneshot};
use futures::future::{AbortHandle, Abortable};
use futures::{SinkExt, StreamExt};
use std::collections::HashSet;
use std::sync::Arc;
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

/// An introduction point that has acknowledged our ESTABLISH_INTRO.
struct EstablishedIntroPoint {
    /// Held so the circuit's reactor keeps running; INTRODUCE2 arrives here.
    tunnel: Arc<ClientTunnel>,
    /// What the descriptor says about this introduction point.
    descriptor: IntroPointDesc,
}

/// A published onion service.
///
/// Dropping it, or calling [`OnionService::close`], tears down the
/// introduction points; the descriptor then expires on its own.
pub struct OnionService {
    address: String,
    incoming: Mutex<mpsc::Receiver<DataStream>>,
    state: Arc<ServiceState>,
}

/// The parts of a running service that its background tasks share.
struct ServiceState {
    circuit_manager: Arc<CircuitManager>,
    subcredential: Subcredential,
    on_log: Option<LogCallback>,
    /// Introduction circuits and live client circuits. A tunnel's reactor
    /// stops when its last handle is dropped, so they are held here.
    tunnels: RwLock<Vec<Arc<ClientTunnel>>>,
    /// Aborts the background tasks when the service is closed.
    aborts: RwLock<Vec<AbortHandle>>,
}

impl ServiceState {
    fn log(&self, message: &str, log_type: LogType) {
        if let Some(callback) = &self.on_log {
            (callback.0)(message, log_type);
            return;
        }
        info!("{}", message);
    }
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

        let params = directory_manager.hsdir_params().await?;
        let (blind_key, blind_keypair, subcredential) = identity
            .compute_blinded_key(params.time_period())
            .map_err(|error| TorError::Onion(format!("Key blinding failed: {error}")))?;
        let blind_id: HsBlindId = blind_key.id();

        let state = Arc::new(ServiceState {
            circuit_manager,
            subcredential,
            on_log,
            tunnels: RwLock::new(Vec::new()),
            aborts: RwLock::new(Vec::new()),
        });
        state.log(
            &format!("Publishing onion service {address}"),
            LogType::Info,
        );

        let (introduce_tx, introduce_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (stream_tx, stream_rx) = mpsc::channel(CHANNEL_DEPTH);

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

        let now = system_time_now();
        let descriptor = build_descriptor(
            &blind_key,
            &blind_keypair,
            &subcredential,
            &descriptors,
            &params.time_period(),
            now,
            &mut rng,
        )?;
        drop(blind_keypair);

        let relays = relay_manager.read().await.relays.clone();
        let hsdirs = select_hsdirs_with_spread(&relays, &blind_id, &params, HSDIR_SPREAD_STORE);
        if hsdirs.is_empty() {
            return Err(TorError::Onion(
                "The directory has no HSDir relays to publish the descriptor to".to_string(),
            ));
        }
        publish_descriptor(&state, &hsdirs, &blind_id, &descriptor).await?;

        // From here on the service answers introductions on its own.
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        state.aborts.write().await.push(abort_handle);
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
        for abort in self.state.aborts.write().await.drain(..) {
            abort.abort();
        }
        self.state.tunnels.write().await.clear();
        self.incoming.lock().await.close();
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
    time_period: &tor_hscrypto::time::TimePeriod,
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
    // so it has to grow. Seconds since the time period began does that, and
    // never runs backwards while the service is up.
    let period_start = time_period
        .range()
        .map_err(|error| TorError::Onion(format!("Time period is unrepresentable: {error}")))?
        .start;
    let revision = now
        .duration_since(period_start)
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

/// POST the descriptor to every responsible HSDir. One acceptance is enough
/// for a client to find the service; the rest are redundancy.
async fn publish_descriptor(
    state: &Arc<ServiceState>,
    hsdirs: &[Relay],
    blind_id: &HsBlindId,
    descriptor: &str,
) -> Result<()> {
    debug!(
        "Publishing a {} byte descriptor for {} to {} HSDirs",
        descriptor.len(),
        hex::encode(blind_id.as_ref()),
        hsdirs.len()
    );

    // Every HSDir at once: they are independent, and a service that waited
    // for each in turn would take minutes to become reachable.
    let uploads = hsdirs.iter().map(|hsdir| async move {
        let attempt = async {
            let (tunnel, _) = state
                .circuit_manager
                .build_tunnel_to(&hsdir.as_circ_target()?)
                .await?;
            post_directory_document(&Arc::new(tunnel), "/tor/hs/3/publish", descriptor).await
        };
        (hsdir, with_timeout(UPLOAD_TIMEOUT, "Descriptor upload", attempt).await)
    });

    let mut accepted = 0_usize;
    let mut last_error = None;
    for (hsdir, outcome) in futures::future::join_all(uploads).await {
        match outcome {
            Ok(()) => {
                debug!("HSDir {} stored the descriptor", hsdir.nickname);
                accepted += 1;
            }
            Err(error) => {
                state.log(
                    &format!("HSDir {} rejected the descriptor: {error}", hsdir.nickname),
                    LogType::Error,
                );
                last_error = Some(error);
            }
        }
    }

    if accepted == 0 {
        return Err(last_error
            .unwrap_or_else(|| TorError::Onion("No HSDir accepted the descriptor".to_string())));
    }
    state.log(
        &format!("Descriptor published to {accepted} of {} HSDirs", hsdirs.len()),
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
    let (keygen, rendezvous1_body, payload) = hs_ntor::server_receive_intro(
        &mut rand::rng(),
        &keys.ntor,
        &keys.session_id_key,
        &[state.subcredential],
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
    state.tunnels.write().await.push(tunnel);

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
