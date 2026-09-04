//! Browser binding: a Tor client for `http://` and `ws://` onion services.
//!
//! Everything the client reaches is a v3 onion service. No circuit is built to
//! an exit, so there is no clearnet TLS to terminate inside WASM and no server
//! certificate to check: the onion address commits to the service key and the
//! circuit is encrypted end to end. `https://` and `wss://` are therefore
//! refused rather than tolerated.

mod js_callback;
mod logging;
mod options;

use futures::future::{AbortHandle, Abortable};
use futures::lock::Mutex;
use js_callback::JsCallback;
use logging::Logger;
use options::error as option_error;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use futures::{AsyncReadExt, AsyncWriteExt};
use webtor_core::{
    DEFAULT_MAX_RESPONSE_BYTES,
    onion_websocket, DataReader, DataWriter, HttpRequest, HttpResponse, LogType, OnionService,
    OnionServiceOptions, OnionUrl, TorClient, TorClientOptions, WebSocketConnection,
    WebSocketMessage, WebSocketReader, WebSocketWriter,
};

const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 240_000;
/// Time for the onion stream plus the RFC 6455 upgrade on it.
const DEFAULT_WEBSOCKET_TIMEOUT_MS: u64 = 240_000;
const DEFAULT_MAX_MESSAGE_BYTES: u64 = 1024 * 1024;
const DEFAULT_LOG_PREFIX: &str = "[webtor]";

const CLIENT_OPTIONS: &[&str] = &[
    "bridge",
    "stunUrls",
    "bridgeUrl",
    "bridgeFingerprint",
    "directorySeed",
    "connectionTimeoutMs",
    "log",
    "logPrefix",
    "onLog",
    "onDirectoryChange",
];
const REQUEST_OPTIONS: &[&str] = &["method", "headers", "body", "timeoutMs", "maxResponseBytes"];
const WEBSOCKET_OPTIONS: &[&str] = &["headers", "maxMessageBytes", "timeoutMs"];
const SERVICE_OPTIONS: &[&str] = &["introPoints"];

/// Introduction points a published service establishes, and the most it will
/// accept being asked for: past a handful they cost circuits without making
/// the service easier to reach.
const DEFAULT_INTRO_POINTS: u64 = 3;
const MAX_INTRO_POINTS: u64 = 6;
/// How much of one client's stream a single `receive()` returns.
const SERVICE_READ_BYTES: usize = 8192;

/// A bridge identity is 40 hex characters. Checking it here costs nothing and
/// saves a typo from surfacing minutes later as a channel handshake failure,
/// which reads like a network problem rather than a config one.
fn check_fingerprint(fingerprint: String) -> Result<String, JsValue> {
    if fingerprint.len() == 40 && fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(fingerprint);
    }
    Err(option_error(format!(
        "WebtorClient.create option \"bridgeFingerprint\" must be 40 hex characters, not {fingerprint:?}"
    )))
}

fn js_error(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{context}: {error}"))
}

/// What `create` was told to do, once its option bag has been checked.
struct ClientConfig {
    options: TorClientOptions,
    directory_seed: Option<String>,
    /// Where this client's own lines go; discards them when logging is off.
    log: Logger,
    /// The same sink, or `None` when the caller asked for no logging. Only a
    /// client that reports anywhere claims the page's `tracing` events.
    traces: Option<Logger>,
}

fn read_client_config(raw: Option<js_sys::Object>) -> Result<ClientConfig, JsValue> {
    let bag = options::bag(raw, "WebtorClient.create")?;
    options::reject_unknown_keys(&bag, "WebtorClient.create", CLIENT_OPTIONS)?;
    let what = "WebtorClient.create";

    let bridge = options::string(&bag, "bridge", what)?.unwrap_or_else(|| "websocket".to_string());
    let stun_urls = options::string_array(&bag, "stunUrls", what)?.unwrap_or_default();
    let bridge_url = options::string(&bag, "bridgeUrl", what)?;
    let bridge_fingerprint = options::string(&bag, "bridgeFingerprint", what)?;
    let options = match bridge.as_str() {
        // The direct bridge WebSocket needs no broker, no volunteer proxy and
        // no STUN server, which is why it is the default: one fixed endpoint
        // and no third party beyond torproject.net.
        "websocket" => {
            if !stun_urls.is_empty() {
                return Err(option_error(
                    "WebtorClient.create option \"stunUrls\" applies to the webrtc bridge only",
                ));
            }
            // A bridge is authenticated by its RSA identity alone, so a URL
            // without one would be a request to trust whatever answers.
            match (bridge_url, bridge_fingerprint) {
                (Some(url), Some(fingerprint)) => {
                    TorClientOptions::snowflake_websocket_at(url, check_fingerprint(fingerprint)?)
                }
                (None, None) => TorClientOptions::snowflake_websocket(),
                (Some(_), None) => {
                    return Err(option_error(
                        "WebtorClient.create option \"bridgeUrl\" needs \"bridgeFingerprint\": a bridge is authenticated by its RSA identity and nothing else",
                    ))
                }
                (None, Some(_)) => {
                    return Err(option_error(
                        "WebtorClient.create option \"bridgeFingerprint\" needs \"bridgeUrl\"",
                    ))
                }
            }
        }
        // A volunteer Snowflake proxy, brokered over HTTPS. Harder to block,
        // and it needs a STUN server to find its own address.
        "webrtc" => {
            if bridge_url.is_some() || bridge_fingerprint.is_some() {
                return Err(option_error(
                    "WebtorClient.create options \"bridgeUrl\" and \"bridgeFingerprint\" apply to the websocket bridge only",
                ));
            }
            if stun_urls.is_empty() {
                return Err(option_error(
                    "WebtorClient.create bridge \"webrtc\" requires at least one STUN URL in \"stunUrls\"",
                ));
            }
            TorClientOptions::snowflake_webrtc(stun_urls)
        }
        other => {
            return Err(option_error(format!(
                "WebtorClient.create option \"bridge\" must be \"websocket\" or \"webrtc\", not {other:?}"
            )))
        }
    };

    let timeout =
        options::count(&bag, "connectionTimeoutMs", what)?.unwrap_or(DEFAULT_CONNECTION_TIMEOUT_MS);
    let mut options = options.with_connection_timeout(timeout);

    // Where the lines go is the caller's decision, not this binding's: an
    // application with its own log wants them there, and the console is only
    // the default because a page that has not said otherwise has nowhere else.
    let console = options::boolean(&bag, "log", what)?;
    let prefix = options::string(&bag, "logPrefix", what)?;
    let traces: Option<Logger> = match options::function(&bag, "onLog", what)? {
        Some(callback) => {
            if console.is_some() || prefix.is_some() {
                return Err(option_error(
                    "WebtorClient.create options \"log\" and \"logPrefix\" configure the console sink, which \"onLog\" replaces",
                ));
            }
            Some(logging::js_logger(callback))
        }
        None if console.unwrap_or(true) => Some(logging::console_logger(
            prefix.unwrap_or_else(|| DEFAULT_LOG_PREFIX.into()),
        )),
        None => None,
    };
    let log: Logger = traces.clone().unwrap_or_else(logging::silent);
    let for_client = log.clone();
    options = options.with_on_log(move |message, log_type| for_client(message, log_type));

    // Where a refreshed directory is kept is the caller's, so all this does is
    // hand the seed over the moment there is a newer one.
    if let Some(callback) = options::function(&bag, "onDirectoryChange", what)? {
        let sink = JsCallback::new(callback);
        options = options.with_on_directory_change(move |encoded| sink.call(&[encoded]));
    }

    Ok(ClientConfig {
        options,
        directory_seed: options::string(&bag, "directorySeed", what)?
            .filter(|seed| !seed.is_empty()),
        log,
        traces,
    })
}

/// Whether `host` is a v3 onion address.
#[wasm_bindgen(js_name = isOnionHost)]
pub fn is_onion_host(host: &str) -> bool {
    webtor_core::is_onion_host(host)
}

/// Parse an onion URL, throwing the same error a request would.
///
/// Returns `{scheme, host, port, pathAndQuery}`. Nothing here touches the
/// network, so a caller can validate input before paying for a bootstrap.
#[wasm_bindgen(js_name = parseOnionUrl)]
pub fn parse_onion_url(url: &str) -> Result<JsValue, JsValue> {
    let parsed = OnionUrl::parse(url).map_err(|error| JsValue::from_str(&error.to_string()))?;
    let object = js_sys::Object::new();
    set(&object, "scheme", &JsValue::from_str(parsed.scheme()));
    set(&object, "host", &JsValue::from_str(parsed.host()));
    set(&object, "port", &JsValue::from_f64(parsed.port().into()));
    set(
        &object,
        "pathAndQuery",
        &JsValue::from_str(&parsed.path_and_query()),
    );
    Ok(object.into())
}

/// Read what a `directoryCache()` seed says about itself, with no client and
/// no network: when its consensus is valid, and which onion service time
/// period it places descriptors in.
///
/// Whether a seed is good enough to use is the caller's rule — a consensus
/// stays valid for three hours while the time period it belongs to may have
/// rotated in the meantime, and how much of that an application will tolerate
/// is its own decision. This exists so making that decision does not mean
/// parsing a Tor consensus by hand. It verifies nothing; `create` still
/// revalidates any seed against the pinned directory authorities before
/// installing a byte of it.
#[wasm_bindgen(js_name = describeDirectory)]
pub fn describe_directory(seed: &str) -> Result<DirectoryDescription, JsValue> {
    webtor_core::describe_directory(seed)
        .map(|inner| DirectoryDescription { inner })
        .map_err(|error| js_error("Failed to read the Tor directory seed", error))
}

/// What one directory seed says about itself.
#[wasm_bindgen]
pub struct DirectoryDescription {
    inner: webtor_core::DirectoryDescription,
}

#[wasm_bindgen]
impl DirectoryDescription {
    /// When the consensus became valid.
    #[wasm_bindgen(getter, js_name = validAfter)]
    pub fn valid_after(&self) -> js_sys::Date {
        js_date(self.inner.valid_after())
    }

    /// When the consensus expires. A seed past this is refused, so it is the
    /// deadline a bootstrap has to start within.
    #[wasm_bindgen(getter, js_name = validUntil)]
    pub fn valid_until(&self) -> js_sys::Date {
        js_date(self.inner.valid_until())
    }

    /// The onion service time period this directory places descriptors in.
    ///
    /// Both peers of a transfer must be in the same one: a service publishes
    /// to the HSDirs this number selects, and a client reading a directory
    /// from a different period asks HSDirs the service never uploaded to,
    /// which answer 404 without explaining why.
    #[wasm_bindgen(getter, js_name = timePeriod)]
    pub fn time_period(&self) -> f64 {
        self.inner.time_period() as f64
    }

    /// The time period covering `at`, in epoch milliseconds as `Date.now()`
    /// gives them. Comparing it with `timePeriod` is how a caller tells that
    /// a still-valid consensus has outlived the ring it describes.
    #[wasm_bindgen(js_name = timePeriodAt)]
    pub fn time_period_at(&self, at: f64) -> Result<f64, JsValue> {
        if !at.is_finite() || at < 0.0 {
            return Err(option_error(
                "DirectoryDescription.timePeriodAt takes epoch milliseconds, as Date.now() gives them",
            ));
        }
        let at = std::time::UNIX_EPOCH + Duration::from_millis(at as u64);
        self.inner
            .time_period_at(at)
            .map(|period| period as f64)
            .map_err(|error| js_error("Failed to place that time in a period", error))
    }
}

fn js_date(when: std::time::SystemTime) -> js_sys::Date {
    let ms = when
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as f64)
        .unwrap_or(0.0);
    js_sys::Date::new(&JsValue::from_f64(ms))
}

fn set(object: &js_sys::Object, key: &str, value: &JsValue) {
    let _ = js_sys::Reflect::set(object, &JsValue::from_str(key), value);
}

#[wasm_bindgen]
pub struct WebtorClient {
    client: Arc<TorClient>,
    log: Logger,
    /// Set by `close`. Work issued afterwards fails at once instead of
    /// bootstrapping a Tor client all over again for a stream nobody wants.
    closed: Rc<Cell<bool>>,
    /// Calls still building their onion circuit, keyed so each can remove
    /// itself. `close` aborts them; a rendezvous that nothing will use should
    /// not run on to completion after the caller is gone.
    pending: Rc<RefCell<HashMap<u64, AbortHandle>>>,
    next_pending: Rc<Cell<u64>>,
}

#[wasm_bindgen]
impl WebtorClient {
    /// Bootstrap a Tor client.
    ///
    /// Options, all optional:
    /// - `bridge`: `"websocket"` (default) or `"webrtc"`.
    /// - `stunUrls`: STUN servers for the `"webrtc"` bridge, required there.
    /// - `bridgeUrl` and `bridgeFingerprint`: a bridge to use instead of the
    ///   public one, for the `"websocket"` bridge. Both or neither;
    ///   `scripts/local-bridge` runs one on localhost.
    /// - `directorySeed`: a previous `directoryCache()`, to skip downloading
    ///   the directory over the bridge.
    /// - `connectionTimeoutMs`: bootstrap budget, default 300000.
    /// - `log`: write progress to the console, default `true`.
    /// - `logPrefix`: default `"[webtor]"`.
    /// - `onLog`: `(message, level)` to take every line instead of the
    ///   console, where `level` is `"info"`, `"success"`, `"warn"` or
    ///   `"error"`. Replaces `log` and `logPrefix`, which configure the
    ///   console sink, so passing it with either is an error.
    /// - `onDirectoryChange`: `(seed)` called with a new `directoryCache()`
    ///   whenever this client downloads a directory, including the refreshes
    ///   a published service does hours into its life. `directoryCache()` is
    ///   a pull, so a caller that exports once after `create` stores the
    ///   directory it started with; this is how it hears about a newer one.
    ///   A `directorySeed` is never handed back, having come from the caller.
    ///
    /// A caller that wants proof the client can complete a rendezvous before
    /// it uses it does that itself, with a `fetch` against a service it
    /// chooses: which onion is worth reaching is the caller's question, and
    /// no answer to it belongs in this binding.
    #[wasm_bindgen(js_name = create)]
    pub fn create(options: Option<js_sys::Object>) -> js_sys::Promise {
        future_to_promise(async move {
            console_error_panic_hook::set_once();
            let config = read_client_config(options)?;
            let log = config.log;
            logging::install(config.traces);

            let client = TorClient::new(config.options)
                .await
                .map_err(|error| js_error("Failed to initialize webtor", error))?;
            if let Some(seed) = config.directory_seed {
                client.set_directory_seed(&seed).await;
            }
            client
                .ensure_ready()
                .await
                .map_err(|error| js_error("Failed to establish Tor connection", error))?;
            Ok(JsValue::from(Self {
                client: Arc::new(client),
                log,
                closed: Rc::new(Cell::new(false)),
                pending: Rc::new(RefCell::new(HashMap::new())),
                next_pending: Rc::new(Cell::new(0)),
            }))
        })
    }

    /// Issue one HTTP/1.1 request to `http://<address>.onion[:port][/path]`.
    ///
    /// Options: `method` (default `"GET"`), `headers`, `body` (a string or a
    /// `Uint8Array`), `timeoutMs` (default 240000) and `maxResponseBytes`
    /// (default 8388608), which is the most the buffered response may occupy.
    #[wasm_bindgen(js_name = fetch)]
    pub fn fetch(&self, url: String, options: Option<js_sys::Object>) -> js_sys::Promise {
        let client = self.client.clone();
        self.run(async move {
            let bag = options::bag(options, "fetch")?;
            options::reject_unknown_keys(&bag, "fetch", REQUEST_OPTIONS)?;
            let request = HttpRequest {
                method: options::string(&bag, "method", "fetch")?.unwrap_or_else(|| "GET".into()),
                url: OnionUrl::parse(&url).map_err(option_error)?,
                headers: options::string_map(&bag, "headers", "fetch")?,
                body: options::body(&bag, "body", "fetch")?,
                max_response_bytes: options::count(&bag, "maxResponseBytes", "fetch")?
                    .map_or(DEFAULT_MAX_RESPONSE_BYTES, |bytes| {
                        usize::try_from(bytes).unwrap_or(usize::MAX)
                    }),
            };
            let timeout = options::count(&bag, "timeoutMs", "fetch")?
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
            let response = webtor_core::with_timeout(
                Duration::from_millis(timeout),
                "Onion HTTP request",
                client.send(request),
            )
            .await
            .map_err(|error| js_error("Onion HTTP request failed", error))?;
            Ok(JsValue::from(OnionResponse::new(response)))
        })
    }

    /// Open a WebSocket to `ws://<address>.onion[:port][/path]`.
    ///
    /// Options: `headers` on the upgrade request (a `Cookie`, an `Origin`, a
    /// `Sec-WebSocket-Protocol`; the ones the upgrade itself needs are set
    /// here and refused), `maxMessageBytes` (default 1048576) and `timeoutMs`
    /// (default 240000, covering the onion stream and the upgrade on it).
    #[wasm_bindgen(js_name = connectWebSocket)]
    pub fn connect_websocket(
        &self,
        url: String,
        options: Option<js_sys::Object>,
    ) -> js_sys::Promise {
        let client = self.client.clone();
        let log = self.log.clone();
        self.run(async move {
            let bag = options::bag(options, "connectWebSocket")?;
            options::reject_unknown_keys(&bag, "connectWebSocket", WEBSOCKET_OPTIONS)?;
            let headers = options::string_map(&bag, "headers", "connectWebSocket")?;
            let max_message_bytes =
                options::count(&bag, "maxMessageBytes", "connectWebSocket")?
                    .unwrap_or(DEFAULT_MAX_MESSAGE_BYTES) as usize;
            let timeout = options::count(&bag, "timeoutMs", "connectWebSocket")?
                .unwrap_or(DEFAULT_WEBSOCKET_TIMEOUT_MS);
            let parsed = OnionUrl::parse(&url).map_err(option_error)?;
            if parsed.scheme() != "ws" {
                return Err(option_error(
                    "connectWebSocket needs a ws:// URL; the onion circuit already encrypts it",
                ));
            }

            log(&format!("Opening an onion stream to {url}..."), LogType::Info);
            let socket = webtor_core::with_timeout(
                Duration::from_millis(timeout),
                "Onion WebSocket",
                async {
                    let stream = client.open_stream(&parsed).await?;
                    onion_websocket::connect(stream, &parsed, &headers, max_message_bytes).await
                },
            )
            .await
            .map_err(|error| js_error("Onion WebSocket failed", error))?;
            log(&format!("Connected to {url} through Tor."), LogType::Success);

            let WebSocketConnection { writer, reader, headers } = socket;
            Ok(JsValue::from(OnionWebSocket {
                writer: Rc::new(Mutex::new(writer)),
                reader: Rc::new(Mutex::new(reader)),
                headers,
                max_message_bytes,
                closed: Rc::new(Cell::new(false)),
            }))
        })
    }

    /// Open a raw stream to an onion address and virtual port.
    ///
    /// Nothing is layered on top: the caller reads and writes the bytes the
    /// service speaks. Use `fetch` for HTTP and `connectWebSocket` for
    /// WebSocket; this is for everything else.
    #[wasm_bindgen(js_name = connectStream)]
    pub fn connect_stream(&self, address: String, port: u16) -> js_sys::Promise {
        let client = self.client.clone();
        self.run(async move {
            let stream = client
                .connect_stream(&address, port)
                .await
                .map_err(|error| js_error("Failed to open the onion stream", error))?;
            let (reader, writer) = stream.split();
            Ok(JsValue::from(OnionStream {
                reader: Rc::new(Mutex::new(reader)),
                writer: Rc::new(Mutex::new(writer)),
                closed: Rc::new(Cell::new(false)),
            }))
        })
    }

    /// Publish a v3 onion service from this client.
    ///
    /// The identity key is generated in the page and never stored, so every
    /// call yields a new `.onion` address that lives as long as the returned
    /// service. Resolves once an HSDir has accepted the descriptor, which is
    /// when clients can reach it; the descriptor is then republished in the
    /// background, so the address keeps working past its expiry and across the
    /// time period rotation that moves every HSDir ring.
    ///
    /// Options: `introPoints` (default 3, at most 6).
    #[wasm_bindgen(js_name = publishOnionService)]
    pub fn publish_onion_service(&self, options: Option<js_sys::Object>) -> js_sys::Promise {
        let client = self.client.clone();
        let log = self.log.clone();
        self.run(async move {
            let bag = options::bag(options, "publishOnionService")?;
            options::reject_unknown_keys(&bag, "publishOnionService", SERVICE_OPTIONS)?;
            let intro_points = options::count(&bag, "introPoints", "publishOnionService")?
                .unwrap_or(DEFAULT_INTRO_POINTS);
            if intro_points == 0 || intro_points > MAX_INTRO_POINTS {
                return Err(option_error(format!(
                    "publishOnionService option \"introPoints\" must be between 1 and {MAX_INTRO_POINTS}"
                )));
            }

            let service = client
                .publish_onion_service(OnionServiceOptions {
                    intro_points: intro_points as usize,
                })
                .await
                .map_err(|error| js_error("Failed to publish the onion service", error))?;
            log(
                &format!("Onion service published at {}", service.onion_address()),
                LogType::Success,
            );
            Ok(JsValue::from(WebtorOnionService {
                service: Arc::new(service),
            }))
        })
    }

    /// Export the consensus and microdescriptors from the last successful
    /// bootstrap, so the caller can persist them and seed the next `create`.
    #[wasm_bindgen(js_name = directoryCache)]
    pub fn directory_cache(&self) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            let encoded = client
                .directory_cache_json()
                .await
                .map_err(|error| js_error("Failed to export the Tor directory cache", error))?
                .ok_or_else(|| JsValue::from_str("The Tor directory cache is unavailable"))?;
            Ok(JsValue::from_str(&encoded))
        })
    }

    /// Abort every call still in flight, refuse new ones, and tear the Tor
    /// client down.
    pub fn close(&self) -> js_sys::Promise {
        self.closed.set(true);
        for (_, handle) in self.pending.borrow_mut().drain() {
            handle.abort();
        }
        let client = self.client.clone();
        future_to_promise(async move {
            client.close().await;
            Ok(JsValue::UNDEFINED)
        })
    }
}

impl WebtorClient {
    /// Run one cancellable call: registered while it builds a circuit, and
    /// aborted rather than left to finish if `close` happens meanwhile.
    fn run(
        &self,
        work: impl std::future::Future<Output = Result<JsValue, JsValue>> + 'static,
    ) -> js_sys::Promise {
        let closed = self.closed.clone();
        let pending = self.pending.clone();
        let id = self.next_pending.get();
        self.next_pending.set(id.wrapping_add(1));
        let (handle, registration) = AbortHandle::new_pair();
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("The webtor client is closed"));
            }
            pending.borrow_mut().insert(id, handle);
            let outcome = Abortable::new(work, registration).await;
            pending.borrow_mut().remove(&id);
            match outcome {
                Ok(result) => result,
                Err(_aborted) => Err(JsValue::from_str("The webtor client closed mid-call")),
            }
        })
    }
}

/// A buffered HTTP response from an onion service.
#[wasm_bindgen]
pub struct OnionResponse {
    inner: HttpResponse,
}

impl OnionResponse {
    fn new(inner: HttpResponse) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl OnionResponse {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.inner.status
    }

    #[wasm_bindgen(getter)]
    pub fn ok(&self) -> bool {
        self.inner.is_success()
    }

    /// Response headers as a `Headers`, every occurrence kept: a repeated
    /// name reads back joined through `get`, and the cookies a response set
    /// come back one by one from `getSetCookie`. A header `Headers` refuses,
    /// for a name or value it considers malformed, is left out rather than
    /// making the whole response unreadable over one line a server got wrong.
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> Result<web_sys::Headers, JsValue> {
        let headers = web_sys::Headers::new()?;
        for (name, value) in self.inner.headers() {
            let _ = headers.append(name, value);
        }
        Ok(headers)
    }

    /// The body as bytes.
    pub fn bytes(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.inner.bytes())
    }

    /// The body decoded as UTF-8; throws if it is not.
    pub fn text(&self) -> Result<String, JsValue> {
        self.inner
            .text()
            .map_err(|error| js_error("Response body", error))
    }
}

/// A WebSocket carried on an onion stream.
#[wasm_bindgen]
pub struct OnionWebSocket {
    writer: Rc<Mutex<WebSocketWriter>>,
    reader: Rc<Mutex<WebSocketReader>>,
    headers: Vec<(String, String)>,
    max_message_bytes: usize,
    closed: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl OnionWebSocket {
    /// The headers the service answered the upgrade with, as a `Headers`:
    /// `Sec-WebSocket-Protocol` is the subprotocol it chose, and a
    /// `Set-Cookie` reads back from `getSetCookie`. As on a response, a
    /// header `Headers` refuses is left out.
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> Result<web_sys::Headers, JsValue> {
        let headers = web_sys::Headers::new()?;
        for (name, value) in &self.headers {
            let _ = headers.append(name, value);
        }
        Ok(headers)
    }

    /// Send a text message.
    #[wasm_bindgen(js_name = send)]
    pub fn send(&self, text: String) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        let limit = self.max_message_bytes;
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("The WebSocket is closed"));
            }
            if text.len() > limit {
                return Err(JsValue::from_str(&format!(
                    "Message of {} bytes exceeds maxMessageBytes ({limit})",
                    text.len()
                )));
            }
            writer
                .lock()
                .await
                .send_text(&text)
                .await
                .map_err(|error| js_error("WebSocket send failed", error))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Send a binary message.
    #[wasm_bindgen(js_name = sendBinary)]
    pub fn send_binary(&self, payload: Vec<u8>) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        let limit = self.max_message_bytes;
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("The WebSocket is closed"));
            }
            if payload.len() > limit {
                return Err(JsValue::from_str(&format!(
                    "Message of {} bytes exceeds maxMessageBytes ({limit})",
                    payload.len()
                )));
            }
            writer
                .lock()
                .await
                .send_binary(&payload)
                .await
                .map_err(|error| js_error("WebSocket send failed", error))?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Await the next message: `{type: "text", text}` or `{type: "binary",
    /// bytes}`, or `null` once the peer closes. Pings are answered here.
    pub fn receive(&self) -> js_sys::Promise {
        let writer = self.writer.clone();
        let reader = self.reader.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            loop {
                if closed.get() {
                    return Ok(JsValue::NULL);
                }
                let next = reader.lock().await.next().await;
                match next {
                    Ok(Some(WebSocketMessage::Text(text))) => {
                        let message = js_sys::Object::new();
                        set(&message, "type", &JsValue::from_str("text"));
                        set(&message, "text", &JsValue::from_str(&text));
                        return Ok(message.into());
                    }
                    Ok(Some(WebSocketMessage::Binary(bytes))) => {
                        let message = js_sys::Object::new();
                        set(&message, "type", &JsValue::from_str("binary"));
                        set(&message, "bytes", &js_sys::Uint8Array::from(&bytes[..]));
                        return Ok(message.into());
                    }
                    Ok(Some(WebSocketMessage::Ping(payload))) => {
                        writer
                            .lock()
                            .await
                            .send_pong(&payload)
                            .await
                            .map_err(|error| js_error("WebSocket pong failed", error))?;
                    }
                    Ok(Some(WebSocketMessage::Close)) => {
                        closed.set(true);
                        let _ = writer.lock().await.send_close().await;
                        return Ok(JsValue::NULL);
                    }
                    Ok(None) => {
                        closed.set(true);
                        return Ok(JsValue::NULL);
                    }
                    Err(error) => {
                        closed.set(true);
                        return Err(js_error("WebSocket receive failed", error));
                    }
                }
            }
        })
    }

    pub fn close(&self) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            if !closed.replace(true) {
                let _ = writer.lock().await.send_close().await;
            }
            Ok(JsValue::UNDEFINED)
        })
    }
}

/// A v3 onion service this page is running.
#[wasm_bindgen]
pub struct WebtorOnionService {
    service: Arc<OnionService>,
}

#[wasm_bindgen]
impl WebtorOnionService {
    /// The `<base32>.onion` address clients connect to.
    #[wasm_bindgen(getter, js_name = onionAddress)]
    pub fn onion_address(&self) -> String {
        self.service.onion_address().to_string()
    }

    /// Await the next stream a client has opened, or `null` once the service
    /// is closed. A client that asks for one address and port gets one
    /// stream; what is spoken on it is entirely up to the caller.
    pub fn accept(&self) -> js_sys::Promise {
        let service = self.service.clone();
        future_to_promise(async move {
            match service.accept().await {
                Some(stream) => {
                    let (reader, writer) = stream.split();
                    Ok(JsValue::from(OnionStream {
                        reader: Rc::new(Mutex::new(reader)),
                        writer: Rc::new(Mutex::new(writer)),
                        closed: Rc::new(Cell::new(false)),
                    }))
                }
                None => Ok(JsValue::NULL),
            }
        })
    }

    /// Withdraw the service: drop the introduction points and every client
    /// circuit. The descriptor stays on the HSDirs until it expires, so an
    /// address is not reusable afterwards.
    pub fn close(&self) -> js_sys::Promise {
        let service = self.service.clone();
        future_to_promise(async move {
            service.close().await;
            Ok(JsValue::UNDEFINED)
        })
    }
}

impl Drop for WebtorOnionService {
    /// Freeing the service from JavaScript withdraws it, the same as
    /// `close()` without the promise to await.
    ///
    /// A pending `accept` holds the service too, so this is what has to end
    /// it: without it, a page that let go of the object while waiting for a
    /// client would leave the service published, the timer republishing it
    /// and the introduction points answering, until the tab closed.
    fn drop(&mut self) {
        self.service.shutdown();
    }
}

/// A raw onion stream: either a client's stream into a service this page
/// runs, or this page's stream out to somebody else's service.
#[wasm_bindgen]
pub struct OnionStream {
    reader: Rc<Mutex<DataReader>>,
    writer: Rc<Mutex<DataWriter>>,
    closed: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl OnionStream {
    /// Await the next bytes the peer sent, or `null` at end of stream.
    /// Reads and writes are independent, so a write can go out while this is
    /// still pending.
    pub fn receive(&self) -> js_sys::Promise {
        let reader = self.reader.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            if closed.get() {
                return Ok(JsValue::NULL);
            }
            let mut buffer = vec![0_u8; SERVICE_READ_BYTES];
            let read = reader
                .lock()
                .await
                .read(&mut buffer)
                .await
                .map_err(|error| js_error("Onion stream read failed", error))?;
            if read == 0 {
                return Ok(JsValue::NULL);
            }
            buffer.truncate(read);
            Ok(js_sys::Uint8Array::from(&buffer[..]).into())
        })
    }

    /// Send text to the peer.
    pub fn send(&self, text: String) -> js_sys::Promise {
        self.write(text.into_bytes())
    }

    /// Send bytes to the peer.
    #[wasm_bindgen(js_name = sendBytes)]
    pub fn send_bytes(&self, payload: Vec<u8>) -> js_sys::Promise {
        self.write(payload)
    }

    /// Close this stream. Any service this page runs keeps running.
    pub fn close(&self) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            if !closed.replace(true) {
                let _ = writer.lock().await.close().await;
            }
            Ok(JsValue::UNDEFINED)
        })
    }
}

impl OnionStream {
    fn write(&self, payload: Vec<u8>) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("The onion stream is closed"));
            }
            let mut writer = writer.lock().await;
            writer
                .write_all(&payload)
                .await
                .map_err(|error| js_error("Onion stream write failed", error))?;
            writer
                .flush()
                .await
                .map_err(|error| js_error("Onion stream write failed", error))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
