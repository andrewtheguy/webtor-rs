//! Browser binding: a Tor client for `http://` and `ws://` onion services.
//!
//! Everything the client reaches is a v3 onion service. No circuit is built to
//! an exit, so there is no clearnet TLS to terminate inside WASM and no server
//! certificate to check: the onion address commits to the service key and the
//! circuit is encrypted end to end. `https://` and `wss://` are therefore
//! refused rather than tolerated.

mod console_log;
mod options;

use futures::future::{AbortHandle, Abortable};
use futures::lock::Mutex;
use options::error as option_error;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use futures::{AsyncReadExt, AsyncWriteExt};
use webtor::{
    onion_websocket, DataReader, DataWriter, HttpRequest, HttpResponse, LogType, OnionService,
    OnionServiceOptions, OnionUrl, TorClient, TorClientOptions, WebSocketMessage,
    WebSocketReader, WebSocketWriter,
};

/// The Tor Project's own onion site. Fetching it exercises the whole client —
/// HSDir lookup, introduction, rendezvous and a stream — which is what the
/// `verifyOnion` option asks for when it is set to `true`.
const DEFAULT_VERIFY_URL: &str =
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/";

const DEFAULT_CONNECTION_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 240_000;
const DEFAULT_VERIFY_TIMEOUT_MS: u64 = 240_000;
/// Time for the onion stream plus the RFC 6455 upgrade on it.
const DEFAULT_WEBSOCKET_TIMEOUT_MS: u64 = 240_000;
const DEFAULT_MAX_MESSAGE_BYTES: u64 = 1024 * 1024;
const DEFAULT_LOG_PREFIX: &str = "[webtor]";

const CLIENT_OPTIONS: &[&str] = &[
    "bridge",
    "stunUrls",
    "directorySeed",
    "connectionTimeoutMs",
    "verifyOnion",
    "log",
    "logPrefix",
];
const REQUEST_OPTIONS: &[&str] = &["method", "headers", "body", "timeoutMs"];
const WEBSOCKET_OPTIONS: &[&str] = &["maxMessageBytes", "timeoutMs"];
const SERVICE_OPTIONS: &[&str] = &["introPoints"];

/// Introduction points a published service establishes, and the most it will
/// accept being asked for: past a handful they cost circuits without making
/// the service easier to reach.
const DEFAULT_INTRO_POINTS: u64 = 3;
const MAX_INTRO_POINTS: u64 = 6;
/// How much of one client's stream a single `receive()` returns.
const SERVICE_READ_BYTES: usize = 8192;

fn js_error(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{context}: {error}"))
}

fn console_logger(prefix: String) -> impl Fn(&str, LogType) + Send + Sync + 'static {
    move |message: &str, log_type: LogType| {
        let rendered = JsValue::from_str(&format!("{prefix} {message}"));
        match log_type {
            LogType::Error => web_sys::console::error_1(&rendered),
            LogType::Info | LogType::Success => web_sys::console::info_1(&rendered),
        }
    }
}

/// A log sink shared by the Tor client and this binding, so progress from
/// both sides of the boundary lands in one place with one prefix.
type Logger = Arc<dyn Fn(&str, LogType) + Send + Sync>;

/// What `create` was told to do, once its option bag has been checked.
struct ClientConfig {
    options: TorClientOptions,
    directory_seed: Option<String>,
    verify_url: Option<String>,
    log: Logger,
}

fn read_client_config(raw: Option<js_sys::Object>) -> Result<ClientConfig, JsValue> {
    let bag = options::bag(raw, "WebtorClient.create")?;
    options::reject_unknown_keys(&bag, "WebtorClient.create", CLIENT_OPTIONS)?;
    let what = "WebtorClient.create";

    let bridge = options::string(&bag, "bridge", what)?.unwrap_or_else(|| "websocket".to_string());
    let stun_urls = options::string_array(&bag, "stunUrls", what)?.unwrap_or_default();
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
            TorClientOptions::snowflake_websocket()
        }
        // A volunteer Snowflake proxy, brokered over HTTPS. Harder to block,
        // and it needs a STUN server to find its own address.
        "webrtc" => {
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

    let log: Logger = if options::boolean(&bag, "log", what)?.unwrap_or(true) {
        let prefix =
            options::string(&bag, "logPrefix", what)?.unwrap_or_else(|| DEFAULT_LOG_PREFIX.into());
        Arc::new(console_logger(prefix))
    } else {
        Arc::new(|_: &str, _| {})
    };
    let for_client = log.clone();
    options = options.with_on_log(move |message, log_type| for_client(message, log_type));

    // `verifyOnion` is either a flag choosing the default target or the URL.
    let verify = options::raw(&bag, "verifyOnion");
    let verify_url = if verify.is_undefined() || verify.is_null() {
        None
    } else if let Some(flag) = verify.as_bool() {
        flag.then(|| DEFAULT_VERIFY_URL.to_string())
    } else if let Some(url) = verify.as_string() {
        Some(url)
    } else {
        return Err(option_error(
            "WebtorClient.create option \"verifyOnion\" must be a boolean or a URL string",
        ));
    };

    Ok(ClientConfig {
        options,
        directory_seed: options::string(&bag, "directorySeed", what)?
            .filter(|seed| !seed.is_empty()),
        verify_url,
        log,
    })
}

/// Prove the client can complete a rendezvous before it is handed over, so a
/// caller that only watches the log channel gets a verdict either way.
async fn verify_onion_client(client: &TorClient, url: &str, log: &Logger) -> Result<(), JsValue> {
    log(
        &format!("Verifying the onion client against {url} ..."),
        LogType::Info,
    );
    let outcome = webtor::with_timeout(
        Duration::from_millis(DEFAULT_VERIFY_TIMEOUT_MS),
        "Onion client verification",
        client.get(url),
    )
    .await;
    let status = match outcome {
        Ok(response) if response.is_success() => response.status,
        Ok(response) => {
            let message = format!(
                "Onion client verification against {url} failed: answered HTTP {}",
                response.status
            );
            log(&message, LogType::Error);
            return Err(JsValue::from_str(&message));
        }
        Err(error) => {
            let message = format!("Onion client verification against {url} failed: {error}");
            log(&message, LogType::Error);
            return Err(JsValue::from_str(&message));
        }
    };
    log(
        &format!("Onion client verified: {url} answered HTTP {status}."),
        LogType::Success,
    );
    Ok(())
}

/// Whether `host` is a v3 onion address.
#[wasm_bindgen(js_name = isOnionHost)]
pub fn is_onion_host(host: &str) -> bool {
    webtor::is_onion_host(host)
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
    /// - `directorySeed`: a previous `directoryCache()`, to skip downloading
    ///   the directory over the bridge.
    /// - `connectionTimeoutMs`: bootstrap budget, default 300000.
    /// - `verifyOnion`: `true`, or a `http://…onion/` URL, to prove the client
    ///   can complete a rendezvous before `create` resolves. Default `false`.
    /// - `log`: write progress to the console, default `true`.
    /// - `logPrefix`: default `"[webtor]"`.
    #[wasm_bindgen(js_name = create)]
    pub fn create(options: Option<js_sys::Object>) -> js_sys::Promise {
        future_to_promise(async move {
            console_error_panic_hook::set_once();
            console_log::install();
            let config = read_client_config(options)?;
            let log = config.log;

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
            if let Some(url) = &config.verify_url {
                verify_onion_client(&client, url, &log).await?;
            }

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
    /// `Uint8Array`) and `timeoutMs` (default 240000).
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
            };
            let timeout = options::count(&bag, "timeoutMs", "fetch")?
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
            let response = webtor::with_timeout(
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
    /// Options: `maxMessageBytes` (default 1048576) and `timeoutMs` (default
    /// 240000, covering the onion stream and the upgrade on it).
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
            let socket = webtor::with_timeout(
                Duration::from_millis(timeout),
                "Onion WebSocket",
                async {
                    let stream = client.open_stream(&parsed).await?;
                    onion_websocket::connect(stream, &parsed, max_message_bytes).await
                },
            )
            .await
            .map_err(|error| js_error("Onion WebSocket failed", error))?;
            log(&format!("Connected to {url} through Tor."), LogType::Success);

            let (writer, reader) = socket;
            Ok(JsValue::from(OnionWebSocket {
                writer: Rc::new(Mutex::new(writer)),
                reader: Rc::new(Mutex::new(reader)),
                max_message_bytes,
                closed: Rc::new(Cell::new(false)),
            }))
        })
    }

    /// Publish a v3 onion service from this client.
    ///
    /// The identity key is generated in the page and never stored, so every
    /// call yields a new `.onion` address that lives as long as the returned
    /// service. Resolves once an HSDir has accepted the descriptor, which is
    /// when clients can reach it.
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

    /// Response headers as a plain object; names are lowercased.
    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> js_sys::Object {
        let object = js_sys::Object::new();
        for (name, value) in self.inner.headers() {
            set(&object, name, &JsValue::from_str(value));
        }
        object
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
    max_message_bytes: usize,
    closed: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl OnionWebSocket {
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
                    Ok(JsValue::from(OnionServiceStream {
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

/// One client's stream to a service this page runs.
#[wasm_bindgen]
pub struct OnionServiceStream {
    reader: Rc<Mutex<DataReader>>,
    writer: Rc<Mutex<DataWriter>>,
    closed: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl OnionServiceStream {
    /// Await the next bytes the client sent, or `null` at end of stream.
    /// Reads and writes are independent, so a reply can go out while this is
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
                .map_err(|error| js_error("Onion service read failed", error))?;
            if read == 0 {
                return Ok(JsValue::NULL);
            }
            buffer.truncate(read);
            Ok(js_sys::Uint8Array::from(&buffer[..]).into())
        })
    }

    /// Send text back to the client.
    pub fn send(&self, text: String) -> js_sys::Promise {
        self.write(text.into_bytes())
    }

    /// Send bytes back to the client.
    #[wasm_bindgen(js_name = sendBytes)]
    pub fn send_bytes(&self, payload: Vec<u8>) -> js_sys::Promise {
        self.write(payload)
    }

    /// Close this client's stream. The service keeps running.
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

impl OnionServiceStream {
    fn write(&self, payload: Vec<u8>) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("The onion service stream is closed"));
            }
            let mut writer = writer.lock().await;
            writer
                .write_all(&payload)
                .await
                .map_err(|error| js_error("Onion service write failed", error))?;
            writer
                .flush()
                .await
                .map_err(|error| js_error("Onion service write failed", error))?;
            Ok(JsValue::UNDEFINED)
        })
    }
}
