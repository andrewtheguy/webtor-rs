//! Browser binding for pTransfer's anonymous Nostr signaling.
//!
//! The client reaches Nostr relays only as onion services. Bootstrap opens
//! the Snowflake bridge channel and installs a directory; it is then proven
//! against the Tor Project's own onion site before it is handed to the
//! caller, so every `connect` runs on a client that has already completed
//! one full onion rendezvous.

use futures::future::{AbortHandle, Abortable};
use futures::lock::Mutex;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use webtor::{
    relay_socket, LogType, OnionUrl, RelayMessage, RelaySocketReader, RelaySocketWriter, TorClient,
    TorClientOptions,
};

const MAX_NOSTR_MESSAGE_BYTES: usize = 1024 * 1024;
const CONNECTION_TIMEOUT_MS: u64 = 240_000;
/// The Tor Project's website as an onion service. Fetching it exercises the
/// whole onion client: HSDir lookup, introduction, rendezvous and a stream.
const ONION_CHECK_URL: &str =
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/";
const ONION_CHECK_TIMEOUT: Duration = Duration::from_secs(240);
const RELAY_STREAM_TIMEOUT: Duration = Duration::from_secs(240);
const RELAY_WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(30);

fn js_error(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("{context}: {error}"))
}

fn log_tor_progress(message: &str, log_type: LogType) {
    let rendered = JsValue::from_str(&format!("[Anonymous signaling] {message}"));
    match log_type {
        LogType::Error => web_sys::console::error_1(&rendered),
        LogType::Info | LogType::Success => web_sys::console::info_1(&rendered),
    }
}

async fn verify_onion_client(client: &TorClient) -> Result<(), JsValue> {
    log_tor_progress(
        "Verifying the onion client against the Tor Project onion site...",
        LogType::Info,
    );
    let response = webtor::with_timeout(
        ONION_CHECK_TIMEOUT,
        "Onion client verification",
        client.get(ONION_CHECK_URL),
    )
    .await
    .map_err(|error| js_error("Onion client verification request failed", error))?;
    if !response.is_success() {
        return Err(JsValue::from_str(&format!(
            "Onion client verification returned HTTP {}",
            response.status
        )));
    }
    log_tor_progress("Onion client verified.", LogType::Success);
    Ok(())
}

fn signaling_client_options(stun_urls: Vec<String>, websocket_bridge: bool) -> TorClientOptions {
    let options = if websocket_bridge {
        TorClientOptions::snowflake_websocket()
    } else {
        TorClientOptions::snowflake_webrtc(stun_urls)
    };
    options
        .with_connection_timeout(CONNECTION_TIMEOUT_MS)
        .with_on_log(log_tor_progress)
}

/// The relay URL an onion relay socket is allowed to have: `ws://` on a
/// v3 onion host. `wss://` is refused rather than tolerated because a TLS
/// layer over an onion circuit is redundant and this client carries none.
fn parse_onion_relay_url(relay_url: &str) -> Result<OnionUrl, String> {
    let url = OnionUrl::parse(relay_url).map_err(|error| error.to_string())?;
    if url.scheme() != "ws" {
        return Err("Anonymous signaling requires a ws:// relay on a .onion host".to_string());
    }
    Ok(url)
}

#[wasm_bindgen]
pub struct AnonymousSignalingClient {
    client: Arc<TorClient>,
    /// Set by `close`. A `connect` issued afterwards fails at once instead of
    /// bootstrapping the Tor client all over again for a socket nobody wants.
    closed: Rc<Cell<bool>>,
    /// `connect` calls still building their onion circuit, keyed so each can
    /// remove itself. `close` aborts them; a rendezvous that nothing will use
    /// should not run on to completion after the caller is gone.
    pending: Rc<RefCell<HashMap<u64, AbortHandle>>>,
    next_pending: Rc<Cell<u64>>,
}

/// Open a WebSocket to a Nostr relay over a fresh onion stream.
async fn open_relay_socket(
    client: &TorClient,
    relay_url: &str,
) -> Result<AnonymousSignalingSocket, JsValue> {
    let url = parse_onion_relay_url(relay_url).map_err(|error| JsValue::from_str(&error))?;
    log_tor_progress(
        &format!("Opening an onion stream to {relay_url}..."),
        LogType::Info,
    );
    let stream = webtor::with_timeout(
        RELAY_STREAM_TIMEOUT,
        "Nostr relay onion stream",
        client.open_stream(&url),
    )
    .await
    .map_err(|error| js_error("Failed to open onion stream", error))?;

    log_tor_progress(
        &format!("Upgrading the onion stream to WebSocket for {relay_url}..."),
        LogType::Info,
    );
    let (writer, reader) = webtor::with_timeout(
        RELAY_WEBSOCKET_TIMEOUT,
        "Nostr relay WebSocket handshake",
        relay_socket::connect(stream, &url, MAX_NOSTR_MESSAGE_BYTES),
    )
    .await
    .map_err(|error| js_error("Nostr WebSocket handshake failed", error))?;
    log_tor_progress(
        &format!("Connected to Nostr relay {relay_url} through Tor."),
        LogType::Success,
    );

    Ok(AnonymousSignalingSocket {
        writer: Rc::new(Mutex::new(writer)),
        reader: Rc::new(Mutex::new(reader)),
        closed: Rc::new(Cell::new(false)),
    })
}

#[wasm_bindgen]
impl AnonymousSignalingClient {
    /// Bootstrap a Tor client and prove it can reach an onion service.
    ///
    /// `directory_seed` is the directory data a previous `directoryCache()`
    /// returned, or empty. `stun_urls` is used by the WebRTC bridge path;
    /// `websocket_bridge` selects the direct Snowflake WebSocket instead.
    #[wasm_bindgen(js_name = create)]
    pub fn create(
        directory_seed: Option<String>,
        stun_urls: js_sys::Array,
        websocket_bridge: bool,
    ) -> js_sys::Promise {
        future_to_promise(async move {
            console_error_panic_hook::set_once();
            let stun_urls = stun_urls
                .iter()
                .map(|value| {
                    value.as_string().ok_or_else(|| {
                        JsValue::from_str("Anonymous signaling received a non-string STUN URL")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !websocket_bridge && stun_urls.is_empty() {
                return Err(JsValue::from_str(
                    "Anonymous signaling over WebRTC requires at least one STUN URL",
                ));
            }

            let client = TorClient::new(signaling_client_options(stun_urls, websocket_bridge))
                .await
                .map_err(|error| js_error("Failed to initialize webtor", error))?;
            if let Some(encoded) = directory_seed.filter(|value| !value.is_empty()) {
                client.set_directory_seed(&encoded).await;
            }
            client
                .ensure_ready()
                .await
                .map_err(|error| js_error("Failed to establish Tor connection", error))?;
            verify_onion_client(&client).await?;

            Ok(JsValue::from(Self {
                client: Arc::new(client),
                closed: Rc::new(Cell::new(false)),
                pending: Rc::new(RefCell::new(HashMap::new())),
                next_pending: Rc::new(Cell::new(0)),
            }))
        })
    }

    #[wasm_bindgen(js_name = directoryCache)]
    pub fn directory_cache(&self) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            let encoded = client
                .directory_cache_json()
                .await
                .map_err(|error| js_error("Failed to export Tor directory cache", error))?
                .ok_or_else(|| JsValue::from_str("Tor directory cache is unavailable"))?;
            Ok(JsValue::from_str(&encoded))
        })
    }

    /// Open a WebSocket to a Nostr relay at `ws://<address>.onion[/path]`.
    ///
    /// Rejects once `close` has been called, and a call still in flight when
    /// `close` happens is aborted rather than left to finish its rendezvous.
    #[wasm_bindgen(js_name = connect)]
    pub fn connect(&self, relay_url: String) -> js_sys::Promise {
        let client = self.client.clone();
        let closed = self.closed.clone();
        let pending = self.pending.clone();
        let id = self.next_pending.get();
        self.next_pending.set(id.wrapping_add(1));
        let (handle, registration) = AbortHandle::new_pair();
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("Anonymous signaling client is closed"));
            }
            pending.borrow_mut().insert(id, handle);
            let outcome = Abortable::new(open_relay_socket(&client, &relay_url), registration).await;
            pending.borrow_mut().remove(&id);
            match outcome {
                Ok(socket) => socket.map(JsValue::from),
                Err(_aborted) => Err(JsValue::from_str(
                    "Anonymous signaling client closed while connecting",
                )),
            }
        })
    }

    /// Abort every `connect` still in flight, refuse new ones, and tear the
    /// Tor client down.
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

#[wasm_bindgen]
pub struct AnonymousSignalingSocket {
    writer: Rc<Mutex<RelaySocketWriter>>,
    reader: Rc<Mutex<RelaySocketReader>>,
    closed: Rc<Cell<bool>>,
}

#[wasm_bindgen]
impl AnonymousSignalingSocket {
    pub fn send(&self, text: String) -> js_sys::Promise {
        let writer = self.writer.clone();
        let closed = self.closed.clone();
        future_to_promise(async move {
            if closed.get() {
                return Err(JsValue::from_str("WebSocket is closed"));
            }
            if text.len() > MAX_NOSTR_MESSAGE_BYTES {
                return Err(JsValue::from_str("Nostr message exceeds 1 MiB"));
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
                    Ok(Some(RelayMessage::Text(text))) => return Ok(JsValue::from_str(&text)),
                    Ok(Some(RelayMessage::Ping(payload))) => {
                        writer
                            .lock()
                            .await
                            .send_pong(&payload)
                            .await
                            .map_err(|error| js_error("WebSocket pong failed", error))?;
                    }
                    Ok(Some(RelayMessage::Close)) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signaling_uses_snowflake_webrtc_with_caller_stun_urls() {
        let options = signaling_client_options(vec!["stun:example.com".to_string()], false);
        let webtor::BridgeType::SnowflakeWebRtc { stun_urls, .. } = options.bridge else {
            panic!("signaling must use Snowflake WebRTC");
        };
        assert_eq!(stun_urls, vec!["stun:example.com"]);
    }

    #[test]
    fn signaling_uses_the_direct_websocket_bridge_when_asked() {
        let options = signaling_client_options(vec!["stun:example.com".to_string()], true);
        assert!(matches!(
            options.bridge,
            webtor::BridgeType::SnowflakeWebSocket { .. }
        ));
    }

    #[test]
    fn relay_urls_must_be_plain_websockets_on_onion_hosts() {
        assert!(parse_onion_relay_url(
            "ws://nerostrrgb5fhj6dnzhjbgmnkpy2berdlczh6tuh2jsqrjok3j4zoxid.onion"
        )
        .is_ok());
        assert!(parse_onion_relay_url(
            "wss://nerostrrgb5fhj6dnzhjbgmnkpy2berdlczh6tuh2jsqrjok3j4zoxid.onion"
        )
        .is_err());
        assert!(parse_onion_relay_url("ws://relay.example").is_err());
        assert!(parse_onion_relay_url("wss://relay.example").is_err());
    }
}
