use async_tungstenite::tungstenite::{protocol::Message, Error as WebSocketError};
use futures::lock::Mutex;
use futures::StreamExt;
use serde::Deserialize;
use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use subtle_tls::{TlsConfig, TlsConnector, TlsStream, TlsVersion};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use webtor::config::LogType;
use webtor::{DataStream, TorClient, TorClientOptions};

const MAX_NOSTR_MESSAGE_BYTES: usize = 1024 * 1024;
const CONNECTION_TIMEOUT_MS: u64 = 240_000;
const CIRCUIT_TIMEOUT_MS: u64 = 120_000;
const TOR_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const TOR_CHECK_URL: &str = "https://check.torproject.org/api/ip";

#[derive(Deserialize)]
struct TorCheckResponse {
    #[serde(rename = "IsTor")]
    is_tor: bool,
}

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

async fn verify_tor_exit(client: &TorClient) -> Result<(), JsValue> {
    log_tor_progress("Verifying the Tor exit...", LogType::Info);
    let response = webtor::with_timeout(
        TOR_CHECK_TIMEOUT,
        "Tor exit verification",
        client.get(TOR_CHECK_URL),
    )
    .await
    .map_err(|error| js_error("Tor exit verification request failed", error))?;

    if !response.is_success() {
        return Err(JsValue::from_str(&format!(
            "Tor exit verification returned HTTP {}",
            response.status
        )));
    }

    let check = response
        .json::<TorCheckResponse>()
        .map_err(|error| js_error("Tor exit verification response was invalid", error))?;
    if !check.is_tor {
        return Err(JsValue::from_str(
            "Tor exit verification failed: Tor Check did not recognize the connection as Tor",
        ));
    }

    log_tor_progress("Tor exit verified.", LogType::Success);
    Ok(())
}

type RelayTlsStream = TlsStream<DataStream>;
type RelayWriter = async_tungstenite::WebSocketSender<RelayTlsStream>;
type RelayReader = async_tungstenite::WebSocketReceiver<RelayTlsStream>;

async fn connect_tls(client: &TorClient, url: &Url) -> Result<RelayTlsStream, JsValue> {
    let host = url
        .host_str()
        .ok_or_else(|| JsValue::from_str("Relay URL has no host"))?;
    let tls13_config = TlsConfig {
        skip_verification: false,
        alpn_protocols: vec!["http/1.1".to_string()],
        version: TlsVersion::Tls13,
    };
    let tls13_connector = TlsConnector::with_config(tls13_config);
    let stream = client
        .open_stream(url)
        .await
        .map_err(|error| js_error("Failed to open Tor stream", error))?;

    tls13_connector
        .connect(stream, host)
        .await
        .map_err(|error| js_error("Relay TLS 1.3 failed", error))
}

#[wasm_bindgen]
pub struct AnonymousSignalingClient {
    client: Arc<TorClient>,
}

#[wasm_bindgen]
impl AnonymousSignalingClient {
    #[wasm_bindgen(js_name = create)]
    pub fn create() -> js_sys::Promise {
        future_to_promise(async move {
            console_error_panic_hook::set_once();
            let options = TorClientOptions::direct_snowflake_websocket()
                .with_connection_timeout(CONNECTION_TIMEOUT_MS)
                .with_circuit_timeout(CIRCUIT_TIMEOUT_MS)
                .with_create_circuit_early(false)
                .with_on_log(log_tor_progress)
                .with_circuit_update_interval(None);
            let client = TorClient::new(options)
                .await
                .map_err(|error| js_error("Failed to initialize webtor", error))?;
            client
                .ensure_ready()
                .await
                .map_err(|error| js_error("Failed to establish Tor connection", error))?;
            client
                .wait_for_circuit()
                .await
                .map_err(|error| js_error("Tor circuit did not become ready", error))?;
            verify_tor_exit(&client).await?;

            Ok(JsValue::from(Self {
                client: Arc::new(client),
            }))
        })
    }

    #[wasm_bindgen(js_name = connect)]
    pub fn connect(&self, relay_url: String) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            let url =
                Url::parse(&relay_url).map_err(|error| js_error("Invalid relay URL", error))?;
            if url.scheme() != "wss" {
                return Err(JsValue::from_str(
                    "Anonymous signaling requires a secure wss:// relay",
                ));
            }

            let tls_stream = connect_tls(&client, &url).await?;
            let (socket, _) = async_tungstenite::client_async(url.as_str(), tls_stream)
                .await
                .map_err(|error| js_error("Nostr WebSocket handshake failed", error))?;
            let (writer, reader) = socket.split();

            Ok(JsValue::from(AnonymousSignalingSocket {
                writer: Rc::new(Mutex::new(writer)),
                reader: Rc::new(Mutex::new(reader)),
                closed: Rc::new(Cell::new(false)),
            }))
        })
    }

    pub fn close(&self) -> js_sys::Promise {
        let client = self.client.clone();
        future_to_promise(async move {
            client.close().await;
            Ok(JsValue::UNDEFINED)
        })
    }
}

#[wasm_bindgen]
pub struct AnonymousSignalingSocket {
    writer: Rc<Mutex<RelayWriter>>,
    reader: Rc<Mutex<RelayReader>>,
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
                .send(Message::Text(text.into()))
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
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > MAX_NOSTR_MESSAGE_BYTES {
                            return Err(JsValue::from_str("Nostr message exceeds 1 MiB"));
                        }
                        return Ok(JsValue::from_str(text.as_str()));
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        writer
                            .lock()
                            .await
                            .send(Message::Pong(payload))
                            .await
                            .map_err(|error| js_error("WebSocket pong failed", error))?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(frame))) => {
                        closed.set(true);
                        let _ = writer.lock().await.send(Message::Close(frame)).await;
                        return Ok(JsValue::NULL);
                    }
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Frame(_))) => {
                        return Err(JsValue::from_str(
                            "Nostr relay sent a non-text WebSocket message",
                        ));
                    }
                    Some(Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed))
                    | None => {
                        closed.set(true);
                        return Ok(JsValue::NULL);
                    }
                    Some(Err(error)) => {
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
                let _ = writer.lock().await.close(None).await;
            }
            Ok(JsValue::UNDEFINED)
        })
    }
}
