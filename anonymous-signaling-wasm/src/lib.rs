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
use webtor::{DataStream, LogType, TorClient, TorClientOptions, TorError};

const MAX_NOSTR_MESSAGE_BYTES: usize = 1024 * 1024;
const CONNECTION_TIMEOUT_MS: u64 = 240_000;
const TOR_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const TOR_CHECK_URL: &str = "https://check.torproject.org/api/ip";
/// Echoes any frame back verbatim, so a returned nonce is proof of a working
/// round trip. It must serve TLS 1.3, since subtle-tls offers nothing older:
/// `ws.postman-echo.com`, for one, is TLS 1.2 only and drops the connection
/// mid-handshake. This endpoint opens with an unsolicited greeting frame,
/// which the nonce comparison below skips.
const WEBSOCKET_CHECK_URL: &str = "wss://echo.websocket.org/";
const WEBSOCKET_CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_TCP_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_TLS_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Runs immediately after the exit is verified and before the caller opens any
/// relay stream. Proves the verified exit can carry a single `wss` stream, so
/// a bridge that cannot carry any WebSocket stops looking exactly like Nostr
/// relays that happen to be unreachable — today both fail the same way, with
/// every relay stream timing out and nothing to tell the two apart.
async fn verify_websocket_stream(client: &TorClient) -> Result<(), JsValue> {
    log_tor_progress("Verifying a WebSocket stream over Tor...", LogType::Info);
    let url = Url::parse(WEBSOCKET_CHECK_URL)
        .map_err(|error| js_error("WebSocket verification URL is invalid", error))?;

    let tls_stream = connect_tls(client, &url).await?;
    let (socket, _) = webtor::with_timeout(
        RELAY_WEBSOCKET_TIMEOUT,
        "WebSocket verification handshake",
        async {
            async_tungstenite::client_async(url.as_str(), tls_stream)
                .await
                .map_err(|error| TorError::websocket_connection(error.to_string()))
        },
    )
    .await
    .map_err(|error| js_error("WebSocket verification handshake failed", error))?;

    let (mut writer, mut reader) = socket.split();
    let nonce = format!("ptransfer-websocket-check-{}", js_sys::Math::random());
    webtor::with_timeout(
        WEBSOCKET_CHECK_TIMEOUT,
        "WebSocket verification echo",
        async {
            writer
                .send(Message::Text(nonce.clone().into()))
                .await
                .map_err(|error| TorError::websocket_connection(error.to_string()))?;
            while let Some(message) = reader.next().await {
                match message
                    .map_err(|error| TorError::websocket_connection(error.to_string()))?
                {
                    Message::Text(text) if text.as_str() == nonce => return Ok(()),
                    Message::Ping(payload) => {
                        writer.send(Message::Pong(payload)).await.map_err(|error| {
                            TorError::websocket_connection(error.to_string())
                        })?;
                    }
                    Message::Close(_) => break,
                    // A greeting or any other frame is not the echo; keep reading.
                    _ => continue,
                }
            }
            Err(TorError::websocket_connection(
                "the echo endpoint closed before returning the nonce".to_string(),
            ))
        },
    )
    .await
    .map_err(|error| js_error("WebSocket verification failed", error))?;

    let _ = writer.send(Message::Close(None)).await;
    log_tor_progress("WebSocket over Tor verified.", LogType::Success);
    Ok(())
}

type RelayTlsStream = TlsStream<DataStream>;
type RelayWriter = async_tungstenite::WebSocketSender<RelayTlsStream>;
type RelayReader = async_tungstenite::WebSocketReceiver<RelayTlsStream>;

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

async fn connect_tls(client: &TorClient, url: &Url) -> Result<RelayTlsStream, JsValue> {
    let host = url
        .host_str()
        .ok_or_else(|| JsValue::from_str("Relay URL has no host"))?;
    log_tor_progress(
        &format!("Opening a Tor stream to {host}..."),
        LogType::Info,
    );
    let tls13_config = TlsConfig {
        skip_verification: false,
        alpn_protocols: vec!["http/1.1".to_string()],
        // subtle-tls carries TLS 1.2 again, but nothing here negotiates it:
        // every retained path requires TLS 1.3.
        version: TlsVersion::Tls13,
    };
    let tls13_connector = TlsConnector::with_config(tls13_config);
    let stream = webtor::with_timeout(
        RELAY_TCP_TIMEOUT,
        "Nostr relay Tor stream",
        client.open_stream(url),
    )
    .await
    .map_err(|error| js_error("Failed to open Tor stream", error))?;
    log_tor_progress(
        &format!("Tor stream to {host} opened; starting TLS..."),
        LogType::Info,
    );

    let tls_stream = webtor::with_timeout(RELAY_TLS_TIMEOUT, "Nostr relay TLS handshake", async {
        tls13_connector
            .connect(stream, host)
            .await
            .map_err(|error| TorError::tls(error.to_string()))
    })
    .await
    .map_err(|error| js_error("Relay TLS 1.3 failed", error))?;
    log_tor_progress(
        &format!("TLS established with {host}."),
        LogType::Success,
    );
    Ok(tls_stream)
}

#[wasm_bindgen]
pub struct AnonymousSignalingClient {
    client: Arc<TorClient>,
}

#[wasm_bindgen]
impl AnonymousSignalingClient {
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
            // The direct WebSocket bridge dials Snowflake itself, so it needs
            // no STUN; the WebRTC proxy path cannot negotiate without one.
            if !websocket_bridge && stun_urls.is_empty() {
                return Err(JsValue::from_str(
                    "Anonymous signaling over WebRTC requires at least one STUN URL",
                ));
            }
            let client = TorClient::new(signaling_client_options(stun_urls, websocket_bridge))
                .await
                .map_err(|error| js_error("Failed to initialize webtor", error))?;
            // Bootstrap starts from this directory data when it is present and
            // still valid; otherwise webtor downloads a consensus itself.
            if let Some(encoded) = directory_seed.filter(|value| !value.is_empty()) {
                client.set_directory_seed(&encoded).await;
            }
            client
                .ensure_ready()
                .await
                .map_err(|error| js_error("Failed to establish Tor connection", error))?;
            verify_tor_exit(&client).await?;
            // Widen the trust store before any relay connection. Not fatal:
            // the embedded roots still reach part of the network, so a failed
            // fetch narrows what is reachable rather than breaking signaling.
            if let Err(error) = client.load_ca_bundle().await {
                log_tor_progress(
                    &format!(
                        "Could not load the CA bundle; only the embedded roots are trusted: {error}"
                    ),
                    LogType::Error,
                );
            }
            verify_websocket_stream(&client).await?;

            Ok(JsValue::from(Self {
                client: Arc::new(client),
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
            log_tor_progress(
                &format!("Upgrading the Tor stream to WebSocket for {relay_url}..."),
                LogType::Info,
            );
            let (socket, _) = webtor::with_timeout(
                RELAY_WEBSOCKET_TIMEOUT,
                "Nostr relay WebSocket handshake",
                async {
                    async_tungstenite::client_async(url.as_str(), tls_stream)
                        .await
                        .map_err(|error| TorError::websocket_connection(error.to_string()))
                },
            )
                .await
                .map_err(|error| js_error("Nostr WebSocket handshake failed", error))?;
            log_tor_progress(
                &format!("Connected to Nostr relay {relay_url} through Tor."),
                LogType::Success,
            );
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
