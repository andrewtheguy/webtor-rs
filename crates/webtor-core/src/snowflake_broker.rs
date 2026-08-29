//! Browser client for Snowflake's volunteer-proxy broker.

use crate::error::{Result, TorError};
use crate::global_scope::fetch_with_request;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

const CLIENT_VERSION: &str = "1.0";

fn broker_error_is_retryable(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("timed out")
        || error.contains("no snowflake proxies")
        || error.contains("no proxies")
        || error.contains("match")
}

#[derive(Debug, Serialize)]
struct ClientPollRequest {
    offer: String,
    nat: &'static str,
    fingerprint: String,
}

impl ClientPollRequest {
    fn new(offer: String, fingerprint: String) -> Self {
        Self {
            offer,
            // This matches the official client's behavior when its NAT type is
            // unknown and permits matching with restricted volunteer proxies.
            nat: "unrestricted",
            fingerprint,
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_string(self)
            .map_err(|error| TorError::Protocol(format!("Failed to encode broker request: {error}")))?;
        Ok(format!("{CLIENT_VERSION}\n{json}").into_bytes())
    }
}

#[derive(Debug, Deserialize)]
struct ClientPollResponse {
    #[serde(default)]
    answer: String,
    #[serde(default)]
    error: String,
}

pub struct BrokerClient<'a> {
    broker_url: &'a str,
    fingerprint: &'a str,
}

impl<'a> BrokerClient<'a> {
    pub fn new(broker_url: &'a str, fingerprint: &'a str) -> Self {
        Self {
            broker_url,
            fingerprint,
        }
    }

    /// Exchange a fresh SDP offer for an answer from a volunteer proxy.
    pub async fn negotiate(&self, sdp_offer: String) -> Result<String> {
        let request = ClientPollRequest::new(sdp_offer, self.fingerprint.to_string());
        let body = request.encode()?;
        let url = format!("{}/client", self.broker_url.trim_end_matches('/'));

        info!("Contacting Snowflake broker");
        debug!("Broker URL: {url}");
        let response_bytes = fetch(&url, &body).await?;
        let response: ClientPollResponse = serde_json::from_slice(&response_bytes)
            .map_err(|error| TorError::Protocol(format!("Invalid broker response: {error}")))?;

        if !response.error.is_empty() {
            return if broker_error_is_retryable(&response.error) {
                Err(TorError::network(format!(
                    "No Snowflake proxy available: {}",
                    response.error
                )))
            } else {
                Err(TorError::tor_protocol(format!(
                    "Snowflake broker error: {}",
                    response.error
                )))
            };
        }
        if response.answer.is_empty() {
            return Err(TorError::network("Snowflake broker returned an empty answer"));
        }

        info!("Received Snowflake proxy answer");
        Ok(response.answer)
    }
}

async fn fetch(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    let options = RequestInit::new();
    options.set_method("POST");
    options.set_mode(RequestMode::Cors);
    options.set_body(&js_sys::Uint8Array::from(body).into());

    let request = Request::new_with_str_and_init(url, &options)
        .map_err(|error| TorError::network(format!("Failed to create broker request: {error:?}")))?;
    request
        .headers()
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(|error| TorError::network(format!("Failed to set broker headers: {error:?}")))?;

    let pending = fetch_with_request(&request).map_err(|error| {
        TorError::Internal(format!("Snowflake broker request could not be started: {error:?}"))
    })?;
    let value = JsFuture::from(pending)
        .await
        .map_err(|error| TorError::network(format!("Snowflake broker request failed: {error:?}")))?;
    let response: Response = value
        .dyn_into()
        .map_err(|_| TorError::Internal("Failed to read Snowflake broker response".to_string()))?;
    if !response.ok() {
        return Err(TorError::network(format!(
            "Snowflake broker returned HTTP {}",
            response.status()
        )));
    }

    let buffer = JsFuture::from(
        response
            .array_buffer()
            .map_err(|error| TorError::network(format!("Failed to read broker response: {error:?}")))?,
    )
    .await
    .map_err(|error| TorError::network(format!("Failed to read broker response: {error:?}")))?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}
