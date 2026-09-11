//! Browser client for Snowflake's volunteer-proxy broker.

use crate::error::{Result, TorError};
use crate::global_scope::fetch_with_request;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use tracing::{debug, info};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

const CLIENT_VERSION: &str = "1.0";
const NAT_UNRESTRICTED: &str = "unrestricted";
const NAT_UNKNOWN: &str = "unknown";

/// What a client tells the broker about its NAT, for as long as it lives.
///
/// The broker matches a client that says "unrestricted" with the proxies
/// hardest to reach first, those behind a strict NAT, and one that says
/// anything else only with proxies behind an open one. A browser has no raw
/// UDP to probe its own NAT with, so this client's is always unknown. Like the
/// official client's `NATPolicy` it claims "unrestricted" anyway, which spares
/// the open proxies for clients that need them, until a proxy it was matched
/// with that way cannot be reached. It says "unknown" from then on: behind a
/// restricted NAT, every later strict proxy would fail the same way.
#[derive(Debug, Default)]
pub(crate) struct NatPolicy {
    unrestricted_failed: Cell<bool>,
}

impl NatPolicy {
    pub(crate) fn nat_type(&self) -> &'static str {
        if self.unrestricted_failed.get() {
            NAT_UNKNOWN
        } else {
            NAT_UNRESTRICTED
        }
    }

    /// A proxy matched for `sent` answered, and its data channel never opened.
    /// A broker with no proxy to offer says nothing about the NAT, so only
    /// this moves the policy.
    pub(crate) fn unreachable(&self, sent: &str) {
        if sent == NAT_UNRESTRICTED && !self.unrestricted_failed.replace(true) {
            info!("A proxy matched for an unrestricted NAT was unreachable; asking for open proxies from now on");
        }
    }
}

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
    fn new(offer: String, nat: &'static str, fingerprint: String) -> Self {
        Self {
            offer,
            nat,
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

    /// Exchange a fresh SDP offer for an answer from a volunteer proxy,
    /// telling the broker the client's NAT is `nat`.
    pub async fn negotiate(&self, sdp_offer: String, nat: &'static str) -> Result<String> {
        let request = ClientPollRequest::new(sdp_offer, nat, self.fingerprint.to_string());
        let body = request.encode()?;
        let url = format!("{}/client", self.broker_url.trim_end_matches('/'));

        info!("Contacting Snowflake broker as a client behind a {nat} NAT");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_unrestricted_until_a_proxy_matched_that_way_is_unreachable() {
        let policy = NatPolicy::default();
        assert_eq!(policy.nat_type(), NAT_UNRESTRICTED);

        policy.unreachable(NAT_UNKNOWN);
        assert_eq!(policy.nat_type(), NAT_UNRESTRICTED);

        policy.unreachable(NAT_UNRESTRICTED);
        assert_eq!(policy.nat_type(), NAT_UNKNOWN);

        policy.unreachable(NAT_UNKNOWN);
        assert_eq!(policy.nat_type(), NAT_UNKNOWN);
    }

    #[test]
    fn a_poll_carries_the_nat_type_it_was_given() {
        let body = ClientPollRequest::new("offer".to_string(), NAT_UNKNOWN, "AAAA".to_string())
            .encode()
            .unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"1.0
{"offer":"offer","nat":"unknown","fingerprint":"AAAA"}"#
        );
    }
}
