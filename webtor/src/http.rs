//! Minimal Tor HTTP GET client used to verify the exit address.

use crate::circuit::CircuitManager;
use crate::error::{Result, TorError};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::collections::HashMap;
use std::sync::Arc;
use subtle_tls::{TlsConfig, TlsConnector};
use tracing::debug;
use url::Url;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) struct TorHttpClient {
    circuit_manager: Arc<CircuitManager>,
}

impl TorHttpClient {
    pub(crate) fn new(circuit_manager: Arc<CircuitManager>) -> Self {
        Self { circuit_manager }
    }

    pub(crate) async fn get(&self, url: Url) -> Result<HttpResponse> {
        let host = url
            .host_str()
            .ok_or_else(|| TorError::http_request("Invalid URL: no host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TorError::http_request("Invalid URL: no port"))?;
        if url.scheme() != "https" {
            return Err(TorError::http_request(
                "Exit verification requires HTTPS",
            ));
        }

        let circuit = self.circuit_manager.ready_circuit().await?;
        let stream = circuit.begin_stream(&host, port).await?;
        let connector = TlsConnector::with_config(TlsConfig {
            skip_verification: false,
            alpn_protocols: vec!["http/1.1".to_string()],
        });
        let mut stream = connector
            .connect(stream, &host)
            .await
            .map_err(|error| TorError::tls(format!("TLS handshake failed: {error}")))?;

        let request = build_get_request(&url, &host);
        execute_request(&mut stream, &request).await
    }
}

fn build_get_request(url: &Url, host: &str) -> Vec<u8> {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let query = url
        .query()
        .map(|value| format!("?{value}"))
        .unwrap_or_default();
    format!(
        "GET {path}{query} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pTransfer\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

async fn execute_request<S>(stream: &mut S, request: &[u8]) -> Result<HttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(|error| TorError::http_request(format!("Failed to write request: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| TorError::http_request(format!("Failed to flush request: {error}")))?;

    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| TorError::http_request(format!("Failed to read response: {error}")))?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > MAX_RESPONSE_BYTES {
            return Err(TorError::http_request(
                "Exit verification response exceeds 1 MiB",
            ));
        }
    }

    parse_response(&response)
}

fn parse_response(data: &[u8]) -> Result<HttpResponse> {
    let header_end = find_subsequence(data, b"\r\n\r\n")
        .ok_or_else(|| TorError::http_request("Invalid HTTP response: missing header boundary"))?;
    let header_text = std::str::from_utf8(&data[..header_end])
        .map_err(|error| TorError::http_request(format!("Invalid HTTP headers: {error}")))?;
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| TorError::http_request("Invalid HTTP response: missing status"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| TorError::http_request("Invalid HTTP status line"))?
        .parse::<u16>()
        .map_err(|error| TorError::http_request(format!("Invalid HTTP status: {error}")))?;

    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let mut body = data[header_end + 4..].to_vec();

    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        body = decode_chunked_body(&body)?;
    } else if let Some(length) = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        if body.len() < length {
            return Err(TorError::http_request(
                "HTTP response ended before Content-Length",
            ));
        }
        body.truncate(length);
    }

    debug!("Parsed exit verification response with status {}", status);
    Ok(HttpResponse { status, body })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut remaining = body;

    loop {
        let line_end = find_subsequence(remaining, b"\r\n")
            .ok_or_else(|| TorError::http_request("Incomplete HTTP chunk size"))?;
        let size_text = std::str::from_utf8(&remaining[..line_end])
            .map_err(|_| TorError::http_request("HTTP chunk size is not UTF-8"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| TorError::http_request(format!("Invalid HTTP chunk size: {error}")))?;
        remaining = &remaining[line_end + 2..];

        if size == 0 {
            return Ok(decoded);
        }
        if remaining.len() < size + 2 || &remaining[size..size + 2] != b"\r\n" {
            return Err(TorError::http_request("Incomplete HTTP chunk"));
        }
        decoded.extend_from_slice(&remaining[..size]);
        if decoded.len() > MAX_RESPONSE_BYTES {
            return Err(TorError::http_request(
                "Decoded exit verification response exceeds 1 MiB",
            ));
        }
        remaining = &remaining[size + 2..];
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|error| TorError::serialization(format!("Invalid JSON response: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_only_supported_request() {
        let url = Url::parse("https://check.torproject.org/api/ip?format=json").unwrap();
        let request = String::from_utf8(build_get_request(&url, "check.torproject.org")).unwrap();
        assert!(request.starts_with("GET /api/ip?format=json HTTP/1.1\r\n"));
        assert!(request.contains("Connection: close\r\n"));
    }

    #[test]
    fn parses_chunked_json() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"x\":1}\r\n0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert!(response.is_success());
        assert_eq!(response.json::<serde_json::Value>().unwrap()["x"], 1);
    }

    #[test]
    fn rejects_partial_chunks() {
        let error = decode_chunked_body(b"5\r\nHi").unwrap_err();
        assert!(error.to_string().contains("Incomplete HTTP chunk"));
    }
}
