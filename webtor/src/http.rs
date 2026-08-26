//! Minimal HTTP/1.1 codec for plain requests over an onion stream. It backs
//! the onion-service check and any other request a caller issues to an
//! onion site; the onion circuit already authenticates and encrypts it.

use crate::error::{Result, TorError};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::collections::HashMap;
use crate::onion_url::OnionUrl;
use tracing::debug;

/// A whole response is buffered in memory before the caller sees it, so this
/// bounds what one request can cost. Callers streaming anything larger have to
/// range-request it in pieces.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Headers the client sets from the request itself. A caller-supplied copy
/// would either be ignored or contradict the framing actually on the wire, so
/// supplying one is an error rather than a silent override.
const RESERVED_HEADERS: [&str; 4] = [
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
];

pub struct HttpRequest {
    pub method: String,
    pub url: OnionUrl,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn get(url: OnionUrl) -> Self {
        Self {
            method: "GET".to_string(),
            url,
            headers: vec![("Accept".to_string(), "*/*".to_string())],
            body: None,
        }
    }
}

pub(crate) fn build_request(request: &HttpRequest, host: &str) -> Result<Vec<u8>> {
    let method = request.method.to_ascii_uppercase();
    if method.is_empty() || method.bytes().any(|byte| !byte.is_ascii_alphabetic()) {
        return Err(TorError::http_request(format!(
            "Invalid HTTP method: {}",
            request.method
        )));
    }
    let target = request.url.path_and_query();

    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pTransfer\r\nConnection: close\r\n");
    for (name, value) in &request.headers {
        // A newline in either half would let a caller inject headers, or a
        // whole second request, into the stream.
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(TorError::http_request(format!(
                "Header {name} contains a line break"
            )));
        }
        if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(TorError::http_request(format!(
                "Header {name} is set by the client and cannot be supplied"
            )));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    // Every request carries a length, so a body-bearing method is framed and a
    // bodyless one is unambiguous to servers that would otherwise wait.
    if let Some(body) = &request.body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");

    let mut wire = head.into_bytes();
    if let Some(body) = &request.body {
        wire.extend_from_slice(body);
    }
    Ok(wire)
}

pub(crate) async fn execute_request<S>(stream: &mut S, request: &[u8]) -> Result<HttpResponse>
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
            return Err(TorError::http_request("HTTP response exceeds 8 MiB"));
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

    debug!("Parsed HTTP response with status {}", status);
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
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
            return Err(TorError::http_request("Decoded HTTP response exceeds 8 MiB"));
        }
        remaining = &remaining[size + 2..];
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Header names are lowercased on parse, so lookups are case-insensitive.
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|error| TorError::serialization(format!("Response is not UTF-8: {error}")))
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
    fn builds_a_get_request() {
        let url = OnionUrl::parse("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/api/ip?format=json").unwrap();
        let request =
            String::from_utf8(build_request(&HttpRequest::get(url), "check.torproject.org").unwrap())
                .unwrap();
        assert!(request.starts_with("GET /api/ip?format=json HTTP/1.1\r\n"));
        assert!(request.contains("Connection: close\r\n"));
        assert!(!request.contains("Content-Length"));
    }

    #[test]
    fn builds_a_body_request_with_a_length() {
        let request = HttpRequest {
            method: "put".to_string(),
            url: OnionUrl::parse("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/upload").unwrap(),
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(b"hello".to_vec()),
        };
        let wire = String::from_utf8(build_request(&request, "example.org").unwrap()).unwrap();
        assert!(wire.starts_with("PUT /upload HTTP/1.1\r\n"));
        assert!(wire.contains("Content-Type: text/plain\r\n"));
        assert!(wire.contains("Content-Length: 5\r\n"));
        assert!(wire.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn rejects_header_injection() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: OnionUrl::parse("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/").unwrap(),
            headers: vec![("X-Evil".to_string(), "a\r\nX-Injected: 1".to_string())],
            body: None,
        };
        let error = build_request(&request, "example.org").unwrap_err();
        assert!(error.to_string().contains("line break"));
    }

    #[test]
    fn rejects_client_owned_headers() {
        let request = HttpRequest {
            method: "POST".to_string(),
            url: OnionUrl::parse("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/").unwrap(),
            headers: vec![("content-length".to_string(), "9".to_string())],
            body: Some(b"hello".to_vec()),
        };
        let error = build_request(&request, "example.org").unwrap_err();
        assert!(error.to_string().contains("cannot be supplied"));
    }

    #[test]
    fn parses_chunked_json() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"x\":1}\r\n0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert!(response.is_success());
        assert_eq!(response.json::<serde_json::Value>().unwrap()["x"], 1);
    }

    #[test]
    fn exposes_response_headers() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/a\r\nContent-Length: 0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers().get("location").map(String::as_str),
            Some("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/a")
        );
    }

    #[test]
    fn rejects_partial_chunks() {
        let error = decode_chunked_body(b"5\r\nHi").unwrap_err();
        assert!(error.to_string().contains("Incomplete HTTP chunk"));
    }
}
