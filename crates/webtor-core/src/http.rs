//! Minimal HTTP/1.1 codec for plain requests over an onion stream. The onion
//! circuit already authenticates the service and encrypts the exchange, so
//! what goes over it is ordinary cleartext HTTP.

use crate::error::{Result, TorError};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::onion_url::OnionUrl;
use tracing::debug;

/// A whole response is buffered in memory before the caller sees it, so a
/// request carries a bound on what it may cost. This is the bound when the
/// caller names none; one expecting more, a gateway serving a download, say,
/// raises it for that request rather than for every request.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Sent when the caller supplies no `User-Agent` of its own.
const DEFAULT_USER_AGENT: &str = concat!("webtor/", env!("CARGO_PKG_VERSION"));

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
    /// The most the response, headers and body together, may occupy before
    /// the request fails rather than buffer more.
    pub max_response_bytes: usize,
}

impl HttpRequest {
    pub fn get(url: OnionUrl) -> Self {
        Self {
            method: "GET".to_string(),
            url,
            headers: vec![("Accept".to_string(), "*/*".to_string())],
            body: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
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

    let mut head =
        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    // A caller who names no User-Agent still gets one: a server that varies on
    // it should see a stable, honest value rather than none at all.
    if !request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    {
        head.push_str(&format!("User-Agent: {DEFAULT_USER_AGENT}\r\n"));
    }
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

pub(crate) async fn execute_request<S>(
    stream: &mut S,
    request: &[u8],
    max_response_bytes: usize,
) -> Result<HttpResponse>
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
    let mut framing = None;
    // How much of `response` the chunked scan has already looked at, so a
    // long body is scanned once rather than once per read.
    let mut scanned = 0;
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|error| TorError::http_request(format!("Failed to read response: {error}")))?;
        if count == 0 {
            break;
        }
        // Checked before appending, so the buffer never holds more than the
        // limit, not even for the one read that crosses it.
        if count > max_response_bytes - response.len() {
            return Err(TorError::http_request(format!(
                "HTTP response exceeds the {max_response_bytes}-byte limit on a response"
            )));
        }
        response.extend_from_slice(&buffer[..count]);
        if framing.is_none() {
            framing = split_headers(&response)
                .map(|(header_end, headers)| body_framing(header_end, &headers))
                .transpose()?;
        }
        if response_is_complete(&framing, &response, &mut scanned) {
            break;
        }
    }

    parse_response(&response)
}

/// How a response's body ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    /// Complete once the response reaches this many bytes in total.
    Length(usize),
    /// Complete once the terminating zero-length chunk arrives.
    Chunked,
    /// Framed by the stream closing, so nothing but EOF ends it.
    UntilClose,
}

/// How the body ends, from every framing header in arrival order, RFC 7230
/// §3.3.3. `Transfer-Encoding` wins over `Content-Length`, and only a *final*
/// `chunked` coding frames the body; any other final coding leaves the close
/// to end it. A `Content-Length` counts only when every value given, across
/// repeated headers and comma-separated lists alike, parses and agrees:
/// conflicting lengths are how a response is smuggled past a parser that
/// reads one and a server that honours another, so they are refused.
fn body_framing(header_end: usize, headers: &[(String, String)]) -> Result<BodyFraming> {
    if let Some(last) = header_list(headers, "transfer-encoding").last() {
        return Ok(if last.eq_ignore_ascii_case("chunked") {
            BodyFraming::Chunked
        } else {
            BodyFraming::UntilClose
        });
    }
    let mut lengths = header_list(headers, "content-length");
    let Some(first) = lengths.next() else {
        return Ok(BodyFraming::UntilClose);
    };
    let length = first.parse::<usize>().map_err(|_| {
        TorError::http_request(format!("Invalid HTTP Content-Length: {first}"))
    })?;
    if lengths.any(|other| other.parse::<usize>().ok() != Some(length)) {
        return Err(TorError::http_request(
            "Conflicting HTTP Content-Length values",
        ));
    }
    (header_end + 4)
        .checked_add(length)
        .map(BodyFraming::Length)
        .ok_or_else(|| TorError::http_request(format!("HTTP Content-Length too large: {length}")))
}

/// Whether the response is whole, so that reading can stop without waiting
/// for the peer to close.
///
/// Waiting for the close is not just slower: `tor-proto` ends every stream an
/// application closes with `END MISC`, which arrives as an error rather than
/// as end of stream, so a complete response would be thrown away.
fn response_is_complete(
    framing: &Option<BodyFraming>,
    response: &[u8],
    scanned: &mut usize,
) -> bool {
    match framing {
        Some(BodyFraming::Length(total)) => response.len() >= *total,
        Some(BodyFraming::Chunked) => {
            // The terminator can appear inside chunk data, so it only decides
            // where to look; whether the body really ends there is decided by
            // decoding it, which happens at most once for a well-formed body.
            const TERMINATOR: &[u8] = b"\r\n0\r\n\r\n";
            let from = scanned.saturating_sub(TERMINATOR.len() - 1);
            let found = find_subsequence(&response[from..], TERMINATOR).is_some();
            *scanned = response.len();
            found
                && split_headers(response).is_some_and(|(header_end, _)| {
                    decode_chunked_body(&response[header_end + 4..]).is_ok()
                })
        }
        Some(BodyFraming::UntilClose) | None => false,
    }
}

/// Every member of every header called `name`, which is lowercase here: a
/// framing header may be repeated, and each value may itself be a
/// comma-separated list, and both say the same thing.
fn header_list<'a>(
    headers: &'a [(String, String)],
    name: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .iter()
        .filter(move |(header, _)| header == name)
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|member| !member.is_empty())
}

/// The first value of the header called `name`, which is lowercase here.
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// The end of the header block and the headers in it, once `data` holds a
/// whole header block. Every header is kept, in order: a response may repeat
/// a name, `Set-Cookie` above all, and each occurrence means something.
fn split_headers(data: &[u8]) -> Option<(usize, Vec<(String, String)>)> {
    let header_end = find_subsequence(data, b"\r\n\r\n")?;
    let header_text = std::str::from_utf8(&data[..header_end]).ok()?;
    let headers = header_text
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    Some((header_end, headers))
}

fn parse_response(data: &[u8]) -> Result<HttpResponse> {
    let (header_end, headers) = split_headers(data)
        .ok_or_else(|| TorError::http_request("Invalid HTTP response: missing header boundary"))?;
    let header_text = std::str::from_utf8(&data[..header_end])
        .map_err(|error| TorError::http_request(format!("Invalid HTTP headers: {error}")))?;
    let status_line = header_text
        .lines()
        .next()
        .ok_or_else(|| TorError::http_request("Invalid HTTP response: missing status"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| TorError::http_request("Invalid HTTP status line"))?
        .parse::<u16>()
        .map_err(|error| TorError::http_request(format!("Invalid HTTP status: {error}")))?;

    let mut body = data[header_end + 4..].to_vec();

    // The same decision the reading loop made, so what is parsed is what was
    // waited for.
    match body_framing(header_end, &headers)? {
        BodyFraming::Chunked => body = decode_chunked_body(&body)?,
        BodyFraming::Length(total) => {
            let length = total - (header_end + 4);
            if body.len() < length {
                return Err(TorError::http_request(
                    "HTTP response ended before Content-Length",
                ));
            }
            body.truncate(length);
        }
        BodyFraming::UntilClose => {}
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
        remaining = &remaining[size + 2..];
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Every header in the order it arrived, names lowercased. A name may
    /// repeat: a response sets each cookie with a `Set-Cookie` of its own.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The first value of the header called `name`, in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, &name.to_ascii_lowercase())
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
        assert!(request.contains(&format!("User-Agent: {DEFAULT_USER_AGENT}\r\n")));
        assert!(!request.contains("Content-Length"));
    }

    #[test]
    fn a_caller_supplied_user_agent_replaces_the_default() {
        let url = OnionUrl::parse(
            "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/",
        )
        .unwrap();
        let request = HttpRequest {
            method: "GET".to_string(),
            url,
            headers: vec![("user-agent".to_string(), "curl/8".to_string())],
            body: None,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        };
        let wire = String::from_utf8(build_request(&request, "example.onion").unwrap()).unwrap();
        assert!(wire.contains("user-agent: curl/8\r\n"));
        assert!(!wire.contains(DEFAULT_USER_AGENT));
    }

    #[test]
    fn builds_a_body_request_with_a_length() {
        let request = HttpRequest {
            method: "put".to_string(),
            url: OnionUrl::parse("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/upload").unwrap(),
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(b"hello".to_vec()),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
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
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
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
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
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
            response.header("Location"),
            Some("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/a")
        );
    }

    #[test]
    fn keeps_every_repeated_header() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nContent-Length: 0\r\nSet-Cookie: b=2; HttpOnly\r\n\r\n";
        let response = parse_response(raw).unwrap();
        let cookies: Vec<&str> = response
            .headers()
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(cookies, ["a=1; Path=/", "b=2; HttpOnly"]);
        assert_eq!(response.header("set-cookie"), Some("a=1; Path=/"));
    }

    /// The framing a header block decides on, or `None` short of a whole one.
    fn framing_of(head: &[u8]) -> Option<BodyFraming> {
        split_headers(head).map(|(end, headers)| body_framing(end, &headers).unwrap())
    }

    /// Run one exchange over an in-memory stream: the request is written over
    /// the zeroed prefix, and what follows it is read back as the response.
    fn exchange(response: &[u8], max_response_bytes: usize) -> Result<HttpResponse> {
        let wire = b"GET / HTTP/1.1\r\n\r\n";
        let mut data = vec![0_u8; wire.len()];
        data.extend_from_slice(response);
        let mut stream = futures::io::Cursor::new(data);
        futures::executor::block_on(execute_request(&mut stream, wire, max_response_bytes))
    }

    #[test]
    fn the_response_limit_is_the_requests_own() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(exchange(response, response.len()).unwrap().bytes(), b"hello");
        let error = exchange(response, response.len() - 1).unwrap_err();
        assert!(
            error.to_string().contains(&format!("{}-byte limit", response.len() - 1)),
            "{error}"
        );
    }

    #[test]
    fn rejects_partial_chunks() {
        let error = decode_chunked_body(b"5\r\nHi").unwrap_err();
        assert!(error.to_string().contains("Incomplete HTTP chunk"));
    }

    /// A response with `Content-Length` is whole as soon as the body is
    /// there. Waiting for the close instead would surface `tor-proto`'s
    /// `END MISC` as an error and throw the response away.
    #[test]
    fn a_content_length_response_is_complete_without_a_close() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let mut scanned = 0;
        let framing = framing_of(head);
        assert_eq!(framing, Some(BodyFraming::Length(head.len() + 5)));
        assert!(!response_is_complete(&framing, head, &mut scanned));

        let mut whole = head.to_vec();
        whole.extend_from_slice(b"hello");
        assert!(response_is_complete(&framing, &whole, &mut scanned));
    }

    #[test]
    fn a_chunked_response_is_complete_at_its_terminating_chunk() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let framing = framing_of(head);
        assert_eq!(framing, Some(BodyFraming::Chunked));

        let mut scanned = 0;
        let mut response = head.to_vec();
        response.extend_from_slice(b"5\r\nhello\r\n");
        assert!(!response_is_complete(&framing, &response, &mut scanned));

        response.extend_from_slice(b"0\r\n\r\n");
        assert!(response_is_complete(&framing, &response, &mut scanned));
    }

    /// The terminator can appear inside chunk data, which is why finding it
    /// only decides where to look and decoding decides whether it is the end.
    #[test]
    fn a_terminator_inside_chunk_data_does_not_end_the_response() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let framing = framing_of(head);

        let mut scanned = 0;
        let mut response = head.to_vec();
        response.extend_from_slice(b"7\r\n\r\n0\r\n\r\n\r\n");
        assert!(!response_is_complete(&framing, &response, &mut scanned));

        response.extend_from_slice(b"0\r\n\r\n");
        assert!(response_is_complete(&framing, &response, &mut scanned));
    }

    /// `Transfer-Encoding` may arrive split across fields; only the final
    /// coding decides, and a `chunked` that is not final frames nothing.
    #[test]
    fn split_transfer_encoding_fields_frame_by_their_final_coding() {
        let chunked_last = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(framing_of(chunked_last), Some(BodyFraming::Chunked));
        let listed = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n";
        assert_eq!(framing_of(listed), Some(BodyFraming::Chunked));
        let chunked_first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\nContent-Length: 3\r\n\r\n";
        assert_eq!(framing_of(chunked_first), Some(BodyFraming::UntilClose));
    }

    /// Two lengths that disagree, or one that is not a number, are not a
    /// framing at all, and the response is refused rather than read by either.
    #[test]
    fn conflicting_or_invalid_content_lengths_are_refused() {
        let agreeing = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5, 5\r\n\r\nhello";
        assert_eq!(framing_of(agreeing), Some(BodyFraming::Length(agreeing.len())));
        assert_eq!(parse_response(agreeing).unwrap().bytes(), b"hello");

        let conflicting = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
        let (end, headers) = split_headers(conflicting).unwrap();
        let error = body_framing(end, &headers).unwrap_err();
        assert!(error.to_string().contains("Conflicting"), "{error}");
        assert!(parse_response(conflicting).is_err());
        assert!(exchange(conflicting, 1024).is_err());

        let listed = b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\nhello!";
        assert!(parse_response(listed).is_err());

        let invalid = b"HTTP/1.1 200 OK\r\nContent-Length: five\r\n\r\nhello";
        let (end, headers) = split_headers(invalid).unwrap();
        let error = body_framing(end, &headers).unwrap_err();
        assert!(error.to_string().contains("Invalid HTTP Content-Length"), "{error}");
        assert!(exchange(invalid, 1024).is_err());
    }

    /// Without either framing header only the stream closing ends the body.
    #[test]
    fn an_unframed_response_waits_for_the_close() {
        let response = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody";
        let framing = framing_of(response);
        assert_eq!(framing, Some(BodyFraming::UntilClose));
        assert!(!response_is_complete(&framing, response, &mut 0));
    }
}
