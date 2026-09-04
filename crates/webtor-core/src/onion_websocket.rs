//! A WebSocket client over an onion stream: RFC 6455 with text and binary
//! messages, ping/pong and close, and nothing else. A general WebSocket stack
//! brought an HTTP parser, a second SHA-1 and a third `rand` along for a
//! handshake that is one request line and four headers.
//!
//! `ws://` only. The onion circuit already authenticates the service and
//! encrypts the exchange, so there is no `wss://` here and no TLS to run.

use crate::error::{Result, TorError};
use crate::onion_url::OnionUrl;
use base64::Engine;
use digest::Digest;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use rand::Rng;
use tor_llcrypto::d::Sha1;
use tor_proto::client::stream::{DataReader, DataStream, DataWriter};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// Headers the upgrade sets itself; a caller may not supply them.
const RESERVED_HEADERS: [&str; 7] = [
    "host",
    "upgrade",
    "connection",
    "sec-websocket-key",
    "sec-websocket-version",
    "content-length",
    "transfer-encoding",
];

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Sending half of an onion WebSocket.
pub struct WebSocketWriter {
    inner: DataWriter,
}

/// An onion WebSocket once the upgrade has been accepted.
pub struct WebSocketConnection {
    pub writer: WebSocketWriter,
    pub reader: WebSocketReader,
    /// The headers the service answered the upgrade with, names lowercased,
    /// in the order they came: `Sec-WebSocket-Protocol` says which
    /// subprotocol it chose, and a `Set-Cookie` here is as good as one on a
    /// response.
    pub headers: Vec<(String, String)>,
}

/// Receiving half of an onion WebSocket.
pub struct WebSocketReader {
    inner: DataReader,
    /// Bytes read past the end of the last frame.
    buffer: Vec<u8>,
    /// Payload cap for one message, fragments included.
    max_message_bytes: usize,
}

/// One inbound WebSocket event the caller has to act on.
pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
    /// Peer sent a ping; the payload has to go back in a pong.
    Ping(Vec<u8>),
    /// Peer sent a close frame; the connection is done.
    Close,
}

fn ws_error(context: &str, detail: impl std::fmt::Display) -> TorError {
    TorError::websocket_connection(format!("{context}: {detail}"))
}

/// The upgrade request for `url`: RFC 6455 §4.1's line and four headers,
/// then `headers`, which is where a `Cookie`, an `Origin` or a
/// `Sec-WebSocket-Protocol` goes. A header that would break the line
/// framing, or one the upgrade sets itself, is refused.
fn upgrade_request(url: &OnionUrl, key: &str, headers: &[(String, String)]) -> Result<String> {
    let host = if url.port() == 80 {
        url.host().to_string()
    } else {
        format!("{}:{}", url.host(), url.port())
    };
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n",
        url.path_and_query()
    );
    for (name, value) in headers {
        // A newline in either half would let a caller inject headers, or a
        // whole second request, into the stream.
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(ws_error(
                "WebSocket upgrade refused",
                format!("header {name} contains a line break"),
            ));
        }
        if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(ws_error(
                "WebSocket upgrade refused",
                format!("header {name} is set by the upgrade and cannot be supplied"),
            ));
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    Ok(request)
}

/// Upgrade `stream` to a WebSocket for `url`, with `headers` on the request
/// after the ones the upgrade itself needs.
pub async fn connect(
    mut stream: DataStream,
    url: &OnionUrl,
    headers: &[(String, String)],
    max_message_bytes: usize,
) -> Result<WebSocketConnection> {
    let mut nonce = [0_u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let request = upgrade_request(url, &key, headers)?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| ws_error("Failed to send WebSocket upgrade", error))?;
    stream
        .flush()
        .await
        .map_err(|error| ws_error("Failed to send WebSocket upgrade", error))?;

    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(end) = find(&response, b"\r\n\r\n") {
            break end;
        }
        if response.len() > MAX_HANDSHAKE_BYTES {
            return Err(ws_error("WebSocket upgrade failed", "response too large"));
        }
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|error| ws_error("Failed to read WebSocket upgrade", error))?;
        if count == 0 {
            return Err(ws_error(
                "WebSocket upgrade failed",
                "the service closed the stream during the handshake",
            ));
        }
        response.extend_from_slice(&chunk[..count]);
    };
    let leftover = response.split_off(header_end + 4);
    let head = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101") {
        return Err(ws_error("WebSocket upgrade refused", status));
    }
    let response_headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let expected = base64::engine::general_purpose::STANDARD
        .encode(Sha1::digest(format!("{key}{WS_GUID}").as_bytes()));
    let accepted = response_headers
        .iter()
        .any(|(name, value)| name == "sec-websocket-accept" && value == &expected);
    if !accepted {
        return Err(ws_error(
            "WebSocket upgrade failed",
            "Sec-WebSocket-Accept missing or wrong",
        ));
    }

    let (reader, writer) = stream.split();
    Ok(WebSocketConnection {
        writer: WebSocketWriter { inner: writer },
        reader: WebSocketReader {
            inner: reader,
            buffer: leftover,
            max_message_bytes,
        },
        headers: response_headers,
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl WebSocketWriter {
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_frame(OP_TEXT, text.as_bytes()).await
    }

    pub async fn send_binary(&mut self, payload: &[u8]) -> Result<()> {
        self.send_frame(OP_BINARY, payload).await
    }

    pub async fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        self.send_frame(OP_PING, payload).await
    }

    pub async fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        self.send_frame(OP_PONG, payload).await
    }

    /// Send a close frame with status 1000 (normal closure).
    pub async fn send_close(&mut self) -> Result<()> {
        self.send_frame(OP_CLOSE, &1000_u16.to_be_bytes()).await
    }

    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        // Clients must mask every frame (RFC 6455 §5.3).
        let mut mask = [0_u8; 4];
        rand::rng().fill_bytes(&mut mask);
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4]),
        );
        self.inner
            .write_all(&frame)
            .await
            .map_err(|error| ws_error("WebSocket send failed", error))?;
        self.inner
            .flush()
            .await
            .map_err(|error| ws_error("WebSocket send failed", error))
    }
}

impl WebSocketReader {
    /// Read the next message. `None` means the stream ended without a close
    /// frame.
    pub async fn next(&mut self) -> Result<Option<WebSocketMessage>> {
        let mut message: Vec<u8> = Vec::new();
        // The opcode of the message being assembled, once a data frame has
        // started; continuation frames carry no opcode of their own.
        let mut assembling: Option<u8> = None;
        loop {
            let Some((fin, opcode, payload)) = self.read_frame().await? else {
                return Ok(None);
            };
            match opcode {
                // A control frame may arrive between the fragments of a data
                // message, so answering one must not disturb the assembly.
                OP_PING => return Ok(Some(WebSocketMessage::Ping(payload))),
                OP_PONG => continue,
                OP_CLOSE => return Ok(Some(WebSocketMessage::Close)),
                OP_TEXT | OP_BINARY if assembling.is_none() => {
                    assembling = Some(opcode);
                    message = payload;
                }
                OP_CONTINUATION if assembling.is_some() => message.extend_from_slice(&payload),
                _ => {
                    return Err(ws_error(
                        "WebSocket receive failed",
                        format!("unexpected frame opcode {opcode:#x}"),
                    ))
                }
            }
            if message.len() > self.max_message_bytes {
                return Err(ws_error(
                    "WebSocket receive failed",
                    "message exceeds the size limit",
                ));
            }
            if fin {
                return Ok(Some(if assembling == Some(OP_BINARY) {
                    WebSocketMessage::Binary(message)
                } else {
                    let text = String::from_utf8(message)
                        .map_err(|error| ws_error("WebSocket receive failed", error))?;
                    WebSocketMessage::Text(text)
                }));
            }
        }
    }

    async fn read_frame(&mut self) -> Result<Option<(bool, u8, Vec<u8>)>> {
        let Some(header) = self.read_exact(2).await? else {
            return Ok(None);
        };
        let fin = header[0] & 0x80 != 0;
        let opcode = header[0] & 0x0F;
        let masked = header[1] & 0x80 != 0;
        let mut length = (header[1] & 0x7F) as usize;
        if length == 126 {
            let bytes = self.need(2).await?;
            length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        } else if length == 127 {
            let bytes = self.need(8).await?;
            let wide = u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"));
            length = usize::try_from(wide)
                .map_err(|_| ws_error("WebSocket receive failed", "frame too large"))?;
        }
        if length > self.max_message_bytes {
            return Err(ws_error(
                "WebSocket receive failed",
                "frame exceeds the size limit",
            ));
        }
        // Servers must not mask (RFC 6455 §5.1), but tolerating it costs nothing.
        let mask = if masked {
            let bytes = self.need(4).await?;
            Some([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            None
        };
        let mut payload = self.need(length).await?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        Ok(Some((fin, opcode, payload)))
    }

    /// Like `need`, but a clean end of stream before any byte is `None`.
    async fn read_exact(&mut self, count: usize) -> Result<Option<Vec<u8>>> {
        if self.buffer.is_empty() && !self.fill().await? {
            return Ok(None);
        }
        self.need(count).await.map(Some)
    }

    async fn need(&mut self, count: usize) -> Result<Vec<u8>> {
        while self.buffer.len() < count {
            if !self.fill().await? {
                return Err(ws_error(
                    "WebSocket receive failed",
                    "the service closed the stream mid-frame",
                ));
            }
        }
        let rest = self.buffer.split_off(count);
        Ok(std::mem::replace(&mut self.buffer, rest))
    }

    /// Read more bytes into the buffer; `false` at end of stream.
    async fn fill(&mut self) -> Result<bool> {
        let mut chunk = [0_u8; 16 * 1024];
        let count = self
            .inner
            .read(&mut chunk)
            .await
            .map_err(|error| ws_error("WebSocket receive failed", error))?;
        self.buffer.extend_from_slice(&chunk[..count]);
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "ws://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/ws/private?a=1";

    fn pairs(headers: &[(&str, &str)]) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn upgrade_request_carries_the_callers_headers_after_its_own() {
        let url = OnionUrl::parse(ONION).unwrap();
        let request = upgrade_request(
            &url,
            "dGhlIHNhbXBsZSBub25jZQ==",
            &pairs(&[("Cookie", "session=abc"), ("Origin", "http://example.onion")]),
        )
        .unwrap();
        assert_eq!(
            request,
            "GET /ws/private?a=1 HTTP/1.1\r\n\
             Host: 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
             Cookie: session=abc\r\nOrigin: http://example.onion\r\n\r\n"
        );
    }

    #[test]
    fn upgrade_request_refuses_a_header_the_upgrade_sets() {
        let url = OnionUrl::parse(ONION).unwrap();
        for name in ["Host", "upgrade", "Sec-WebSocket-Key", "CONNECTION"] {
            let error = upgrade_request(&url, "key", &pairs(&[(name, "x")])).unwrap_err();
            assert!(error.to_string().contains("set by the upgrade"), "{name}: {error}");
        }
    }

    #[test]
    fn upgrade_request_refuses_a_line_break() {
        let url = OnionUrl::parse(ONION).unwrap();
        let error = upgrade_request(&url, "key", &pairs(&[("Cookie", "a\r\nHost: evil")])).unwrap_err();
        assert!(error.to_string().contains("line break"), "{error}");
        let error = upgrade_request(&url, "key", &pairs(&[("Bad:Name", "x")])).unwrap_err();
        assert!(error.to_string().contains("line break"), "{error}");
    }
}
