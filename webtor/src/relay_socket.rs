//! A WebSocket client for Nostr relays over an onion stream: RFC 6455 with
//! text frames, ping/pong and close, and nothing else. A general WebSocket
//! stack brought an HTTP parser, a second SHA-1 and a third `rand` along for
//! a handshake that is one request line and four headers.

use crate::error::{Result, TorError};
use crate::onion_url::OnionUrl;
use base64::Engine;
use digest::Digest;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use rand::RngCore;
use tor_llcrypto::d::Sha1;
use tor_proto::client::stream::{DataReader, DataStream, DataWriter};

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// Sending half of a relay socket.
pub struct RelaySocketWriter {
    inner: DataWriter,
}

/// Receiving half of a relay socket.
pub struct RelaySocketReader {
    inner: DataReader,
    /// Bytes read past the end of the last frame.
    buffer: Vec<u8>,
    /// Payload cap for one message, fragments included.
    max_message_bytes: usize,
}

/// One inbound WebSocket event the caller has to act on.
pub enum RelayMessage {
    Text(String),
    /// Peer sent a ping; the payload has to go back in a pong.
    Ping(Vec<u8>),
    /// Peer sent a close frame; the connection is done.
    Close,
}

fn ws_error(context: &str, detail: impl std::fmt::Display) -> TorError {
    TorError::websocket_connection(format!("{context}: {detail}"))
}

/// Upgrade `stream` to a WebSocket for `url` and split it into halves.
pub async fn connect(
    mut stream: DataStream,
    url: &OnionUrl,
    max_message_bytes: usize,
) -> Result<(RelaySocketWriter, RelaySocketReader)> {
    let mut nonce = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let host = if url.port() == 80 {
        url.host().to_string()
    } else {
        format!("{}:{}", url.host(), url.port())
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        url.path_and_query()
    );
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
                "relay closed the stream during the handshake",
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
    let expected = base64::engine::general_purpose::STANDARD
        .encode(Sha1::digest(format!("{key}{WS_GUID}").as_bytes()));
    let accepted = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("sec-websocket-accept") && value.trim() == expected
        })
    });
    if !accepted {
        return Err(ws_error(
            "WebSocket upgrade failed",
            "Sec-WebSocket-Accept missing or wrong",
        ));
    }

    let (reader, writer) = stream.split();
    Ok((
        RelaySocketWriter { inner: writer },
        RelaySocketReader {
            inner: reader,
            buffer: leftover,
            max_message_bytes,
        },
    ))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

impl RelaySocketWriter {
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_frame(OP_TEXT, text.as_bytes()).await
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
        rand::thread_rng().fill_bytes(&mut mask);
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

impl RelaySocketReader {
    /// Read the next message. `None` means the stream ended without a close
    /// frame.
    pub async fn next(&mut self) -> Result<Option<RelayMessage>> {
        let mut message: Vec<u8> = Vec::new();
        let mut in_text = false;
        loop {
            let Some((fin, opcode, payload)) = self.read_frame().await? else {
                return Ok(None);
            };
            match opcode {
                OP_PING => return Ok(Some(RelayMessage::Ping(payload))),
                OP_PONG => continue,
                OP_CLOSE => return Ok(Some(RelayMessage::Close)),
                OP_TEXT if !in_text => {
                    in_text = true;
                    message = payload;
                }
                OP_CONTINUATION if in_text => message.extend_from_slice(&payload),
                OP_BINARY => {
                    return Err(ws_error(
                        "WebSocket receive failed",
                        "relay sent a binary message",
                    ))
                }
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
                let text = String::from_utf8(message)
                    .map_err(|error| ws_error("WebSocket receive failed", error))?;
                return Ok(Some(RelayMessage::Text(text)));
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
                    "relay closed the stream mid-frame",
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
