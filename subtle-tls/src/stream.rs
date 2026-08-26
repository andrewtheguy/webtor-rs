//! TLS Stream implementation with AsyncRead/AsyncWrite
//!
//! Wraps an underlying stream with TLS encryption after handshake.

use crate::error::{Result, TlsError};
use crate::handshake::{
    self, HandshakeState, CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, HANDSHAKE_CERTIFICATE,
    HANDSHAKE_CERTIFICATE_VERIFY, HANDSHAKE_ENCRYPTED_EXTENSIONS, HANDSHAKE_FINISHED,
    HANDSHAKE_SERVER_HELLO,
};
use crate::record::RecordLayer;
use futures::io::{AsyncRead, AsyncWrite};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::{debug, info, trace, warn};

/// TLS-encrypted stream
pub struct TlsStream<S> {
    /// Underlying transport stream
    inner: S,
    /// Record layer for reading/writing TLS records
    record_layer: RecordLayer,
    /// Buffered plaintext for reading
    read_buffer: Vec<u8>,
    /// Position in read buffer
    read_pos: usize,
    /// DER-encoded peer certificate (for CertifiedConn)
    peer_certificate: Option<Vec<u8>>,
    /// Buffer for accumulating encrypted record data being read
    record_read_buffer: Vec<u8>,
    /// Buffer for pending write data (encrypted, ready to send to transport)
    record_write_buffer: Vec<u8>,
}

impl<S> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Perform the TLS 1.3 handshake and return the encrypted stream.
    ///
    /// `server_name` only fills the SNI extension. The server's certificate
    /// is accepted as presented and exposed through `peer_certificate`; the
    /// caller (Tor's channel handshake) is what authenticates the peer.
    pub async fn connect(mut stream: S, server_name: &str) -> Result<Self> {
        info!("Starting TLS 1.3 handshake with {}", server_name);

        let mut handshake = HandshakeState::new(server_name)?;
        let mut record_layer = RecordLayer::new();

        // Step 1: Send ClientHello
        let client_hello = handshake.build_client_hello();
        handshake.update_transcript(&client_hello);
        record_layer
            .write_record(&mut stream, CONTENT_TYPE_HANDSHAKE, &client_hello)
            .await?;
        debug!("Sent ClientHello");

        // Step 2: Receive ServerHello
        info!("Waiting for ServerHello...");
        let server_hello_data = Self::read_server_hello(&mut stream, &mut record_layer).await?;
        info!("Got ServerHello: {} bytes", server_hello_data.len());

        // Add raw record to transcript (including handshake header)
        let mut server_hello_msg = vec![HANDSHAKE_SERVER_HELLO];
        let len = server_hello_data.len();
        server_hello_msg.push((len >> 16) as u8);
        server_hello_msg.push((len >> 8) as u8);
        server_hello_msg.push(len as u8);
        server_hello_msg.extend_from_slice(&server_hello_data);
        handshake.update_transcript(&server_hello_msg);

        let server_key_share = handshake.parse_server_hello(&server_hello_data)?;

        // Step 3: Derive handshake keys
        handshake.derive_handshake_keys(&server_key_share)?;

        // Activate server->client encryption
        let (read_key, read_iv) = handshake.get_handshake_keys(false)?;
        record_layer.set_read_cipher(&read_key, &read_iv)?;

        // Step 4: Receive encrypted handshake messages
        // (EncryptedExtensions, Certificate, CertificateVerify, Finished)
        info!("Processing encrypted handshake messages...");
        let peer_certificate = match Self::process_encrypted_handshake(
            &mut stream,
            &mut record_layer,
            &mut handshake,
        )
        .await
        {
            Ok(cert) => {
                info!("process_encrypted_handshake returned Ok");
                cert
            }
            Err(e) => {
                tracing::error!("process_encrypted_handshake returned Err: {}", e);
                return Err(e);
            }
        };
        info!("Encrypted handshake complete");

        // Step 5: Derive application keys
        handshake.derive_application_keys()?;

        // Step 6: Activate client->server encryption and send Finished
        let (write_key, write_iv) = handshake.get_handshake_keys(true)?;
        record_layer.set_write_cipher(&write_key, &write_iv)?;

        let client_finished = handshake.build_client_finished()?;
        handshake.update_transcript(&client_finished);
        record_layer
            .write_record(&mut stream, CONTENT_TYPE_HANDSHAKE, &client_finished)
            .await?;
        debug!("Sent client Finished");

        // Step 7: Switch to application keys
        let (app_read_key, app_read_iv) = handshake.get_application_keys(false)?;
        let (app_write_key, app_write_iv) = handshake.get_application_keys(true)?;
        record_layer.set_read_cipher(&app_read_key, &app_read_iv)?;
        record_layer.set_write_cipher(&app_write_key, &app_write_iv)?;

        info!("TLS 1.3 handshake completed with {}", server_name);

        Ok(Self {
            inner: stream,
            record_layer,
            read_buffer: Vec::new(),
            read_pos: 0,
            peer_certificate,
            record_read_buffer: Vec::new(),
            record_write_buffer: Vec::new(),
        })
    }

    /// Get the peer certificate (DER-encoded)
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_deref()
    }

    async fn read_server_hello(stream: &mut S, record_layer: &mut RecordLayer) -> Result<Vec<u8>> {
        loop {
            let (content_type, data) = record_layer.read_record(stream).await?;

            match content_type {
                CONTENT_TYPE_HANDSHAKE => {
                    // Parse handshake message
                    if data.len() < 4 {
                        return Err(TlsError::handshake("Handshake message too short"));
                    }
                    let msg_type = data[0];
                    let length =
                        ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);

                    if msg_type == HANDSHAKE_SERVER_HELLO {
                        let total_len = 4 + length;
                        if data.len() < total_len {
                            return Err(TlsError::handshake(format!(
                                "ServerHello message truncated: expected {} bytes, got {}",
                                total_len,
                                data.len()
                            )));
                        }
                        return Ok(data[4..total_len].to_vec());
                    } else {
                        return Err(TlsError::UnexpectedMessage {
                            expected: "ServerHello".to_string(),
                            got: format!("HandshakeType {}", msg_type),
                        });
                    }
                }
                CONTENT_TYPE_ALERT => {
                    return Err(Self::parse_alert(&data));
                }
                CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                    // Ignore CCS for TLS 1.3 compatibility
                    debug!("Ignoring ChangeCipherSpec");
                    continue;
                }
                _ => {
                    return Err(TlsError::UnexpectedMessage {
                        expected: "Handshake".to_string(),
                        got: format!("ContentType {}", content_type),
                    });
                }
            }
        }
    }

    /// Process encrypted handshake messages and return the peer's leaf
    /// certificate (if it sent one)
    async fn process_encrypted_handshake(
        stream: &mut S,
        record_layer: &mut RecordLayer,
        handshake: &mut HandshakeState,
    ) -> Result<Option<Vec<u8>>> {
        let mut got_encrypted_extensions = false;
        let mut got_finished = false;
        let mut cert_chain: Vec<Vec<u8>> = Vec::new();

        // Buffer for accumulating fragmented handshake messages
        let mut handshake_buffer: Vec<u8> = Vec::new();

        while !got_finished {
            info!("process_encrypted_handshake: reading next record...");
            let (content_type, data) = record_layer.read_record(stream).await?;
            info!(
                "process_encrypted_handshake: got record type={}, len={}",
                content_type,
                data.len()
            );

            match content_type {
                20 => {
                    // CONTENT_TYPE_CHANGE_CIPHER_SPEC
                    debug!("Ignoring ChangeCipherSpec");
                    continue;
                }
                21 => {
                    // CONTENT_TYPE_ALERT
                    return Err(Self::parse_alert(&data));
                }
                22 => {
                    // CONTENT_TYPE_HANDSHAKE
                    // Accumulate handshake data (may be fragmented across records)
                    info!(
                        "Adding {} bytes to handshake buffer (was {} bytes)",
                        data.len(),
                        handshake_buffer.len()
                    );
                    handshake_buffer.extend_from_slice(&data);
                    info!(
                        "Handshake buffer now {} bytes, first 4 bytes: {:02x?}",
                        handshake_buffer.len(),
                        &handshake_buffer[..4.min(handshake_buffer.len())]
                    );

                    // Parse complete handshake messages from the buffer
                    while handshake_buffer.len() >= 4 {
                        let msg_type = handshake_buffer[0];
                        let length = ((handshake_buffer[1] as usize) << 16)
                            | ((handshake_buffer[2] as usize) << 8)
                            | (handshake_buffer[3] as usize);

                        let total_len = 4 + length;
                        trace!(
                            "Parsing handshake: type={}, length={}, buffer_len={}",
                            msg_type,
                            length,
                            handshake_buffer.len()
                        );

                        if handshake_buffer.len() < total_len {
                            // Need more data - wait for next record
                            debug!(
                                "Handshake message fragmented: have {} bytes, need {}",
                                handshake_buffer.len(),
                                total_len
                            );
                            break;
                        }

                        // Extract complete message
                        let msg_data: Vec<u8> = handshake_buffer.drain(..total_len).collect();
                        let msg_body = &msg_data[4..];

                        match msg_type {
                            HANDSHAKE_ENCRYPTED_EXTENSIONS => {
                                debug!("Received EncryptedExtensions");
                                handshake.update_transcript(&msg_data);
                                got_encrypted_extensions = true;
                            }
                            HANDSHAKE_CERTIFICATE => {
                                debug!("Received Certificate ({} bytes)", msg_body.len());
                                handshake.update_transcript(&msg_data);
                                cert_chain = handshake::parse_certificate(msg_body)?;
                            }
                            HANDSHAKE_CERTIFICATE_VERIFY => {
                                // Not checked: Tor authenticates the relay
                                // through CERTS cells, not this signature.
                                debug!("Received CertificateVerify");
                                handshake.update_transcript(&msg_data);
                            }
                            HANDSHAKE_FINISHED => {
                                info!("Received server Finished ({} bytes)", msg_body.len());
                                let verify_data = handshake::parse_finished(msg_body)?;
                                info!("Verifying server Finished...");
                                handshake.verify_server_finished(&verify_data)?;
                                info!("Server Finished verified OK");
                                handshake.update_transcript(&msg_data);
                                got_finished = true;
                                info!("got_finished = true, breaking out of loop");
                            }
                            _ => {
                                warn!("Ignoring unknown handshake message type: {}", msg_type);
                                handshake.update_transcript(&msg_data);
                            }
                        }
                    }
                }
                _ => {
                    return Err(TlsError::UnexpectedMessage {
                        expected: "Handshake".to_string(),
                        got: format!("ContentType {}", content_type),
                    });
                }
            }
        }

        if !got_encrypted_extensions {
            return Err(TlsError::handshake("Missing EncryptedExtensions"));
        }

        debug!("Encrypted handshake phase completed");
        // Return the leaf certificate (first in chain)
        Ok(cert_chain.into_iter().next())
    }

    fn parse_alert(data: &[u8]) -> TlsError {
        if data.len() >= 2 {
            let level = data[0];
            let description = data[1];
            let level_str = if level == 1 { "warning" } else { "fatal" };
            let desc_str = match description {
                0 => "close_notify",
                10 => "unexpected_message",
                20 => "bad_record_mac",
                40 => "handshake_failure",
                42 => "bad_certificate",
                43 => "unsupported_certificate",
                44 => "certificate_revoked",
                45 => "certificate_expired",
                46 => "certificate_unknown",
                47 => "illegal_parameter",
                48 => "unknown_ca",
                49 => "access_denied",
                50 => "decode_error",
                51 => "decrypt_error",
                70 => "protocol_version",
                71 => "insufficient_security",
                80 => "internal_error",
                86 => "inappropriate_fallback",
                90 => "user_canceled",
                109 => "missing_extension",
                110 => "unsupported_extension",
                112 => "unrecognized_name",
                113 => "bad_certificate_status_response",
                115 => "unknown_psk_identity",
                116 => "certificate_required",
                120 => "no_application_protocol",
                _ => "unknown",
            };
            TlsError::Alert(format!(
                "{} alert: {} ({})",
                level_str, desc_str, description
            ))
        } else {
            TlsError::Alert("Unknown alert".to_string())
        }
    }

    /// Read application data (blocking)
    pub async fn read_app_data(&mut self) -> Result<Vec<u8>> {
        loop {
            let (content_type, data) = self.record_layer.read_record(&mut self.inner).await?;

            match content_type {
                CONTENT_TYPE_APPLICATION_DATA => {
                    return Ok(data);
                }
                CONTENT_TYPE_ALERT => {
                    if data.len() >= 2 && data[0] == 1 && data[1] == 0 {
                        // close_notify
                        return Err(TlsError::ConnectionClosed);
                    }
                    return Err(Self::parse_alert(&data));
                }
                CONTENT_TYPE_HANDSHAKE => {
                    // Post-handshake messages (e.g., NewSessionTicket)
                    trace!("Ignoring post-handshake message");
                    continue;
                }
                _ => {
                    warn!("Ignoring unexpected content type: {}", content_type);
                    continue;
                }
            }
        }
    }

    /// Write application data (blocking)
    pub async fn write_app_data(&mut self, data: &[u8]) -> Result<()> {
        self.record_layer
            .write_record(&mut self.inner, CONTENT_TYPE_APPLICATION_DATA, data)
            .await
    }

    /// Close the TLS connection gracefully
    pub async fn close(&mut self) -> Result<()> {
        // Send close_notify alert
        let alert = [1, 0]; // warning, close_notify
        self.record_layer
            .write_record(&mut self.inner, CONTENT_TYPE_ALERT, &alert)
            .await?;
        Ok(())
    }
}

/// Maximum TLS record size
const MAX_RECORD_SIZE: usize = 16384 + 256;

// AsyncRead implementation - properly polls underlying stream
impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // First, drain any buffered plaintext
        if self.read_pos < self.read_buffer.len() {
            let available = &self.read_buffer[self.read_pos..];
            let to_copy = std::cmp::min(buf.len(), available.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(to_copy));
        }

        // Try to read and decrypt a TLS record
        loop {
            // Check if we have enough data for a record header
            if self.record_read_buffer.len() >= 5 {
                let content_type = self.record_read_buffer[0];
                let length = ((self.record_read_buffer[3] as usize) << 8)
                    | (self.record_read_buffer[4] as usize);

                if length > MAX_RECORD_SIZE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("TLS record too large: {}", length),
                    )));
                }

                let total_len = 5 + length;

                // Check if we have the full record
                if self.record_read_buffer.len() >= total_len {
                    // Extract the record
                    let record_data: Vec<u8> = self.record_read_buffer.drain(..total_len).collect();
                    let body = &record_data[5..];

                    // Decrypt if cipher is active
                    let (actual_type, plaintext) = if self.record_layer.has_read_cipher()
                        && content_type == CONTENT_TYPE_APPLICATION_DATA
                    {
                        // Build header for AAD
                        let header = [
                            record_data[0],
                            record_data[1],
                            record_data[2],
                            record_data[3],
                            record_data[4],
                        ];

                        // Decrypt synchronously using the record layer's cipher
                        match self.record_layer.decrypt_record_sync(&header, body) {
                            Ok((ct, pt)) => (ct, pt),
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("Decryption failed: {}", e),
                                )));
                            }
                        }
                    } else {
                        (content_type, body.to_vec())
                    };

                    match actual_type {
                        CONTENT_TYPE_APPLICATION_DATA => {
                            // Copy to output buffer
                            let to_copy = std::cmp::min(buf.len(), plaintext.len());
                            buf[..to_copy].copy_from_slice(&plaintext[..to_copy]);

                            // Buffer any remaining
                            if to_copy < plaintext.len() {
                                self.read_buffer = plaintext[to_copy..].to_vec();
                                self.read_pos = 0;
                            }

                            return Poll::Ready(Ok(to_copy));
                        }
                        CONTENT_TYPE_ALERT => {
                            if plaintext.len() >= 2 && plaintext[0] == 1 && plaintext[1] == 0 {
                                // close_notify - signal EOF
                                return Poll::Ready(Ok(0));
                            }
                            let err = Self::parse_alert(&plaintext);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                err.to_string(),
                            )));
                        }
                        CONTENT_TYPE_HANDSHAKE => {
                            // Post-handshake message (e.g., NewSessionTicket), skip it
                            trace!("Ignoring post-handshake message");
                            continue;
                        }
                        CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                            // Ignore CCS
                            continue;
                        }
                        _ => {
                            warn!("Ignoring unexpected content type: {}", actual_type);
                            continue;
                        }
                    }
                }
            }

            // Need more data from the underlying transport
            let mut temp = [0u8; 4096];

            match Pin::new(&mut self.inner).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(0)) => {
                    // EOF from underlying stream
                    return Poll::Ready(Ok(0));
                }
                Poll::Ready(Ok(n)) => {
                    trace!("TlsStream poll_read: got {} bytes from transport", n);
                    self.record_read_buffer.extend_from_slice(&temp[..n]);
                    // Continue loop to try parsing
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // First, flush any pending write buffer
        while !self.record_write_buffer.is_empty() {
            // Use mem::take to avoid clone while satisfying borrow checker
            let mut pending = std::mem::take(&mut self.record_write_buffer);
            let poll = Pin::new(&mut self.inner).poll_write(cx, &pending);
            match poll {
                Poll::Ready(Ok(0)) => {
                    self.record_write_buffer = pending;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    pending.drain(..n);
                    self.record_write_buffer = pending;
                }
                Poll::Ready(Err(e)) => {
                    self.record_write_buffer = pending;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.record_write_buffer = pending;
                    return Poll::Pending;
                }
            }
        }

        // Encrypt the new data and write it
        // Encrypt using the record layer
        let encrypted = match self
            .record_layer
            .encrypt_record_sync(CONTENT_TYPE_APPLICATION_DATA, buf)
        {
            Ok(data) => data,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Encryption failed: {}", e),
                )));
            }
        };

        // Try to write the encrypted record
        match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) => {
                if n < encrypted.len() {
                    // Partial write - buffer the rest
                    self.record_write_buffer.extend_from_slice(&encrypted[n..]);
                }
                // Report how many plaintext bytes were written
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Buffer all for later
                self.record_write_buffer = encrypted;
                Poll::Pending
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush pending write buffer
        while !self.record_write_buffer.is_empty() {
            // Use mem::take to avoid clone while satisfying borrow checker
            let mut pending = std::mem::take(&mut self.record_write_buffer);
            let poll = Pin::new(&mut self.inner).poll_write(cx, &pending);
            match poll {
                Poll::Ready(Ok(0)) => {
                    self.record_write_buffer = pending;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    pending.drain(..n);
                    self.record_write_buffer = pending;
                }
                Poll::Ready(Err(e)) => {
                    self.record_write_buffer = pending;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    self.record_write_buffer = pending;
                    return Poll::Pending;
                }
            }
        }

        // Flush underlying stream
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First flush pending data
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }

        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Wrapper that provides blocking-style async methods
/// This is the recommended way to use TlsStream in WASM
impl<S> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Read data using async/await (recommended for WASM)
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First drain buffer
        if self.read_pos < self.read_buffer.len() {
            let available = &self.read_buffer[self.read_pos..];
            let to_copy = std::cmp::min(buf.len(), available.len());
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.read_pos += to_copy;

            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Ok(to_copy);
        }

        // Read more data
        match self.read_app_data().await {
            Ok(data) => {
                let to_copy = std::cmp::min(buf.len(), data.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);

                if to_copy < data.len() {
                    self.read_buffer = data[to_copy..].to_vec();
                    self.read_pos = 0;
                }

                Ok(to_copy)
            }
            Err(TlsError::ConnectionClosed) => Ok(0),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    /// Write data using async/await (recommended for WASM)
    pub async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_app_data(buf).await {
            Ok(()) => Ok(buf.len()),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    /// Flush the stream
    pub async fn flush(&mut self) -> io::Result<()> {
        use futures::io::AsyncWriteExt;
        self.inner.flush().await
    }
}

// Implement tor_rtcompat traits for TlsStream

impl<S> tor_rtcompat::StreamOps for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Use default implementation
}

impl<S> tor_rtcompat::CertifiedConn for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn peer_certificate(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.peer_certificate.clone())
    }

    fn export_keying_material(
        &self,
        _len: usize,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        // Only a client that authenticates itself to the relay needs the TLS
        // exporter, and this one never does.
        Err(io::Error::other("TLS keying material export is not supported"))
    }
}
