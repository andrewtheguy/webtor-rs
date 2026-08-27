//! TLS 1.3 Record Layer
//!
//! Handles reading and writing TLS records with encryption/decryption.
//! Records are protected with ChaCha20-Poly1305, the one suite negotiated.

use crate::crypto::Cipher;
use crate::error::{Result, TlsError};
use crate::handshake::{CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE, TLS_VERSION_1_2};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, trace};

/// Maximum TLS record size (16KB + some overhead)
pub const MAX_RECORD_SIZE: usize = 16384 + 256;
/// Maximum plaintext size per record
pub const MAX_PLAINTEXT_SIZE: usize = 16384;

/// TLS record reader/writer with encryption state
pub struct RecordLayer {
    /// Read cipher (for decrypting incoming records)
    read_cipher: Option<RecordCipher>,
    /// Write cipher (for encrypting outgoing records)
    write_cipher: Option<RecordCipher>,
}

/// Encryption state for one direction
struct RecordCipher {
    aead: Cipher,
    iv: Vec<u8>,
    sequence: u64,
}

impl RecordCipher {
    fn new(aead: Cipher, iv: Vec<u8>) -> Self {
        Self {
            aead,
            iv,
            sequence: 0,
        }
    }

    /// Compute the nonce for the current record
    fn compute_nonce(&self) -> Vec<u8> {
        let mut nonce = self.iv.clone();
        // XOR sequence number into the last 8 bytes of IV
        let seq_bytes = self.sequence.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    fn increment_sequence(&mut self) {
        self.sequence = self.sequence.wrapping_add(1);
    }
}

impl RecordLayer {
    /// Create a new record layer (initially unencrypted)
    pub fn new() -> Self {
        Self {
            read_cipher: None,
            write_cipher: None,
        }
    }

    /// Set the read cipher for decrypting incoming records
    pub fn set_read_cipher(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        self.read_cipher = Some(RecordCipher::new(Cipher::new(key)?, iv.to_vec()));
        debug!("Read cipher activated");
        Ok(())
    }

    /// Set the write cipher for encrypting outgoing records
    pub fn set_write_cipher(&mut self, key: &[u8], iv: &[u8]) -> Result<()> {
        self.write_cipher = Some(RecordCipher::new(Cipher::new(key)?, iv.to_vec()));
        debug!("Write cipher activated");
        Ok(())
    }

    /// Read a single TLS record from the stream
    pub async fn read_record<S>(&mut self, stream: &mut S) -> Result<(u8, Vec<u8>)>
    where
        S: AsyncRead + Unpin,
    {
        // Read record header (5 bytes)
        tracing::debug!(
            "read_record: waiting for 5-byte header (cipher active: {})",
            self.read_cipher.is_some()
        );
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.map_err(|e| {
            tracing::error!("read_record: read_exact for header failed: {}", e);
            TlsError::Io(e)
        })?;
        tracing::debug!("read_record: got header: {:02x?}", header);

        let content_type = header[0];
        let _version = ((header[1] as u16) << 8) | (header[2] as u16);
        let length = ((header[3] as usize) << 8) | (header[4] as usize);

        if length > MAX_RECORD_SIZE {
            return Err(TlsError::record(format!("Record too large: {}", length)));
        }

        // Read record body
        tracing::debug!("read_record: reading {} byte body", length);
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.map_err(|e| {
            tracing::error!("read_record: body read failed: {}", e);
            TlsError::Io(e)
        })?;
        tracing::debug!(
            "read_record: got body, type={}, len={}",
            content_type,
            length
        );

        trace!("Read record: type={}, len={}", content_type, length);

        // Decrypt if cipher is active
        if let Some(ref mut cipher) = self.read_cipher {
            if content_type == CONTENT_TYPE_APPLICATION_DATA {
                tracing::debug!("read_record: decrypting APPLICATION_DATA record");
                let nonce = cipher.compute_nonce();
                tracing::debug!(
                    "read_record: nonce={:02x?}, body_len={}",
                    &nonce,
                    body.len()
                );
                // Additional data is the record header with encrypted length
                let aad = &header;

                let plaintext = cipher.aead.decrypt(&nonce, aad, &body)?;
                cipher.increment_sequence();

                // TLS 1.3: plaintext format is [content][content_type][zeros...]
                // The content type is the last byte. We don't strip padding zeros because
                // legitimate content data can end with zeros (e.g., DER-encoded certificates).
                if plaintext.is_empty() {
                    return Err(TlsError::record("Empty decrypted record"));
                }

                let actual_content_type = plaintext[plaintext.len() - 1];
                let data = plaintext[..plaintext.len() - 1].to_vec();

                trace!(
                    "Decrypted record: type={}, len={}",
                    actual_content_type,
                    data.len()
                );
                return Ok((actual_content_type, data));
            }
        }

        Ok((content_type, body))
    }

    /// Write a TLS record to the stream
    pub async fn write_record<S>(
        &mut self,
        stream: &mut S,
        content_type: u8,
        data: &[u8],
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        // One record carries at most 2^14 bytes of plaintext (RFC 8446 5.1),
        // and TLS 1.3 counts the content type byte appended in
        // `write_single_record` against that. A peer answers a larger record
        // with a `record_overflow` alert and drops the connection.
        for chunk in data.chunks(MAX_PLAINTEXT_SIZE - 1) {
            self.write_single_record(stream, content_type, chunk)
                .await?;
        }
        Ok(())
    }

    async fn write_single_record<S>(
        &mut self,
        stream: &mut S,
        content_type: u8,
        data: &[u8],
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let (record_type, body) = if let Some(ref mut cipher) = self.write_cipher {
            // TLS 1.3: encrypt with content type appended to plaintext
            let mut plaintext = data.to_vec();
            plaintext.push(content_type);

            let nonce = cipher.compute_nonce();

            // Build header for AAD (we need to know ciphertext length first)
            let ciphertext_len = plaintext.len() + 16; // +16 for auth tag
            let aad = [
                CONTENT_TYPE_APPLICATION_DATA,
                (TLS_VERSION_1_2 >> 8) as u8,
                TLS_VERSION_1_2 as u8,
                (ciphertext_len >> 8) as u8,
                ciphertext_len as u8,
            ];

            let ciphertext = cipher.aead.encrypt(&nonce, &aad, &plaintext)?;
            cipher.increment_sequence();

            (CONTENT_TYPE_APPLICATION_DATA, ciphertext)
        } else {
            (content_type, data.to_vec())
        };

        // Build record header
        let mut record = Vec::with_capacity(5 + body.len());
        record.push(record_type);
        record.push((TLS_VERSION_1_2 >> 8) as u8);
        record.push(TLS_VERSION_1_2 as u8);
        record.push((body.len() >> 8) as u8);
        record.push(body.len() as u8);
        record.extend_from_slice(&body);

        trace!("Write record: type={}, len={}", record_type, body.len());

        stream.write_all(&record).await.map_err(TlsError::Io)?;
        stream.flush().await.map_err(TlsError::Io)?;

        Ok(())
    }

    /// Read multiple handshake messages from the stream
    /// Returns handshake messages as a vector
    pub async fn read_handshake_messages<S>(&mut self, stream: &mut S) -> Result<Vec<(u8, Vec<u8>)>>
    where
        S: AsyncRead + Unpin,
    {
        let mut messages = Vec::new();

        let (content_type, data) = self.read_record(stream).await?;

        if content_type != CONTENT_TYPE_HANDSHAKE {
            return Err(TlsError::UnexpectedMessage {
                expected: "Handshake".to_string(),
                got: format!("ContentType {}", content_type),
            });
        }

        // Parse handshake messages from the data
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let msg_type = data[pos];
            let length = ((data[pos + 1] as usize) << 16)
                | ((data[pos + 2] as usize) << 8)
                | (data[pos + 3] as usize);
            pos += 4;

            if pos + length > data.len() {
                return Err(TlsError::record("Handshake message extends beyond record"));
            }

            messages.push((msg_type, data[pos..pos + length].to_vec()));
            pos += length;
        }

        Ok(messages)
    }
}

impl Default for RecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordLayer {
    /// Check if read cipher is active
    pub fn has_read_cipher(&self) -> bool {
        self.read_cipher.is_some()
    }

    /// Check if write cipher is active
    pub fn has_write_cipher(&self) -> bool {
        self.write_cipher.is_some()
    }

    /// Decrypt a record synchronously (for use in poll_read)
    /// Returns (content_type, plaintext)
    pub fn decrypt_record_sync(&mut self, header: &[u8; 5], body: &[u8]) -> Result<(u8, Vec<u8>)> {
        if let Some(ref mut cipher) = self.read_cipher {
            let nonce = cipher.compute_nonce();

            // Decrypt using synchronous API
            let plaintext = cipher.aead.decrypt(&nonce, header, body)?;
            cipher.increment_sequence();

            // TLS 1.3 inner plaintext: last byte is content type
            if plaintext.is_empty() {
                return Err(TlsError::record("Empty decrypted record"));
            }
            let actual_content_type = plaintext[plaintext.len() - 1];
            let data = plaintext[..plaintext.len() - 1].to_vec();

            Ok((actual_content_type, data))
        } else {
            // No cipher active, return as-is
            Ok((header[0], body.to_vec()))
        }
    }

    /// Encrypt a record synchronously (for use in poll_write)
    /// Returns the full encrypted record including header
    pub fn encrypt_record_sync(&mut self, content_type: u8, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref mut cipher) = self.write_cipher {
            // TLS 1.3: encrypt with content type appended to plaintext
            let mut plaintext = data.to_vec();
            plaintext.push(content_type);

            let nonce = cipher.compute_nonce();

            // Build header for AAD (we need to know ciphertext length first)
            let ciphertext_len = plaintext.len() + 16; // +16 for auth tag
            let header = [
                CONTENT_TYPE_APPLICATION_DATA,
                (TLS_VERSION_1_2 >> 8) as u8,
                TLS_VERSION_1_2 as u8,
                (ciphertext_len >> 8) as u8,
                ciphertext_len as u8,
            ];

            let ciphertext = cipher.aead.encrypt(&nonce, &header, &plaintext)?;
            cipher.increment_sequence();

            // Build full record
            let mut record = Vec::with_capacity(5 + ciphertext.len());
            record.extend_from_slice(&header);
            record.extend_from_slice(&ciphertext);

            Ok(record)
        } else {
            // No cipher active, send unencrypted
            let mut record = Vec::with_capacity(5 + data.len());
            record.push(content_type);
            record.push((TLS_VERSION_1_2 >> 8) as u8);
            record.push(TLS_VERSION_1_2 as u8);
            record.push((data.len() >> 8) as u8);
            record.push(data.len() as u8);
            record.extend_from_slice(data);
            Ok(record)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_layer_new() {
        let layer = RecordLayer::new();
        assert!(!layer.has_read_cipher());
        assert!(!layer.has_write_cipher());
    }

    /// The largest payload a writer may hand the record layer is
    /// `MAX_PLAINTEXT_SIZE - 1`: TLS 1.3 appends the content type to the
    /// plaintext, and a peer answers a record over 2^14 with a
    /// `record_overflow` alert and hangs up. `TlsStream::poll_write` splits
    /// larger writes for exactly this reason.
    #[test]
    fn largest_allowed_payload_stays_within_the_record_limit() {
        let mut layer = RecordLayer::new();
        layer.set_write_cipher(&[0_u8; 32], &[0_u8; 12]).unwrap();

        let payload = vec![0_u8; MAX_PLAINTEXT_SIZE - 1];
        let record = layer
            .encrypt_record_sync(CONTENT_TYPE_APPLICATION_DATA, &payload)
            .unwrap();

        // The plaintext the peer reconstructs is the payload plus the content
        // type byte, which is what its 2^14 limit applies to.
        assert_eq!(payload.len() + 1, MAX_PLAINTEXT_SIZE);
        let declared = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(declared, record.len() - 5);
        assert!(
            declared <= MAX_RECORD_SIZE,
            "record of {declared} bytes is over the {MAX_RECORD_SIZE} byte limit"
        );
    }

    /// The same limit applies to a payload the caller hands `write_record` in
    /// one piece: it becomes several records rather than one oversized one.
    #[test]
    fn write_record_splits_at_the_plaintext_limit() {
        let mut layer = RecordLayer::new();
        let mut written: Vec<u8> = Vec::new();

        futures::executor::block_on(layer.write_record(
            &mut written,
            CONTENT_TYPE_APPLICATION_DATA,
            &vec![0_u8; MAX_PLAINTEXT_SIZE],
        ))
        .unwrap();

        let first = u16::from_be_bytes([written[3], written[4]]) as usize;
        assert_eq!(first, MAX_PLAINTEXT_SIZE - 1);
        let rest = &written[5 + first..];
        assert_eq!(u16::from_be_bytes([rest[3], rest[4]]) as usize, 1);
        assert_eq!(rest.len(), 5 + 1);
    }
}
