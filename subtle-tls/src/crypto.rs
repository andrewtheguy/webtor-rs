//! Cryptographic primitives for the one TLS 1.3 profile this crate speaks:
//! X25519 key exchange, ChaCha20-Poly1305 records and an HKDF-SHA256 key
//! schedule. Everything is pure Rust and synchronous, which is what lets the
//! record layer run from `poll_read`/`poll_write`.

use crate::error::{Result, TlsError};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Generate random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf)
        .map_err(|e| TlsError::crypto(format!("Failed to generate random bytes: {}", e)))?;
    Ok(buf)
}

/// X25519 key pair for key exchange
pub struct X25519KeyPair {
    secret: EphemeralSecret,
    pub public_key_bytes: Vec<u8>,
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair
    pub fn generate() -> Result<Self> {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = X25519PublicKey::from(&secret);

        Ok(Self {
            secret,
            public_key_bytes: public.as_bytes().to_vec(),
        })
    }

    /// Derive shared secret from peer's public key
    pub fn derive_shared_secret(self, peer_public_key_bytes: &[u8]) -> Result<Vec<u8>> {
        if peer_public_key_bytes.len() != 32 {
            return Err(TlsError::crypto("X25519 public key must be 32 bytes"));
        }

        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_public_key_bytes);
        let peer_public = X25519PublicKey::from(peer_bytes);
        let shared_secret = self.secret.diffie_hellman(&peer_public);
        Ok(shared_secret.as_bytes().to_vec())
    }
}

/// ChaCha20-Poly1305 AEAD for record protection
pub struct Cipher {
    cipher: ChaCha20Poly1305,
}

impl Cipher {
    /// Create a cipher from a 32-byte key
    pub fn new(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(TlsError::crypto("ChaCha20-Poly1305 requires 32-byte key"));
        }

        let key = chacha20poly1305::Key::from_slice(key_bytes);
        Ok(Self {
            cipher: ChaCha20Poly1305::new(key),
        })
    }

    /// Encrypt plaintext with the given nonce and additional data.
    /// Returns ciphertext with the 16-byte authentication tag appended.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(TlsError::crypto("ChaCha20-Poly1305 requires 12-byte nonce"));
        }

        self.cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| TlsError::crypto(format!("ChaCha20-Poly1305 encryption failed: {}", e)))
    }

    /// Decrypt ciphertext (with tag appended) using the given nonce and additional data
    pub fn decrypt(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(TlsError::crypto("ChaCha20-Poly1305 requires 12-byte nonce"));
        }
        if ciphertext.len() < 16 {
            return Err(TlsError::crypto("Ciphertext too short (missing tag)"));
        }

        self.cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|e| TlsError::crypto(format!("ChaCha20-Poly1305 decryption failed: {}", e)))
    }
}

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| TlsError::crypto("Invalid HMAC key length"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// HKDF-SHA256 as used by the TLS 1.3 key schedule
pub struct Hkdf;

impl Hkdf {
    /// HKDF-Extract: Extract a pseudorandom key from input keying material
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Result<Vec<u8>> {
        // Per RFC 5869, an absent salt is HashLen zero bytes.
        let zero_salt = [0u8; 32];
        let effective_salt = if salt.is_empty() { &zero_salt[..] } else { salt };
        hmac_sha256(effective_salt, ikm)
    }

    /// HKDF-Expand: Expand a pseudorandom key to the desired length
    pub fn expand(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        let hash_len = 32;
        let n = length.div_ceil(hash_len);
        if n > 255 {
            return Err(TlsError::crypto("HKDF output too long"));
        }

        let mut okm = Vec::with_capacity(length);
        let mut t = Vec::new();
        for i in 1..=n {
            let mut data = t.clone();
            data.extend_from_slice(info);
            data.push(i as u8);
            t = hmac_sha256(prk, &data)?;
            okm.extend_from_slice(&t);
        }

        okm.truncate(length);
        Ok(okm)
    }

    /// HKDF-Expand-Label for TLS 1.3
    pub fn expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
        // HkdfLabel = struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // }
        let full_label = format!("tls13 {}", label);
        let label_bytes = full_label.as_bytes();

        let mut hkdf_label = Vec::new();
        hkdf_label.push((length >> 8) as u8);
        hkdf_label.push(length as u8);
        hkdf_label.push(label_bytes.len() as u8);
        hkdf_label.extend_from_slice(label_bytes);
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);

        Self::expand(secret, &hkdf_label, length)
    }

    /// Derive-Secret for TLS 1.3
    pub fn derive_secret(secret: &[u8], label: &str, messages_hash: &[u8]) -> Result<Vec<u8>> {
        Self::expand_label(secret, label, messages_hash, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_have_requested_length() {
        assert_eq!(random_bytes(32).unwrap().len(), 32);
    }

    #[test]
    fn x25519_key_exchange_agrees() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let alice_public = alice.public_key_bytes.clone();
        let bob_public = bob.public_key_bytes.clone();

        let alice_secret = alice.derive_shared_secret(&bob_public).unwrap();
        let bob_secret = bob.derive_shared_secret(&alice_public).unwrap();
        assert_eq!(alice_secret, bob_secret);
        assert_eq!(alice_secret.len(), 32);
    }

    #[test]
    fn chacha20_round_trip() {
        let cipher = Cipher::new(&[7u8; 32]).unwrap();
        let nonce = [0u8; 12];
        let ciphertext = cipher.encrypt(&nonce, b"aad", b"Hello, World!").unwrap();
        assert_eq!(ciphertext.len(), 13 + 16);
        assert_eq!(cipher.decrypt(&nonce, b"aad", &ciphertext).unwrap(), b"Hello, World!");
        assert!(cipher.decrypt(&nonce, b"other", &ciphertext).is_err());
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = Hkdf::extract(&salt, &ikm).unwrap();
        assert_eq!(
            prk,
            hex_literal("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = Hkdf::expand(&prk, &info, 42).unwrap();
        assert_eq!(
            okm,
            hex_literal(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    fn hex_literal(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
