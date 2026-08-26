//! TLS 1.3 handshake state machine for one profile: X25519 key exchange,
//! TLS_CHACHA20_POLY1305_SHA256, server authenticated by whatever
//! certificate it presents. The certificate is handed to the caller
//! unverified; Tor authenticates the relay through CERTS cells on the
//! channel, not through the TLS certificate.

use crate::crypto::{self, Hkdf, X25519KeyPair};
use crate::error::{Result, TlsError};
use tracing::{debug, trace};

/// Legacy version written into record headers and the ClientHello
pub const TLS_VERSION_1_2: u16 = 0x0303;
pub const TLS_VERSION_1_3: u16 = 0x0304;

// Content types
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

// Handshake message types
pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_FINISHED: u8 = 20;

// Extension types
pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;

/// The only cipher suite offered. Its AEAD is pure Rust and synchronous,
/// which the record layer needs to encrypt from `poll_read`/`poll_write`.
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// The only key exchange group offered.
pub const GROUP_X25519: u16 = 0x001d;

// Signature algorithms the server may sign CertificateVerify with. The
// extension is mandatory in a ClientHello; the signature itself is not
// checked here (see the module docs).
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;

/// TLS handshake state machine
pub struct HandshakeState {
    /// Our X25519 key pair, consumed when the shared secret is derived
    x25519_key: Option<X25519KeyPair>,
    /// Client random (32 bytes)
    pub client_random: Vec<u8>,
    /// Server random (32 bytes)
    pub server_random: Vec<u8>,
    /// Server name for SNI
    pub server_name: String,
    /// Transcript of all handshake messages
    pub transcript: Vec<u8>,
    /// Handshake secret
    pub handshake_secret: Option<Vec<u8>>,
    /// Client handshake traffic secret
    pub client_handshake_secret: Option<Vec<u8>>,
    /// Server handshake traffic secret
    pub server_handshake_secret: Option<Vec<u8>>,
    /// Client application traffic secret
    pub client_app_secret: Option<Vec<u8>>,
    /// Server application traffic secret
    pub server_app_secret: Option<Vec<u8>>,
}

impl HandshakeState {
    /// Create a new handshake state
    pub fn new(server_name: &str) -> Result<Self> {
        Ok(Self {
            x25519_key: Some(X25519KeyPair::generate()?),
            client_random: crypto::random_bytes(32)?,
            server_random: Vec::new(),
            server_name: server_name.to_string(),
            transcript: Vec::new(),
            handshake_secret: None,
            client_handshake_secret: None,
            server_handshake_secret: None,
            client_app_secret: None,
            server_app_secret: None,
        })
    }

    /// Build ClientHello message
    pub fn build_client_hello(&self) -> Vec<u8> {
        let mut hello = Vec::new();

        // Legacy version (TLS 1.2 for compatibility)
        hello.push((TLS_VERSION_1_2 >> 8) as u8);
        hello.push(TLS_VERSION_1_2 as u8);

        // Random (32 bytes)
        hello.extend_from_slice(&self.client_random);

        // Legacy session ID (empty)
        hello.push(0);

        // Cipher suites: one entry
        hello.push(0);
        hello.push(2);
        hello.push((TLS_CHACHA20_POLY1305_SHA256 >> 8) as u8);
        hello.push(TLS_CHACHA20_POLY1305_SHA256 as u8);

        // Legacy compression methods (null only)
        hello.push(1);
        hello.push(0);

        // Extensions
        let extensions = self.build_extensions();
        hello.push((extensions.len() >> 8) as u8);
        hello.push(extensions.len() as u8);
        hello.extend_from_slice(&extensions);

        // Wrap in handshake header
        let mut message = vec![HANDSHAKE_CLIENT_HELLO];
        let len = hello.len();
        message.push((len >> 16) as u8);
        message.push((len >> 8) as u8);
        message.push(len as u8);
        message.extend_from_slice(&hello);

        message
    }

    fn build_extensions(&self) -> Vec<u8> {
        let mut extensions = Vec::new();

        // Server Name Indication (SNI)
        let sni = self.build_sni_extension();
        extensions.push((EXT_SERVER_NAME >> 8) as u8);
        extensions.push(EXT_SERVER_NAME as u8);
        extensions.push((sni.len() >> 8) as u8);
        extensions.push(sni.len() as u8);
        extensions.extend_from_slice(&sni);

        // Supported Versions (TLS 1.3 only)
        extensions.push((EXT_SUPPORTED_VERSIONS >> 8) as u8);
        extensions.push(EXT_SUPPORTED_VERSIONS as u8);
        extensions.push(0);
        extensions.push(3); // Length
        extensions.push(2); // Versions length
        extensions.push((TLS_VERSION_1_3 >> 8) as u8);
        extensions.push(TLS_VERSION_1_3 as u8);

        // Supported Groups (X25519 only)
        extensions.push((EXT_SUPPORTED_GROUPS >> 8) as u8);
        extensions.push(EXT_SUPPORTED_GROUPS as u8);
        extensions.push(0);
        extensions.push(4); // Length: 2 (list len) + 2 (X25519)
        extensions.push(0);
        extensions.push(2); // Groups length
        extensions.push((GROUP_X25519 >> 8) as u8);
        extensions.push(GROUP_X25519 as u8);

        // Key Share (X25519)
        let key_share = self.build_key_share_extension();
        extensions.push((EXT_KEY_SHARE >> 8) as u8);
        extensions.push(EXT_KEY_SHARE as u8);
        extensions.push((key_share.len() >> 8) as u8);
        extensions.push(key_share.len() as u8);
        extensions.extend_from_slice(&key_share);

        // Signature Algorithms
        let sig_algs = self.build_signature_algorithms_extension();
        extensions.push((EXT_SIGNATURE_ALGORITHMS >> 8) as u8);
        extensions.push(EXT_SIGNATURE_ALGORITHMS as u8);
        extensions.push((sig_algs.len() >> 8) as u8);
        extensions.push(sig_algs.len() as u8);
        extensions.extend_from_slice(&sig_algs);

        extensions
    }

    fn build_sni_extension(&self) -> Vec<u8> {
        let name_bytes = self.server_name.as_bytes();
        let mut ext = Vec::new();

        // Server name list length
        let list_len = 3 + name_bytes.len();
        ext.push((list_len >> 8) as u8);
        ext.push(list_len as u8);

        // Server name type (host_name = 0)
        ext.push(0);

        // Server name length
        ext.push((name_bytes.len() >> 8) as u8);
        ext.push(name_bytes.len() as u8);

        // Server name
        ext.extend_from_slice(name_bytes);

        ext
    }

    fn build_key_share_extension(&self) -> Vec<u8> {
        let key_bytes = self
            .x25519_key
            .as_ref()
            .map(|key| key.public_key_bytes.as_slice())
            .unwrap_or(&[]);
        let mut ext = Vec::new();

        // Client key shares length: group(2) + len(2) + key
        let entry_len = 4 + key_bytes.len();
        ext.push((entry_len >> 8) as u8);
        ext.push(entry_len as u8);

        ext.push((GROUP_X25519 >> 8) as u8);
        ext.push(GROUP_X25519 as u8);
        ext.push((key_bytes.len() >> 8) as u8);
        ext.push(key_bytes.len() as u8);
        ext.extend_from_slice(key_bytes);

        ext
    }

    fn build_signature_algorithms_extension(&self) -> Vec<u8> {
        let algorithms = [
            SIG_ECDSA_SECP256R1_SHA256,
            SIG_RSA_PSS_RSAE_SHA256,
            SIG_RSA_PKCS1_SHA256,
        ];

        let mut ext = Vec::new();
        ext.push(0);
        ext.push((algorithms.len() * 2) as u8);

        for alg in algorithms {
            ext.push((alg >> 8) as u8);
            ext.push(alg as u8);
        }

        ext
    }

    /// Parse ServerHello message and extract key share
    pub fn parse_server_hello(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 38 {
            return Err(TlsError::handshake("ServerHello too short"));
        }

        let mut pos = 0;

        // Legacy version (ignore)
        pos += 2;

        // Random
        self.server_random = data[pos..pos + 32].to_vec();
        pos += 32;

        // Session ID (skip)
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        if pos + 4 > data.len() {
            return Err(TlsError::handshake("ServerHello truncated"));
        }

        // Cipher suite: we offered exactly one, so anything else is a
        // server that ignored the offer.
        let cipher_suite = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        pos += 2;
        if cipher_suite != TLS_CHACHA20_POLY1305_SHA256 {
            return Err(TlsError::handshake(format!(
                "Server selected unsupported cipher suite: 0x{:04x}",
                cipher_suite
            )));
        }

        // Compression method (skip)
        pos += 1;

        // Extensions
        if pos + 2 > data.len() {
            return Err(TlsError::handshake("ServerHello missing extensions"));
        }
        let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
        pos += 2;

        let ext_end = pos + ext_len;
        let mut server_key_share = None;

        while pos + 4 <= ext_end {
            let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
            let ext_data_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
            pos += 4;

            if pos + ext_data_len > ext_end {
                return Err(TlsError::handshake("Extension data overflow"));
            }

            let ext_data = &data[pos..pos + ext_data_len];
            pos += ext_data_len;

            match ext_type {
                EXT_SUPPORTED_VERSIONS => {
                    if ext_data.len() >= 2 {
                        let version = ((ext_data[0] as u16) << 8) | (ext_data[1] as u16);
                        if version != TLS_VERSION_1_3 {
                            return Err(TlsError::handshake(format!(
                                "Unsupported TLS version: 0x{:04x}",
                                version
                            )));
                        }
                    }
                }
                EXT_KEY_SHARE => {
                    // Parse key share: group (2) + key_len (2) + key
                    if ext_data.len() >= 4 {
                        let group = ((ext_data[0] as u16) << 8) | (ext_data[1] as u16);
                        let key_len = ((ext_data[2] as usize) << 8) | (ext_data[3] as usize);

                        if group != GROUP_X25519 {
                            return Err(TlsError::handshake(format!(
                                "Unsupported key share group: 0x{:04x}",
                                group
                            )));
                        }

                        if ext_data.len() >= 4 + key_len {
                            server_key_share = Some(ext_data[4..4 + key_len].to_vec());
                        }
                    }
                }
                _ => {
                    trace!("Ignoring extension 0x{:04x}", ext_type);
                }
            }
        }

        server_key_share.ok_or_else(|| TlsError::handshake("No key_share in ServerHello"))
    }

    /// Derive handshake keys after receiving ServerHello
    pub fn derive_handshake_keys(&mut self, server_key_share: &[u8]) -> Result<()> {
        let x25519_key = self
            .x25519_key
            .take()
            .ok_or_else(|| TlsError::handshake("X25519 key already consumed"))?;
        let shared_secret = x25519_key.derive_shared_secret(server_key_share)?;

        let transcript_hash = crypto::sha256(&self.transcript);

        // TLS 1.3 key schedule
        // Early Secret = HKDF-Extract(salt=0, IKM=0)
        let zero_key = [0u8; 32];
        let early_secret = Hkdf::extract(&[], &zero_key)?;

        // Derive-Secret(early_secret, "derived", "")
        let empty_hash = crypto::sha256(&[]);
        let derived_secret = Hkdf::derive_secret(&early_secret, "derived", &empty_hash)?;

        // Handshake Secret = HKDF-Extract(derived_secret, shared_secret)
        let handshake_secret = Hkdf::extract(&derived_secret, &shared_secret)?;

        // Client/Server handshake traffic secrets
        let client_hs_secret =
            Hkdf::derive_secret(&handshake_secret, "c hs traffic", &transcript_hash)?;
        let server_hs_secret =
            Hkdf::derive_secret(&handshake_secret, "s hs traffic", &transcript_hash)?;

        self.handshake_secret = Some(handshake_secret);
        self.client_handshake_secret = Some(client_hs_secret);
        self.server_handshake_secret = Some(server_hs_secret);

        debug!("Derived handshake traffic secrets");
        Ok(())
    }

    /// Derive application keys after receiving server Finished
    pub fn derive_application_keys(&mut self) -> Result<()> {
        let handshake_secret = self
            .handshake_secret
            .as_ref()
            .ok_or_else(|| TlsError::handshake("Missing handshake secret"))?;

        // Transcript hash up to server Finished
        let transcript_hash = crypto::sha256(&self.transcript);

        // Derive-Secret(handshake_secret, "derived", "")
        let empty_hash = crypto::sha256(&[]);
        let derived_secret = Hkdf::derive_secret(handshake_secret, "derived", &empty_hash)?;

        // Master Secret = HKDF-Extract(derived_secret, 0)
        let zero_key = [0u8; 32];
        let master_secret = Hkdf::extract(&derived_secret, &zero_key)?;

        // Client/Server application traffic secrets
        self.client_app_secret =
            Some(Hkdf::derive_secret(&master_secret, "c ap traffic", &transcript_hash)?);
        self.server_app_secret =
            Some(Hkdf::derive_secret(&master_secret, "s ap traffic", &transcript_hash)?);

        debug!("Derived application traffic secrets");
        Ok(())
    }

    /// Compute Finished message verify data
    pub fn compute_finished(&self, is_client: bool) -> Result<Vec<u8>> {
        let base_key = if is_client {
            self.client_handshake_secret.as_ref()
        } else {
            self.server_handshake_secret.as_ref()
        }
        .ok_or_else(|| TlsError::handshake("Missing handshake secret"))?;

        // finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
        let finished_key = Hkdf::expand_label(base_key, "finished", &[], 32)?;

        // verify_data = HMAC(finished_key, Transcript-Hash)
        let transcript_hash = crypto::sha256(&self.transcript);
        crypto::hmac_sha256(&finished_key, &transcript_hash)
    }

    /// Build client Finished message
    pub fn build_client_finished(&self) -> Result<Vec<u8>> {
        let verify_data = self.compute_finished(true)?;

        let mut message = vec![HANDSHAKE_FINISHED];
        let len = verify_data.len();
        message.push((len >> 16) as u8);
        message.push((len >> 8) as u8);
        message.push(len as u8);
        message.extend_from_slice(&verify_data);

        Ok(message)
    }

    /// Verify server Finished message
    pub fn verify_server_finished(&self, received_verify_data: &[u8]) -> Result<()> {
        let expected = self.compute_finished(false)?;

        if received_verify_data != expected {
            return Err(TlsError::handshake("Server Finished verification failed"));
        }

        debug!("Server Finished verified successfully");
        Ok(())
    }

    /// Add handshake message to transcript
    pub fn update_transcript(&mut self, data: &[u8]) {
        self.transcript.extend_from_slice(data);
    }

    /// Get key and IV for handshake encryption
    pub fn get_handshake_keys(&self, is_client: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        let secret = if is_client {
            self.client_handshake_secret.as_ref()
        } else {
            self.server_handshake_secret.as_ref()
        }
        .ok_or_else(|| TlsError::handshake("Missing handshake secret"))?;
        Self::traffic_keys(secret)
    }

    /// Get key and IV for application data encryption
    pub fn get_application_keys(&self, is_client: bool) -> Result<(Vec<u8>, Vec<u8>)> {
        let secret = if is_client {
            self.client_app_secret.as_ref()
        } else {
            self.server_app_secret.as_ref()
        }
        .ok_or_else(|| TlsError::handshake("Missing application secret"))?;
        Self::traffic_keys(secret)
    }

    /// ChaCha20-Poly1305 traffic key (32 bytes) and IV (12 bytes) from a secret
    fn traffic_keys(secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = Hkdf::expand_label(secret, "key", &[], 32)?;
        let iv = Hkdf::expand_label(secret, "iv", &[], 12)?;
        Ok((key, iv))
    }
}

/// Parse a handshake message header
pub fn parse_handshake_header(data: &[u8]) -> Result<(u8, usize)> {
    if data.len() < 4 {
        return Err(TlsError::handshake("Handshake message too short"));
    }

    let msg_type = data[0];
    let length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);

    Ok((msg_type, length))
}

/// Parse Certificate message
pub fn parse_certificate(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    if data.len() < 4 {
        return Err(TlsError::handshake("Certificate message too short"));
    }

    let mut pos = 0;

    // Certificate request context (should be empty for server cert)
    let context_len = data[pos] as usize;
    pos += 1;

    if pos + context_len > data.len() {
        return Err(TlsError::handshake("Certificate context overflow"));
    }
    pos += context_len;

    if pos + 3 > data.len() {
        return Err(TlsError::handshake("Certificate list length missing"));
    }

    // Certificate list length
    let list_len =
        ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
    pos += 3;

    let list_end = pos.saturating_add(list_len).min(data.len());
    let mut certs = Vec::new();

    while pos + 3 <= list_end && pos + 3 <= data.len() {
        // Certificate length
        let cert_len = ((data[pos] as usize) << 16)
            | ((data[pos + 1] as usize) << 8)
            | (data[pos + 2] as usize);
        pos += 3;

        if pos + cert_len > list_end || pos + cert_len > data.len() {
            return Err(TlsError::handshake("Certificate data overflow"));
        }

        certs.push(data[pos..pos + cert_len].to_vec());
        pos += cert_len;

        // Skip extensions
        if pos + 2 <= list_end && pos + 2 <= data.len() {
            let ext_len = ((data[pos] as usize) << 8) | (data[pos + 1] as usize);
            if pos + 2 + ext_len > data.len() {
                break; // Truncated extensions, stop parsing
            }
            pos += 2 + ext_len;
        }
    }

    if certs.is_empty() {
        return Err(TlsError::handshake("No certificates in message"));
    }

    debug!("Parsed {} certificates", certs.len());
    Ok(certs)
}

/// Parse Finished message
pub fn parse_finished(data: &[u8]) -> Result<Vec<u8>> {
    // Finished message is just the verify_data
    Ok(data.to_vec())
}

/// Maximum handshake message size (matches TLS spec 24-bit length field: 0 to 2^24-1)
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = (1 << 24) - 1;
