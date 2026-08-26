//! Directory authority trust anchor and consensus signature checking.
//!
//! A consensus is only worth anything if a strict majority of the directory
//! authorities signed it. The signatures name a medium-term signing key, so
//! checking them takes a second document: the authority certificate binding
//! that signing key to the authority's long-term identity key. The identity
//! keys themselves are the trust anchor and are pinned here.

use crate::error::{Result, TorError};
use std::time::SystemTime;
use tor_checkable::{ExternallySigned, SelfSigned, TimeBound};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};
use tor_netdoc::doc::netstatus::{MdConsensus, UnvalidatedMdConsensus};
use tracing::{debug, warn};

/// v3 identity fingerprints of the directory authorities, the same set Arti
/// ships in `tor-dircommon`. A consensus must carry good signatures from a
/// strict majority of these — anything else is not the Tor network.
const AUTHORITY_V3IDENTS: [&str; 9] = [
    "27102BC123E7AF1D4741AE047E160C91ADC76B21", // bastet
    "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", // dannenberg
    "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", // dizum
    "70849B868D606BAECFB6128C5E3D782029AA394F", // faravahar
    "ED03BB616EB2F60BEC80151114BB25CEF515B226", // gabelmoo
    "23D15D965BC35114467363C165C4F724B64B4F66", // longclaw
    "49015F787433103580E3B66A1707A00E60F2D15B", // maatuska
    "F533C81CEF0BC0267857C99B2F471ADF249FA232", // moria1
    "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", // tor26
];

/// The pinned authority identities, decoded.
fn trusted_authorities() -> Vec<RsaIdentity> {
    AUTHORITY_V3IDENTS
        .iter()
        .map(|hex| RsaIdentity::from_hex(hex).expect("authority fingerprint is not valid hex"))
        .collect()
}

/// A parsed, timely consensus that has not had its signatures checked, and so
/// cannot be read: the only way to reach the relays inside is [`Self::validate`].
#[derive(Debug)]
pub(crate) struct UncheckedConsensus {
    unvalidated: UnvalidatedMdConsensus,
}

impl UncheckedConsensus {
    /// Parse `body` as a microdescriptor consensus and check that it is
    /// timely at `now`. The signatures are still unchecked at this point.
    pub(crate) fn parse(body: &str, now: SystemTime) -> Result<Self> {
        let (_, _, timebound) = MdConsensus::parse(body).map_err(|error| {
            TorError::serialization(format!("Failed to parse consensus: {}", error))
        })?;
        let unvalidated = timebound
            .if_valid_at(&now)
            .map_err(|error| {
                TorError::ConsensusFetch(format!("Consensus timeliness check failed: {}", error))
            })?;
        Ok(Self { unvalidated })
    }

    /// The certificates needed to check this consensus, restricted to the
    /// pinned authorities. Signatures from anyone else are not worth fetching
    /// a certificate for, since [`Self::validate`] would discard it anyway.
    pub(crate) fn required_cert_ids(&self) -> Vec<AuthCertKeyIds> {
        let trusted = trusted_authorities();
        self.unvalidated
            .signing_cert_ids()
            .filter(|ids| trusted.contains(&ids.id_fingerprint))
            .collect()
    }

    /// Check that a strict majority of the pinned authorities signed this
    /// consensus, using `certs`, and return the consensus it protects.
    pub(crate) fn validate(self, certs: &[AuthCert]) -> Result<MdConsensus> {
        let n_authorities = AUTHORITY_V3IDENTS.len();
        self.unvalidated
            .set_n_authorities(n_authorities)
            .check_signature(certs)
            .map_err(|error| {
                TorError::ConsensusFetch(format!(
                    "Consensus is not signed by {} of {} directory authorities: {}",
                    n_authorities / 2 + 1,
                    n_authorities,
                    error
                ))
            })
    }
}

/// The `/tor/keys/fp-sk/` path that fetches `ids` from a directory cache.
pub(crate) fn authority_certs_path(ids: &[AuthCertKeyIds]) -> String {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    let segments: Vec<String> = ids
        .iter()
        .map(|id| {
            format!(
                "{}-{}",
                hex::encode(id.id_fingerprint.as_bytes()),
                hex::encode(id.sk_fingerprint.as_bytes())
            )
        })
        .collect();
    format!("/tor/keys/fp-sk/{}", segments.join("+"))
}

/// Parse `body` as authority certificates, keeping only those that are
/// self-signed, timely at `now`, and issued by a pinned authority. A
/// certificate that fails any of those is dropped rather than fatal: the
/// consensus check that follows decides whether enough of them survived.
pub(crate) fn parse_authority_certs(body: &str, now: SystemTime) -> Result<Vec<AuthCert>> {
    let trusted = trusted_authorities();
    let certs = AuthCert::parse_multiple(body).map_err(|error| {
        TorError::serialization(format!("Failed to parse authority certificates: {}", error))
    })?;

    let mut trusted_certs = Vec::new();
    for cert in certs {
        let cert = match cert {
            Ok(cert) => cert,
            Err(error) => {
                warn!("Skipping unparseable authority certificate: {}", error);
                continue;
            }
        };
        let cert = match cert.check_signature() {
            Ok(cert) => cert,
            Err(error) => {
                warn!("Skipping authority certificate with a bad signature: {}", error);
                continue;
            }
        };
        let cert = match cert.if_valid_at(&now) {
            Ok(cert) => cert,
            Err(error) => {
                warn!("Skipping authority certificate that is not timely: {}", error);
                continue;
            }
        };
        if !trusted.contains(cert.id_fingerprint()) {
            warn!(
                "Skipping certificate from unrecognized authority {}",
                hex::encode(cert.id_fingerprint().as_bytes())
            );
            continue;
        }
        trusted_certs.push(cert);
    }

    debug!(
        "Kept {} authority certificates from {} bytes",
        trusted_certs.len(),
        body.len()
    );
    Ok(trusted_certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_fingerprints_decode() {
        assert_eq!(trusted_authorities().len(), AUTHORITY_V3IDENTS.len());
    }

    #[test]
    fn certs_path_is_sorted_lowercase_hex() {
        let ids = |id: &str, sk: &str| AuthCertKeyIds {
            id_fingerprint: RsaIdentity::from_hex(id).unwrap(),
            sk_fingerprint: RsaIdentity::from_hex(sk).unwrap(),
        };
        let path = authority_certs_path(&[
            ids(AUTHORITY_V3IDENTS[8], AUTHORITY_V3IDENTS[0]),
            ids(AUTHORITY_V3IDENTS[1], AUTHORITY_V3IDENTS[2]),
        ]);
        assert_eq!(
            path,
            "/tor/keys/fp-sk/\
             0232af901c31a04ee9848595af9bb7620d4c5b2e-e8a9c45ede6d711294fadf8e7951f4de6ca56b58+\
             2f3df9ca0e5d36f2685a2da67184eb8dcb8cba8c-27102bc123e7af1d4741ae047e160c91adc76b21"
        );
    }

    #[test]
    fn garbage_certificates_are_dropped() {
        assert!(parse_authority_certs("not a certificate\n", SystemTime::UNIX_EPOCH)
            .map(|certs| certs.is_empty())
            .unwrap_or(true));
    }

    #[test]
    fn a_consensus_that_is_not_a_consensus_is_rejected() {
        let error =
            UncheckedConsensus::parse("network-status-version 3\n", SystemTime::UNIX_EPOCH)
                .unwrap_err();
        assert!(error.to_string().contains("consensus"), "{}", error);
    }
}
