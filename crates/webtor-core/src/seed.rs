//! Building a directory seed outside the browser.
//!
//! A `directorySeed` is three Tor documents in one JSON object: a microdesc
//! consensus, the authority certificates that check its signatures, and the
//! microdescriptors it names. The client downloads all three over a bridge
//! circuit when it has to, and that download is the slowest and least reliable
//! part of a bootstrap; a backend with a plain HTTP connection to a directory
//! authority can fetch the same documents in seconds and hand the browser a
//! seed instead.
//!
//! This module is the part of that job which is about Tor rather than about
//! HTTP. The caller does the fetching, from wherever it likes; what is here
//! reads the consensus for the paths to fetch next, checks the result exactly
//! as [`crate::TorClient`] checks a seed on the way in, and encodes it. A seed
//! that passes here is one the client will install; one that fails here would
//! have been rejected in the browser, after being downloaded.

use crate::authority::{authority_certs_path, parse_authority_certs, UncheckedConsensus};
use crate::directory::{
    encode_microdescriptor_digest, process_directory_documents, DirectoryCache,
    DIRECTORY_CACHE_VERSION,
};
use crate::error::{Result, TorError};
use std::collections::HashSet;
use std::time::SystemTime;
use tor_netdoc::doc::netstatus::MdConsensus;

/// The consensus document a directory cache serves, compressed with zlib
/// when the `.z` suffix is added.
pub const CONSENSUS_PATH: &str = "/tor/status-vote/current/consensus-microdesc";

/// How many digests one `/tor/micro/d/` request may name. Each is one
/// 43-character path segment, so this keeps the URL within what a directory
/// cache accepts.
pub const MICRODESCRIPTORS_PER_REQUEST: usize = 90;

/// A consensus that has been parsed but whose signatures are unchecked. It
/// says which certificates check it and nothing else: the relays inside are
/// reachable only through [`Self::verify`].
pub struct UnverifiedConsensus {
    body: String,
    unchecked: UncheckedConsensus,
}

impl UnverifiedConsensus {
    /// Parse `body` as a microdesc consensus that is valid at `now`.
    pub fn parse(body: String, now: SystemTime) -> Result<Self> {
        let unchecked = UncheckedConsensus::parse(&body, now)?;
        Ok(Self { body, unchecked })
    }

    /// The `/tor/keys/fp-sk/…` path that fetches the certificates this
    /// consensus needs, restricted to the pinned authorities. An error means
    /// no pinned authority signed it, which no certificate can repair.
    pub fn certificates_path(&self) -> Result<String> {
        let ids = self.unchecked.required_cert_ids();
        if ids.is_empty() {
            return Err(TorError::ConsensusFetch(
                "Consensus carries no signature from a known directory authority".to_string(),
            ));
        }
        Ok(authority_certs_path(&ids))
    }

    /// Check the signatures against `certificates` — the document the path
    /// from [`Self::certificates_path`] fetched — and open the consensus.
    pub fn verify(self, certificates: String, now: SystemTime) -> Result<VerifiedConsensus> {
        let consensus = self
            .unchecked
            .validate(&parse_authority_certs(&certificates, now)?)?;
        Ok(VerifiedConsensus {
            body: self.body,
            certificates,
            consensus,
        })
    }
}

/// A consensus a strict majority of the pinned authorities signed, ready to
/// name the microdescriptors a seed should carry.
pub struct VerifiedConsensus {
    body: String,
    certificates: String,
    consensus: MdConsensus,
}

impl VerifiedConsensus {
    /// When the consensus became valid.
    pub fn valid_after(&self) -> SystemTime {
        self.consensus.lifetime().valid_after()
    }

    /// When the authorities publish the next consensus. A seed built from this
    /// one is the newest available until then, and stale afterwards.
    pub fn fresh_until(&self) -> SystemTime {
        self.consensus.lifetime().fresh_until()
    }

    /// When the consensus expires. The client refuses a seed past this.
    pub fn valid_until(&self) -> SystemTime {
        self.consensus.lifetime().valid_until()
    }

    /// Every microdescriptor digest the consensus names, each once.
    ///
    /// The client, downloading through one bridge circuit, samples a few
    /// relays per role; a backend fetching from an authority can afford the
    /// whole network, which leaves path selection weighted across all of it.
    pub fn microdescriptor_digests(&self) -> Vec<[u8; 32]> {
        let mut seen = HashSet::new();
        self.consensus
            .relays()
            .iter()
            .map(|router| *router.md_digest())
            .filter(|digest| seen.insert(*digest))
            .collect()
    }

    /// The `/tor/micro/d/…` path that fetches `digests`. Ask for at most
    /// [`MICRODESCRIPTORS_PER_REQUEST`] at a time.
    pub fn microdescriptors_path(digests: &[[u8; 32]]) -> String {
        let segments: Vec<String> = digests.iter().map(encode_microdescriptor_digest).collect();
        format!("/tor/micro/d/{}", segments.join("-"))
    }

    /// Put the consensus, its certificates and `microdescriptors` — the
    /// concatenated bodies the paths from [`Self::microdescriptors_path`]
    /// fetched — through the checks a client applies to a seed, and encode
    /// what passes in the shape `directorySeed` accepts.
    pub fn into_seed(self, microdescriptors: String) -> Result<BuiltSeed> {
        let processed = process_directory_documents(&self.consensus, &microdescriptors)?;
        let lifetime = self.consensus.lifetime();
        let (valid_after, fresh_until, valid_until) = (
            lifetime.valid_after(),
            lifetime.fresh_until(),
            lifetime.valid_until(),
        );
        let encoded = DirectoryCache {
            version: DIRECTORY_CACHE_VERSION,
            consensus: self.body,
            certificates: self.certificates,
            microdescriptors,
        }
        .encode()?;
        Ok(BuiltSeed {
            encoded,
            relay_count: processed.relays.len(),
            middle_count: processed.middle_count,
            hsdir_count: processed.hsdir_count,
            valid_after,
            fresh_until,
            valid_until,
        })
    }
}

/// A seed the client will accept, and what it holds.
#[derive(Clone, Debug)]
pub struct BuiltSeed {
    /// The seed itself, as `directorySeed` takes it.
    pub encoded: String,
    /// Relays with both a consensus entry and a microdescriptor.
    pub relay_count: usize,
    /// Of those, the ones usable as a middle hop.
    pub middle_count: usize,
    /// Of those, the ones on the HSDir ring.
    pub hsdir_count: usize,
    pub valid_after: SystemTime,
    pub fresh_until: SystemTime,
    pub valid_until: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microdescriptor_paths_are_unpadded_base64_joined_by_dashes() {
        let path = VerifiedConsensus::microdescriptors_path(&[[0; 32], [255; 32]]);
        assert_eq!(
            path,
            "/tor/micro/d/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-\
             //////////////////////////////////////////8"
        );
    }

    #[test]
    fn a_consensus_that_is_not_a_consensus_is_rejected() {
        let error = UnverifiedConsensus::parse(
            "network-status-version 3\n".to_string(),
            SystemTime::UNIX_EPOCH,
        )
        .err()
        .expect("garbage is not a consensus");
        assert!(error.to_string().contains("consensus"), "{error}");
    }
}
