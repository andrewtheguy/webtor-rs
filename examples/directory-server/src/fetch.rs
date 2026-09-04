//! Building a seed from a directory authority over plain HTTP.
//!
//! What the documents mean, which to ask for next and whether the result is
//! one a client will install all live in `webtor_core::seed`; this is the HTTP
//! around it. Authorities answer on their DirPort with bare HTTP/1.0, and a
//! `.z` suffix asks for the zlib-compressed form of any document.

use anyhow::{anyhow, bail, Context};
use futures::{stream, StreamExt, TryStreamExt};
use std::io::Read;
use std::time::{Duration, SystemTime};
use tracing::info;
use webtor_core::seed::{
    BuiltSeed, UnverifiedConsensus, VerifiedConsensus, CONSENSUS_PATH,
    MICRODESCRIPTORS_PER_REQUEST,
};

/// Directory authorities that serve their DirPort over plain HTTP, tried in
/// order until one answers.
pub const DEFAULT_AUTHORITIES: &[&str] = &[
    "http://45.66.35.11:80",    // dizum
    "http://204.13.164.118:80", // bastet
    "http://131.188.40.189:80", // gabelmoo
    "http://199.58.81.140:80",  // longclaw
    "http://171.25.193.9:443",  // maatuska (plain HTTP on 443)
];

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Microdescriptor batches in flight at once, each on its own connection.
const PARALLEL_REQUESTS: usize = 4;
/// Relays leave the network between the consensus and this fetch, so a few
/// missing microdescriptors are normal; a shortfall past this is a broken
/// authority or a truncated transfer.
const MIN_MICRODESCRIPTOR_FRACTION: f64 = 0.9;

/// The authorities to fetch from, behind one HTTP client.
pub struct Authorities {
    client: reqwest::Client,
    urls: Vec<String>,
}

impl Authorities {
    pub fn new(urls: Vec<String>) -> anyhow::Result<Self> {
        if urls.is_empty() {
            bail!("at least one directory authority URL is needed");
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent("webtor-directory-server")
            .build()
            .context("building the HTTP client")?;
        Ok(Self { client, urls })
    }

    /// GET `path` from the first authority that serves it, inflated when
    /// `path` asked for the compressed form.
    async fn get(&self, path: &str) -> anyhow::Result<String> {
        let mut failures = Vec::new();
        for authority in &self.urls {
            match self.get_from(authority, path).await {
                Ok(body) => return Ok(body),
                Err(error) => failures.push(format!("{authority}: {error:#}")),
            }
        }
        Err(anyhow!(
            "no directory authority served {path}\n  {}",
            failures.join("\n  ")
        ))
    }

    async fn get_from(&self, authority: &str, path: &str) -> anyhow::Result<String> {
        let response = self.client.get(format!("{authority}{path}")).send().await?;
        let status = response.status();
        if !status.is_success() {
            bail!("HTTP {status}");
        }
        let bytes = response.bytes().await?;
        let bytes = if path.ends_with(".z") {
            let mut inflated = Vec::new();
            flate2::read::ZlibDecoder::new(&bytes[..])
                .read_to_end(&mut inflated)
                .context("inflating the response")?;
            inflated
        } else {
            bytes.to_vec()
        };
        String::from_utf8(bytes).context("the document is not UTF-8")
    }

    /// Fetch the current consensus, the certificates that check it and every
    /// microdescriptor it names, and assemble the seed a client will install.
    pub async fn build_seed(&self) -> anyhow::Result<BuiltSeed> {
        info!("Fetching the current microdesc consensus");
        let consensus_body = self.get(&format!("{CONSENSUS_PATH}.z")).await?;
        let now = SystemTime::now();
        let unverified = UnverifiedConsensus::parse(consensus_body, now)
            .context("the consensus could not be parsed")?;

        let certificates_path = unverified.certificates_path()?;
        let certificates = self.get(&format!("{certificates_path}.z")).await?;
        let consensus = unverified
            .verify(certificates, now)
            .context("the consensus signatures did not check out")?;
        info!("Consensus signatures verified against the directory authorities");

        let digests = consensus.microdescriptor_digests();
        info!("Fetching {} microdescriptors", digests.len());
        let microdescriptors = self.fetch_microdescriptors(&digests).await?;
        let received = microdescriptors.matches("\nonion-key\n").count()
            + usize::from(microdescriptors.starts_with("onion-key\n"));
        info!("Received {received} of {} microdescriptors", digests.len());
        if (received as f64) < digests.len() as f64 * MIN_MICRODESCRIPTOR_FRACTION {
            bail!(
                "only {received} of {} microdescriptors came back, too few for a seed",
                digests.len()
            );
        }

        consensus
            .into_seed(microdescriptors)
            .context("the fetched documents do not make an installable seed")
    }

    /// The microdescriptors for `digests`, concatenated, fetched a batch at a
    /// time with a few batches in flight.
    async fn fetch_microdescriptors(&self, digests: &[[u8; 32]]) -> anyhow::Result<String> {
        let paths: Vec<String> = digests
            .chunks(MICRODESCRIPTORS_PER_REQUEST)
            .map(|chunk| format!("{}.z", VerifiedConsensus::microdescriptors_path(chunk)))
            .collect();
        let bodies: Vec<String> = stream::iter(paths)
            .map(|path| async move { self.get(&path).await.map(with_trailing_newline) })
            .buffer_unordered(PARALLEL_REQUESTS)
            .try_collect()
            .await?;
        Ok(bodies.concat())
    }
}

/// Documents are concatenated, and each is line-based, so a body that does
/// not end its last line would glue it to the next document's first.
fn with_trailing_newline(mut body: String) -> String {
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body
}
