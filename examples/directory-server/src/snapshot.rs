//! A built seed as the server holds it: named, hashed, compressed once, and
//! described by the manifest the gateway reads first.

use serde::Serialize;
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use webtor_core::seed::BuiltSeed;

/// One seed, ready to serve.
pub struct Snapshot {
    /// `<valid-after>-<content hash>`: unique to these bytes, so a browser
    /// may cache the URL that names it for as long as the seed is valid.
    pub name: String,
    pub json: Vec<u8>,
    pub gzip: Vec<u8>,
    pub relay_count: usize,
    pub valid_after: SystemTime,
    pub fresh_until: SystemTime,
    pub valid_until: SystemTime,
}

/// What the gateway reads before it fetches a seed: where the current one is
/// and how long it is good for.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// The seed's URL, relative to the manifest's own.
    pub url: String,
    pub valid_after: String,
    pub fresh_until: String,
    pub valid_until: String,
    pub bytes: usize,
    pub relays: usize,
}

impl Snapshot {
    pub fn new(seed: BuiltSeed) -> Self {
        let json = seed.encoded.into_bytes();
        let hash = hex::encode(Sha256::digest(&json));
        let name = format!("{}-{}", compact_utc(seed.valid_after), &hash[..16]);
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::with_capacity(json.len() / 3),
            flate2::Compression::default(),
        );
        encoder
            .write_all(&json)
            .and_then(|()| encoder.finish())
            .map(|gzip| Self {
                name,
                gzip,
                json,
                relay_count: seed.relay_count,
                valid_after: seed.valid_after,
                fresh_until: seed.fresh_until,
                valid_until: seed.valid_until,
            })
            .expect("compressing into memory does not fail")
    }

    /// The manifest, with the seed's URL as `<base>/<name>.json`.
    pub fn manifest(&self, base: &str) -> Manifest {
        Manifest {
            url: format!("{base}/{}.json", self.name),
            valid_after: iso8601(self.valid_after),
            fresh_until: iso8601(self.fresh_until),
            valid_until: iso8601(self.valid_until),
            bytes: self.json.len(),
            relays: self.relay_count,
        }
    }

    /// How long a browser may keep the seed without asking again: until the
    /// consensus expires, and at least a minute so a seed on its way out is
    /// not refetched by every request in that minute.
    pub fn max_age(&self, now: SystemTime) -> Duration {
        self.valid_until
            .duration_since(now)
            .unwrap_or_default()
            .max(Duration::from_secs(60))
    }
}

/// `YYYYMMDDTHHMMSSZ`, for a name that sorts by time.
fn compact_utc(at: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = civil(at);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// RFC 3339 at second precision, as `Date.parse` reads it.
pub fn iso8601(at: SystemTime) -> String {
    let (year, month, day, hour, minute, second) = civil(at);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Break a time into UTC calendar fields. Times before 1970 do not occur in a
/// consensus and are clamped to the epoch.
fn civil(at: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400) as u32;
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, of_day / 3600, of_day % 3600 / 60, of_day % 60)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    pub(crate) fn seed(valid_after: u64, encoded: &str) -> BuiltSeed {
        BuiltSeed {
            encoded: encoded.to_string(),
            relay_count: 3,
            middle_count: 2,
            hsdir_count: 1,
            valid_after: at(valid_after),
            fresh_until: at(valid_after + 3600),
            valid_until: at(valid_after + 3 * 3600),
        }
    }

    #[test]
    fn times_are_formatted_in_utc() {
        assert_eq!(iso8601(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(at(1_757_001_600)), "2025-09-04T16:00:00Z");
        assert_eq!(compact_utc(at(951_782_400)), "20000229T000000Z");
    }

    #[test]
    fn a_name_carries_the_time_and_the_content() {
        let one = Snapshot::new(seed(1_757_001_600, r#"{"version":3,"a":1}"#));
        let two = Snapshot::new(seed(1_757_001_600, r#"{"version":3,"a":2}"#));
        assert!(one.name.starts_with("20250904T160000Z-"), "{}", one.name);
        assert_eq!(one.name.len(), "20250904T160000Z-".len() + 16);
        assert_ne!(one.name, two.name);
    }

    #[test]
    fn the_gzip_body_inflates_to_the_json() {
        use std::io::Read;
        let snapshot = Snapshot::new(seed(0, r#"{"version":3}"#));
        let mut inflated = Vec::new();
        flate2::read::GzDecoder::new(&snapshot.gzip[..])
            .read_to_end(&mut inflated)
            .unwrap();
        assert_eq!(inflated, snapshot.json);
    }

    #[test]
    fn the_manifest_points_under_the_base() {
        let snapshot = Snapshot::new(seed(1_757_001_600, r#"{"version":3}"#));
        let manifest = snapshot.manifest("/api/directory");
        assert_eq!(manifest.url, format!("/api/directory/{}.json", snapshot.name));
        assert_eq!(manifest.valid_after, "2025-09-04T16:00:00Z");
        assert_eq!(manifest.fresh_until, "2025-09-04T17:00:00Z");
        assert_eq!(manifest.valid_until, "2025-09-04T19:00:00Z");
        assert_eq!(manifest.bytes, snapshot.json.len());
        assert_eq!(manifest.relays, 3);
    }

    #[test]
    fn max_age_runs_to_expiry_but_never_under_a_minute() {
        let snapshot = Snapshot::new(seed(1000, "{}"));
        assert_eq!(snapshot.max_age(at(1000)), Duration::from_secs(3 * 3600));
        assert_eq!(snapshot.max_age(at(1000 + 3 * 3600 - 10)), Duration::from_secs(60));
    }
}
