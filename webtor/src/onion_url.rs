//! The one URL shape this client resolves: `scheme://<v3 onion>[:port][/path][?query]`.
//!
//! A general URL parser would bring IDNA and its Unicode tables along for
//! hostnames that are, by construction, 56 base32 characters and `.onion`.

use crate::error::{Result, TorError};

/// Length of a v3 onion address before `.onion`: base32 of the 32-byte key,
/// 2-byte checksum and version byte.
const ONION_V3_LABEL_LEN: usize = 56;

/// Whether `host` is a v3 onion address (lower-case base32 label + `.onion`).
pub fn is_onion_host(host: &str) -> bool {
    let Some(label) = host.strip_suffix(".onion") else {
        return false;
    };
    label.len() == ONION_V3_LABEL_LEN
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
}

/// A parsed onion-service URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnionUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

impl OnionUrl {
    /// Parse `raw`. Only `http` and `ws` schemes are known, since those are
    /// the two things carried over an onion stream; both default to port 80.
    pub fn parse(raw: &str) -> Result<Self> {
        let invalid = |reason: &str| TorError::Configuration(format!("Invalid URL {raw:?}: {reason}"));
        let raw = raw.trim();
        let (scheme, rest) = raw.split_once("://").ok_or_else(|| invalid("no scheme"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "ws" {
            return Err(invalid("only http:// and ws:// reach an onion service"));
        }
        if rest.contains('#') {
            return Err(invalid("fragments are not sent to a server"));
        }
        let end_of_authority = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end_of_authority);
        if authority.contains('@') {
            return Err(invalid("credentials are not supported"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse::<u16>().map_err(|_| invalid("bad port"))?,
            ),
            None => (authority, 80),
        };
        let host = host.to_ascii_lowercase();
        if !is_onion_host(&host) {
            return Err(invalid("host is not a v3 onion address"));
        }
        let (path, query) = match tail.split_once('?') {
            Some((path, query)) => (path, Some(query.to_string())),
            None => (tail, None),
        };
        if path.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
            return Err(invalid("path contains whitespace or control characters"));
        }
        let path = if path.is_empty() { "/".to_string() } else { path.to_string() };
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The request-target for an HTTP request line: path plus `?query`.
    pub fn path_and_query(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    #[test]
    fn parses_the_pieces() {
        let url = OnionUrl::parse(&format!("HTTP://{HOST}:8080/api/ip?format=json")).unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host(), HOST);
        assert_eq!(url.port(), 8080);
        assert_eq!(url.path_and_query(), "/api/ip?format=json");
    }

    #[test]
    fn defaults_port_and_path() {
        let url = OnionUrl::parse(&format!("ws://{HOST}")).unwrap();
        assert_eq!(url.port(), 80);
        assert_eq!(url.path_and_query(), "/");
        assert_eq!(OnionUrl::parse(&format!("ws://{HOST}?x=1")).unwrap().path_and_query(), "/?x=1");
    }

    #[test]
    fn rejects_everything_else() {
        for raw in [
            "wss://example.onion",
            &format!("https://{HOST}/"),
            "ws://relay.damus.io",
            "ws://abcdefghijklmnop.onion",
            &format!("ws://user@{HOST}/"),
            &format!("ws://{HOST}/#frag"),
            &format!("ws://{HOST}:99999/"),
            &format!("ws://{HOST}/a b"),
            HOST,
        ] {
            assert!(OnionUrl::parse(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn onion_host_check_is_strict() {
        assert!(is_onion_host(HOST));
        assert!(!is_onion_host(&HOST.to_ascii_uppercase()));
        assert!(!is_onion_host("facebookcorewwwi.onion"));
        assert!(!is_onion_host("example.com"));
    }
}
