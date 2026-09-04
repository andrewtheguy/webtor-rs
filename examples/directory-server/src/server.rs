//! The endpoints the gateway reads, and the task that keeps them fresh.
//!
//! `GET /api/directory` is a small manifest naming the current seed's URL and
//! lifetime; `GET /api/directory/<name>.json` is the seed. The name is unique
//! to the bytes, so the second answer is immutable and a browser keeps it for
//! as long as the consensus is valid — one copy for every onion origin under
//! the gateway, since they all ask the same URL on the same host. The previous
//! seed stays available for a while, so a worker that read the manifest a
//! moment before a refresh still finds what it was told about.

use crate::fetch::Authorities;
use crate::snapshot::Snapshot;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{info, warn};

/// Where the manifest lives, and the prefix of every seed URL.
pub const DIRECTORY_PATH: &str = "/api/directory";

/// How long after the authorities are due to publish a new consensus to ask
/// for it: they publish at `fresh-until`, and a mirror may lag a little.
const PUBLICATION_LAG: Duration = Duration::from_secs(3 * 60);
/// When a fetch comes back with the consensus already on hand, the new one is
/// not out yet; ask again after this.
const UNCHANGED_RETRY: Duration = Duration::from_secs(5 * 60);
/// Failures back off from here, doubling.
const FIRST_RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(15 * 60);

/// The seeds on hand. `previous` is served but no longer advertised.
#[derive(Default)]
pub struct Directory {
    current: Option<Arc<Snapshot>>,
    previous: Option<Arc<Snapshot>>,
}

impl Directory {
    pub fn install(&mut self, snapshot: Snapshot) {
        self.previous = self.current.take();
        self.current = Some(Arc::new(snapshot));
    }

    pub fn current(&self) -> Option<&Arc<Snapshot>> {
        self.current.as_ref()
    }

    fn named(&self, name: &str) -> Option<&Arc<Snapshot>> {
        [&self.current, &self.previous]
            .into_iter()
            .flatten()
            .find(|snapshot| snapshot.name == name)
    }
}

pub type Shared = Arc<RwLock<Directory>>;

/// The router: the two directory endpoints and a health check under `/api`,
/// and, when `web_root` is given, the gateway's built `dist/` behind them,
/// with `index.html` for any other path so the app answers on every origin.
pub fn router(directory: Shared, web_root: Option<PathBuf>) -> Router {
    // Every onion origin under the gateway asks these across origins, and
    // the answer is the same public document for all of them.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::HEAD])
        .allow_headers(Any);
    let api = Router::new()
        .route("/api/health", get(health))
        .route(DIRECTORY_PATH, get(manifest))
        .route(&format!("{DIRECTORY_PATH}/{{name}}"), get(seed))
        .layer(cors)
        .with_state(directory);

    match web_root {
        Some(root) => {
            // `ServeDir` answers a real file; anything else is `index.html`
            // with a 200, because the app reads the onion out of its own
            // hostname and so must load at every path on every origin.
            let index = root.join("index.html");
            let spa_index = tower::service_fn(move |_request: Request<Body>| {
                let index = index.clone();
                async move {
                    let response = match tokio::fs::read(&index).await {
                        Ok(bytes) => {
                            ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], bytes)
                                .into_response()
                        }
                        Err(_) => StatusCode::NOT_FOUND.into_response(),
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            api.fallback_service(ServeDir::new(&root).fallback(spa_index))
        }
        None => api,
    }
}

async fn health(State(directory): State<Shared>) -> Json<serde_json::Value> {
    let directory = directory.read().await;
    Json(json!({
        "ok": true,
        "directory": directory.current().map(|snapshot| snapshot.manifest(DIRECTORY_PATH)),
    }))
}

/// The current seed's manifest, or a 503 with `Retry-After` until the first
/// build has landed. Never cached: it is the one thing that changes.
async fn manifest(State(directory): State<Shared>) -> Response {
    let directory = directory.read().await;
    let mut response = match directory.current() {
        Some(snapshot) => Json(snapshot.manifest(DIRECTORY_PATH)).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "30")],
            Json(json!({ "error": "No Tor directory has been built yet" })),
        )
            .into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// One seed by name. Immutable for as long as the consensus is valid, gzip
/// when the caller takes it, and a 304 when the caller already has it.
async fn seed(
    State(directory): State<Shared>,
    Path(name): Path<String>,
    request_headers: HeaderMap,
) -> Response {
    let Some(name) = name.strip_suffix(".json") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(snapshot) = directory.read().await.named(name).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let etag = format!("\"{}\"", snapshot.name);
    let cache_control = format!(
        "public, max-age={}, immutable",
        snapshot.max_age(SystemTime::now()).as_secs()
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, HeaderValue::from_str(&etag).expect("hex and digits"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&cache_control).expect("ascii"),
    );
    headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    if request_headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|value| value.as_bytes() == etag.as_bytes())
    {
        return (StatusCode::NOT_MODIFIED, headers).into_response();
    }

    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let gzip = accepts_gzip(&request_headers);
    let body = if gzip {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        snapshot.gzip.clone()
    } else {
        snapshot.json.clone()
    };
    info!(
        "Serving directory {} ({}, {} MiB) to {}",
        snapshot.name,
        if gzip { "gzip" } else { "identity" },
        body.len() / (1024 * 1024),
        request_headers
            .get(header::ORIGIN)
            .and_then(|origin| origin.to_str().ok())
            .unwrap_or("a same-origin caller"),
    );
    (headers, body).into_response()
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|coding| coding.trim().split(';').next() == Some("gzip"))
}

/// Build a seed, install it, and keep doing so: a new consensus every hour,
/// when the authorities publish it, and sooner after a failure.
pub async fn refresh_forever(directory: Shared, authorities: Arc<Authorities>) {
    let mut retry = FIRST_RETRY;
    loop {
        let wait = match authorities.build_seed().await {
            Ok(seed) => {
                retry = FIRST_RETRY;
                let now = SystemTime::now();
                let unchanged = directory
                    .read()
                    .await
                    .current()
                    .is_some_and(|current| current.valid_after == seed.valid_after);
                if unchanged {
                    info!("The authorities still serve the consensus already on hand");
                    UNCHANGED_RETRY
                } else {
                    let snapshot = Snapshot::new(seed);
                    info!(
                        "Built directory {} with {} relays, {} MiB ({} MiB gzip), valid until {}",
                        snapshot.name,
                        snapshot.relay_count,
                        snapshot.json.len() / (1024 * 1024),
                        snapshot.gzip.len() / (1024 * 1024),
                        crate::snapshot::iso8601(snapshot.valid_until),
                    );
                    let wait = until_next_consensus(now, snapshot.fresh_until);
                    directory.write().await.install(snapshot);
                    wait
                }
            }
            Err(error) => {
                warn!("Could not build a directory: {error:#}");
                let wait = retry;
                retry = (retry * 2).min(MAX_RETRY);
                wait
            }
        };
        info!("Next directory refresh in {}s", wait.as_secs());
        tokio::time::sleep(wait).await;
    }
}

/// How long to wait before the next consensus should be out: a little past
/// `fresh_until`, and at least a minute so a late clock cannot spin.
pub fn until_next_consensus(now: SystemTime, fresh_until: SystemTime) -> Duration {
    (fresh_until + PUBLICATION_LAG)
        .duration_since(now)
        .unwrap_or_default()
        .max(Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::tests::seed as built_seed;
    use http_body_util::BodyExt;
    use std::time::UNIX_EPOCH;
    use tower::ServiceExt;

    async fn call(router: &Router, path: &str, headers: &[(&str, &str)]) -> Response {
        let mut request = Request::get(path);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
        response.headers().get(name).and_then(|value| value.to_str().ok())
    }

    fn recent() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 600
    }

    #[tokio::test]
    async fn the_manifest_is_unavailable_until_a_seed_is_built() {
        let router = router(Shared::default(), None);
        let response = call(&router, DIRECTORY_PATH, &[]).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(header(&response, "retry-after"), Some("30"));
        assert_eq!(header(&response, "cache-control"), Some("no-cache"));
        assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
    }

    #[tokio::test]
    async fn the_manifest_names_the_seed_and_the_seed_is_immutable() {
        let directory = Shared::default();
        directory
            .write()
            .await
            .install(Snapshot::new(built_seed(recent(), r#"{"version":3}"#)));
        let router = router(directory, None);

        let response = call(&router, DIRECTORY_PATH, &[("origin", "http://a.onion.x")]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
        let manifest = json(response).await;
        let url = manifest["url"].as_str().unwrap().to_string();
        assert!(url.starts_with(&format!("{DIRECTORY_PATH}/")) && url.ends_with(".json"));
        assert_eq!(manifest["bytes"], 13);

        let response = call(&router, &url, &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header(&response, "content-type"), Some("application/json"));
        assert_eq!(header(&response, "content-encoding"), None);
        assert_eq!(header(&response, "vary"), Some("accept-encoding"));
        let cache_control = header(&response, "cache-control").unwrap();
        assert!(cache_control.starts_with("public, max-age=") && cache_control.ends_with(", immutable"));
        let etag = header(&response, "etag").unwrap().to_string();
        assert_eq!(json(response).await, json!({ "version": 3 }));

        let response = call(&router, &url, &[("if-none-match", &etag)]).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn the_seed_is_gzipped_for_a_caller_that_takes_gzip() {
        let directory = Shared::default();
        directory
            .write()
            .await
            .install(Snapshot::new(built_seed(recent(), r#"{"version":3}"#)));
        let name = directory.read().await.current().unwrap().name.clone();
        let router = router(directory, None);
        let response = call(
            &router,
            &format!("{DIRECTORY_PATH}/{name}.json"),
            &[("accept-encoding", "br, gzip;q=0.8")],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header(&response, "content-encoding"), Some("gzip"));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
    }

    #[tokio::test]
    async fn the_previous_seed_stays_served_and_others_are_not() {
        let directory = Shared::default();
        directory
            .write()
            .await
            .install(Snapshot::new(built_seed(recent(), r#"{"version":3,"n":1}"#)));
        let first = directory.read().await.current().unwrap().name.clone();
        directory
            .write()
            .await
            .install(Snapshot::new(built_seed(recent() + 3600, r#"{"version":3,"n":2}"#)));
        let router = router(directory, None);

        let response = call(&router, &format!("{DIRECTORY_PATH}/{first}.json"), &[]).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = call(&router, &format!("{DIRECTORY_PATH}/{first}"), &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = call(&router, &format!("{DIRECTORY_PATH}/nope.json"), &[]).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn health_reports_the_current_directory() {
        let router = router(Shared::default(), None);
        let body = json(call(&router, "/api/health", &[]).await).await;
        assert_eq!(body, json!({ "ok": true, "directory": null }));
    }

    #[test]
    fn the_next_refresh_follows_publication_with_a_floor() {
        let fresh_until = UNIX_EPOCH + Duration::from_secs(10_000);
        assert_eq!(
            until_next_consensus(UNIX_EPOCH + Duration::from_secs(1_000), fresh_until),
            Duration::from_secs(9_000) + PUBLICATION_LAG
        );
        assert_eq!(
            until_next_consensus(UNIX_EPOCH + Duration::from_secs(20_000), fresh_until),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn gzip_is_read_out_of_accept_encoding() {
        let mut headers = HeaderMap::new();
        assert!(!accepts_gzip(&headers));
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br, zstd"));
        assert!(!accepts_gzip(&headers));
        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br, gzip;q=0.5"));
        assert!(accepts_gzip(&headers));
    }
}
