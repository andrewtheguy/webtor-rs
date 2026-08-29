//! The JavaScript global object, whatever kind of scope this runs in.
//!
//! `web_sys::window()` is `Some` only in a document. A dedicated worker, a
//! shared worker and a service worker each have a global scope of their own,
//! and every one of them carries the same `performance` and `fetch` as a
//! window does. Going through `globalThis` is what lets one build of this
//! crate run in all four, which is what a service-worker gateway or a client
//! moved off the main thread needs.

use wasm_bindgen::{JsCast, JsValue};

fn property(name: &str) -> Result<JsValue, JsValue> {
    js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str(name))
}

/// `performance.now()`: monotonic milliseconds since the scope was created.
///
/// Every browser scope has `performance`; the fallback is for a JavaScript
/// host that is not one, and it is `Date.now()` rather than a constant so
/// that an elapsed time measured against it is still a duration. A constant
/// makes every timeout expire never and every backoff wait nothing.
pub(crate) fn performance_now_ms() -> f64 {
    property("performance")
        .ok()
        .and_then(|performance| performance.dyn_into::<web_sys::Performance>().ok())
        .map(|performance| performance.now())
        .unwrap_or_else(js_sys::Date::now)
}

/// `fetch(request)` on the global scope.
pub(crate) fn fetch_with_request(request: &web_sys::Request) -> Result<js_sys::Promise, JsValue> {
    let global = js_sys::global();
    let fetch: js_sys::Function = property("fetch")?.dyn_into()?;
    fetch.call1(&global, request)?.dyn_into()
}
