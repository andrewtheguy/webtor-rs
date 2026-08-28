//! A JS function held where the Tor client wants `Send + Sync`.
//!
//! The client's callbacks are declared `Send + Sync` because its core is
//! written against a threaded runtime as well as this one. Browser WASM is
//! single-threaded and a `js_sys::Function` never leaves its thread, so the
//! bound is satisfiable here but not derivable — which needs an `unsafe impl`,
//! and this is the one place that carries it.

use wasm_bindgen::prelude::*;

pub(crate) struct JsCallback(js_sys::Function);

impl JsCallback {
    pub(crate) fn new(function: js_sys::Function) -> Self {
        Self(function)
    }

    /// Call it with `arguments`, discarding the result and anything it throws.
    /// A callback that fails is the caller's to see in its own stack, not a
    /// reason to fail the work that was reporting to it.
    pub(crate) fn call(&self, arguments: &[&str]) {
        let list = js_sys::Array::new();
        for argument in arguments {
            list.push(&JsValue::from_str(argument));
        }
        let _ = self.0.apply(&JsValue::NULL, &list);
    }
}

// Nothing here crosses a thread; see the module comment.
unsafe impl Send for JsCallback {}
unsafe impl Sync for JsCallback {}
