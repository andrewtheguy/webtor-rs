//! A caller's JS function, called with strings for whatever it is told about.

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
