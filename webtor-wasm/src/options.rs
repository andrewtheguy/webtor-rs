//! Reading typed fields out of the plain objects the JS API takes.
//!
//! Every option bag is validated the same way: a field has one accepted type
//! and a key nobody recognises is an error. A silently ignored `maxMessageSize`
//! would leave the caller believing a limit is in force that is not, and the
//! bootstrap it misconfigures takes minutes to fail.

use wasm_bindgen::prelude::*;

/// The option bag itself. `wasm_bindgen` has already rejected anything that
/// is not an object, but an array and a function are objects in JavaScript and
/// neither is a plausible bag; passing one is a mistake worth naming.
pub(crate) fn bag(
    value: Option<js_sys::Object>,
    what: &str,
) -> Result<Option<js_sys::Object>, JsValue> {
    let Some(object) = value else { return Ok(None) };
    if js_sys::Array::is_array(&object) || object.is_function() {
        return Err(error(format!("{what} options must be a plain object")));
    }
    Ok(Some(object))
}

pub(crate) fn error(message: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

/// Fail on any key not in `allowed`, so a misspelled option is loud.
pub(crate) fn reject_unknown_keys(
    bag: &Option<js_sys::Object>,
    what: &str,
    allowed: &[&str],
) -> Result<(), JsValue> {
    let Some(bag) = bag else { return Ok(()) };
    for key in js_sys::Object::keys(bag).iter() {
        let key = key.as_string().unwrap_or_default();
        if !allowed.contains(&key.as_str()) {
            return Err(error(format!(
                "{what} has no option {key:?}; known options are {}",
                allowed.join(", ")
            )));
        }
    }
    Ok(())
}

/// The raw value of a field; `undefined` when absent. Public because a couple
/// of options accept more than one type and read it directly.
pub(crate) fn raw(bag: &Option<js_sys::Object>, key: &str) -> JsValue {
    let Some(bag) = bag else {
        return JsValue::UNDEFINED;
    };
    js_sys::Reflect::get(bag, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

fn present(value: &JsValue) -> bool {
    !value.is_undefined() && !value.is_null()
}

pub(crate) fn string(
    bag: &Option<js_sys::Object>,
    key: &str,
    what: &str,
) -> Result<Option<String>, JsValue> {
    let value = raw(bag, key);
    if !present(&value) {
        return Ok(None);
    }
    value
        .as_string()
        .map(Some)
        .ok_or_else(|| error(format!("{what} option {key:?} must be a string")))
}

pub(crate) fn boolean(
    bag: &Option<js_sys::Object>,
    key: &str,
    what: &str,
) -> Result<Option<bool>, JsValue> {
    let value = raw(bag, key);
    if !present(&value) {
        return Ok(None);
    }
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| error(format!("{what} option {key:?} must be a boolean")))
}

/// A duration or size in whole units: a non-negative, finite integer.
pub(crate) fn count(
    bag: &Option<js_sys::Object>,
    key: &str,
    what: &str,
) -> Result<Option<u64>, JsValue> {
    let value = raw(bag, key);
    if !present(&value) {
        return Ok(None);
    }
    let number = value
        .as_f64()
        .filter(|number| number.is_finite() && *number >= 0.0 && number.fract() == 0.0)
        .ok_or_else(|| {
            error(format!(
                "{what} option {key:?} must be a non-negative whole number"
            ))
        })?;
    Ok(Some(number as u64))
}

pub(crate) fn string_array(
    bag: &Option<js_sys::Object>,
    key: &str,
    what: &str,
) -> Result<Option<Vec<String>>, JsValue> {
    let value = raw(bag, key);
    if !present(&value) {
        return Ok(None);
    }
    let array = value
        .dyn_ref::<js_sys::Array>()
        .ok_or_else(|| error(format!("{what} option {key:?} must be an array of strings")))?;
    array
        .iter()
        .map(|item| {
            item.as_string()
                .ok_or_else(|| error(format!("{what} option {key:?} must be an array of strings")))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// A `{name: value}` object of string headers, kept in insertion order.
pub(crate) fn string_map(
    bag: &Option<js_sys::Object>,
    key: &str,
    what: &str,
) -> Result<Vec<(String, String)>, JsValue> {
    let value = raw(bag, key);
    if !present(&value) {
        return Ok(Vec::new());
    }
    let object = value
        .dyn_ref::<js_sys::Object>()
        .filter(|object| !js_sys::Array::is_array(object))
        .ok_or_else(|| {
            error(format!(
                "{what} option {key:?} must be an object of string values"
            ))
        })?;
    let mut pairs = Vec::new();
    for entry in js_sys::Object::entries(object).iter() {
        let entry = js_sys::Array::from(&entry);
        let name = entry.get(0).as_string().unwrap_or_default();
        let value = entry.get(1).as_string().ok_or_else(|| {
            error(format!(
                "{what} option {key:?} value for {name:?} must be a string"
            ))
        })?;
        pairs.push((name, value));
    }
    Ok(pairs)
}

/// A request body: a string is sent as UTF-8, a `Uint8Array` verbatim.
pub(crate) fn body(
    bag: &Option<js_sys::Object>,
    key: &str,
    what: &str,
) -> Result<Option<Vec<u8>>, JsValue> {
    let value = raw(bag, key);
    if !present(&value) {
        return Ok(None);
    }
    if let Some(text) = value.as_string() {
        return Ok(Some(text.into_bytes()));
    }
    if let Some(bytes) = value.dyn_ref::<js_sys::Uint8Array>() {
        return Ok(Some(bytes.to_vec()));
    }
    Err(error(format!(
        "{what} option {key:?} must be a string or a Uint8Array"
    )))
}
