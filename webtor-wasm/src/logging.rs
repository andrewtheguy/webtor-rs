//! Where this binding's log lines go.
//!
//! Two streams of them exist: what the Tor client reports about its own
//! progress, and the `tracing` warnings the Arti crates emit under it —
//! nothing else observes those in a browser, so without a subscriber a
//! circuit reactor's exit reason is lost. Both end up in one sink, and which
//! sink that is belongs to the caller: the console under a prefix, a function
//! of the caller's own, or nothing at all.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, Once};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};
use wasm_bindgen::prelude::*;
use webtor::LogType;

/// A log sink shared by the Tor client and this binding, so progress from
/// both sides of the boundary lands in one place.
pub(crate) type Logger = Arc<dyn Fn(&str, LogType) + Send + Sync>;

/// What a JS `onLog` callback is told a line is.
fn level_name(log_type: LogType) -> &'static str {
    match log_type {
        LogType::Info => "info",
        LogType::Success => "success",
        LogType::Warn => "warn",
        LogType::Error => "error",
    }
}

/// The default sink: the browser console, every line under one prefix.
pub(crate) fn console_logger(prefix: String) -> Logger {
    Arc::new(move |message: &str, log_type: LogType| {
        let rendered = JsValue::from_str(&format!("{prefix} {message}"));
        match log_type {
            LogType::Error => web_sys::console::error_1(&rendered),
            LogType::Warn => web_sys::console::warn_1(&rendered),
            LogType::Info | LogType::Success => web_sys::console::info_1(&rendered),
        }
    })
}

/// A sink the caller supplied, so an application can put Tor progress wherever
/// the rest of its logging goes rather than only in the console.
pub(crate) fn js_logger(callback: js_sys::Function) -> Logger {
    let sink = JsSink(callback);
    // Called through the whole struct on purpose: capturing the function field
    // on its own would leave the closure without the Send and Sync that the
    // struct is what carries.
    Arc::new(move |message: &str, log_type: LogType| sink.emit(message, log_type))
}

/// Drop every line, for a caller that asked for no logging at all.
pub(crate) fn silent() -> Logger {
    Arc::new(|_: &str, _| {})
}

/// A JS callback held where the Tor client wants `Send + Sync`.
struct JsSink(js_sys::Function);

impl JsSink {
    fn emit(&self, message: &str, log_type: LogType) {
        // A callback that throws is the caller's to see in its own stack, not
        // a reason to fail the bootstrap it was reporting on.
        let _ = self.0.call2(
            &JsValue::NULL,
            &JsValue::from_str(message),
            &JsValue::from_str(level_name(log_type)),
        );
    }
}

// Browser WASM is single-threaded, while the client requires its log sink to
// satisfy Send and Sync at the generic boundary.
unsafe impl Send for JsSink {}
unsafe impl Sync for JsSink {}

/// Where `tracing` events go.
///
/// A `tracing` event carries no client identity — the Arti crates emit these
/// from code that knows nothing about which client's circuit it is running —
/// so on a page holding more than one client there is nothing to route by,
/// and the most recently created *logging* client owns this.
static SINK: Mutex<Option<Logger>> = Mutex::new(None);

/// Send `tracing` warnings and errors to `logger`, installing the subscriber
/// the first time a client asks for one.
///
/// `None` leaves whatever is installed alone rather than replacing it with
/// something that discards: a client created with logging off is saying where
/// its own lines go, not silencing a client that is still reporting.
pub(crate) fn install(logger: Option<Logger>) {
    let Some(logger) = logger else { return };
    if let Ok(mut sink) = SINK.lock() {
        *sink = Some(logger);
    }
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(TracingSink);
    });
}

struct TracingSink;

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

impl Subscriber for TracingSink {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::WARN
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        // Cloned out of the lock before it is called: a caller's sink can
        // re-enter WASM, and a line logged from there would deadlock here.
        let Some(logger) = SINK.lock().ok().and_then(|sink| sink.clone()) else {
            return;
        };
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let line = format!("[tor {}] {}", event.metadata().target(), visitor.0);
        let log_type = if *event.metadata().level() == Level::ERROR {
            LogType::Error
        } else {
            LogType::Warn
        };
        logger(&line, log_type);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}
