//! Routes `tracing` warnings and errors from webtor and the Arti crates to
//! the browser console. Nothing else observes those events in a browser, so
//! without this a circuit reactor's exit reason is lost.

use std::fmt::Write as _;
use std::sync::Once;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

struct ConsoleSubscriber;

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

impl Subscriber for ConsoleSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= Level::WARN
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let line = format!("[tor {}] {}", event.metadata().target(), visitor.0);
        let value = wasm_bindgen::JsValue::from_str(&line);
        if *event.metadata().level() == Level::ERROR {
            web_sys::console::error_1(&value);
        } else {
            web_sys::console::warn_1(&value);
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Install the console subscriber once per page.
pub(crate) fn install() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = tracing::subscriber::set_global_default(ConsoleSubscriber);
    });
}
