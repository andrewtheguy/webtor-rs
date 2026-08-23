//! No-op memory accounting used by the browser Tor client.

#[macro_use]
mod memory_cost_derive;

mod error;
mod internal_prelude;
pub mod memory_cost;
pub mod mq_queue;
pub mod mtracker;

mod private {
    pub trait Sealed {}
}

/// Uninhabited proof token: browser builds never enable quota tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnabledToken {}

impl EnabledToken {
    /// Browser builds always return `None` because accounting is disabled.
    pub const fn new_if_compiled_in() -> Option<Self> {
        None
    }
}

pub use error::{Error, MemoryReclaimedError};
pub use memory_cost::HasMemoryCost;
pub use memory_cost_derive::{HasMemoryCostStructural, assert_copy_static};
pub use mtracker::{Account, MemoryQuotaTracker};

#[doc(hidden)]
pub use derive_deftly;

/// Result type used by memory-aware queues.
pub type Result<T> = std::result::Result<T, Error>;
