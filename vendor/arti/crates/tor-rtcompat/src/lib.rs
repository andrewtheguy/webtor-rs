//! Browser-focused timing and stream traits used by the retained Tor client.

mod coarse_time;
mod dyn_time;
mod timer;
mod traits;

pub use coarse_time::{CoarseDuration, CoarseInstant, RealCoarseTimeProvider};
pub use dyn_time::DynTimeProvider;
pub use timer::{SleepProviderExt, Timeout, TimeoutError};
pub use traits::{
    CertifiedConn, CoarseTimeProvider, Instant, NoOpStreamOpsHandle, SleepProvider, SpawnExt,
    StreamOps, UnsupportedStreamOp,
};
