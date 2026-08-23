//! Errors exposed by memory-aware browser queues.

use tor_error::{Bug, ErrorKind, HasKind};

/// Error raised by a memory-aware queue.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Internal invariant failure.
    #[error("internal error")]
    Bug(#[from] Bug),
}

/// A queue was discarded because of resource pressure.
#[derive(Debug, Clone, thiserror::Error, Default)]
#[error("data structure discarded due to memory pressure")]
pub struct MemoryReclaimedError;

impl MemoryReclaimedError {
    /// Construct a reclaimed-memory error.
    pub const fn new() -> Self {
        Self
    }
}

impl From<Error> for MemoryReclaimedError {
    fn from(_error: Error) -> Self {
        Self
    }
}

impl HasKind for Error {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Bug(error) => error.kind(),
        }
    }
}

impl HasKind for MemoryReclaimedError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::LocalResourceExhausted
    }
}
