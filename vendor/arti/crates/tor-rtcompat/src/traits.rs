//! Runtime traits required by the browser Tor channel implementation.

use asynchronous_codec::Framed;
use futures::future::{FutureExt, RemoteHandle};
use futures::task::{Spawn, SpawnError};
use futures::Future;
use std::io::{self, Result as IoResult};
use std::time::{Duration, SystemTime};

/// WASM-compatible monotonic clock instant.
pub use web_time::Instant;

/// A runtime component that can wait until a timer expires.
pub trait SleepProvider: Clone + Send + Sync + 'static {
    /// Future returned by [`SleepProvider::sleep`].
    type SleepFuture: Future<Output = ()> + Send + 'static;

    /// Return a future that becomes ready after `duration`.
    #[must_use = "sleep() returns a future, which does nothing unless used"]
    fn sleep(&self, duration: Duration) -> Self::SleepFuture;

    /// Return the provider's current monotonic time.
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Return the provider's current wall-clock time.
    fn wallclock(&self) -> SystemTime {
        SystemTime::now()
    }

    /// No-op compatibility hook for time-aware algorithms.
    fn block_advance<T: Into<String>>(&self, _reason: T) {}

    /// No-op compatibility hook for time-aware algorithms.
    fn release_advance<T: Into<String>>(&self, _reason: T) {}

    /// No-op compatibility hook for time-aware algorithms.
    fn allow_one_advance(&self, _duration: Duration) {}
}

/// A provider of reduced-precision timestamps.
pub trait CoarseTimeProvider: Clone + Send + Sync + 'static {
    /// Return the provider's current reduced-precision instant.
    fn now_coarse(&self) -> crate::CoarseInstant;
}

/// Extension helpers for spawning instrumented futures.
pub trait SpawnExt: Spawn {
    /// Spawn a task that produces no result.
    #[track_caller]
    fn spawn<Fut>(&self, future: Fut) -> Result<(), SpawnError>
    where
        Fut: Future<Output = ()> + Send + 'static,
    {
        use tracing::Instrument as _;
        self.spawn_obj(Box::new(future.in_current_span()).into())
    }

    /// Spawn a task and return a handle for its result.
    #[track_caller]
    fn spawn_with_handle<Fut>(
        &self,
        future: Fut,
    ) -> Result<RemoteHandle<<Fut as Future>::Output>, SpawnError>
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send,
    {
        let (future, handle) = future.remote_handle();
        self.spawn(future)?;
        Ok(handle)
    }
}

impl<T: Spawn> SpawnExt for T {}

/// Additional operations exposed by a Tor transport stream.
pub trait StreamOps {
    /// Set `TCP_NOTSENT_LOWAT` when the transport supports it.
    fn set_tcp_notsent_lowat(&self, _notsent_lowat: u32) -> IoResult<()> {
        Err(UnsupportedStreamOp::new(
            "set_tcp_notsent_lowat",
            "unsupported object type",
        )
        .into())
    }

    /// Return an independently owned stream-operations handle.
    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        Box::new(NoOpStreamOpsHandle)
    }
}

/// Stream-operations handle for browser transports without TCP socket options.
#[derive(Copy, Clone, Debug, Default)]
pub struct NoOpStreamOpsHandle;

impl StreamOps for NoOpStreamOpsHandle {
    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        Box::new(*self)
    }
}

impl<T: StreamOps, C> StreamOps for Framed<T, C> {
    fn set_tcp_notsent_lowat(&self, notsent_lowat: u32) -> IoResult<()> {
        let inner: &T = self;
        inner.set_tcp_notsent_lowat(notsent_lowat)
    }

    fn new_handle(&self) -> Box<dyn StreamOps + Send + Unpin> {
        let inner: &T = self;
        inner.new_handle()
    }
}

/// Error returned for stream operations unavailable in the browser.
#[derive(Clone, Debug, thiserror::Error)]
#[error("Operation {op} not supported: {reason}")]
pub struct UnsupportedStreamOp {
    op: &'static str,
    reason: &'static str,
}

impl UnsupportedStreamOp {
    /// Construct an unsupported-operation error.
    pub const fn new(op: &'static str, reason: &'static str) -> Self {
        Self { op, reason }
    }
}

impl From<UnsupportedStreamOp> for io::Error {
    fn from(value: UnsupportedStreamOp) -> Self {
        io::Error::new(io::ErrorKind::Unsupported, value)
    }
}

/// A TLS connection that exposes Tor channel authentication material.
pub trait CertifiedConn {
    /// Export RFC 5705 keying material.
    fn export_keying_material(
        &self,
        len: usize,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> IoResult<Vec<u8>>;

    /// Return the peer's DER certificate, if available.
    fn peer_certificate(&self) -> IoResult<Option<Vec<u8>>>;
}
