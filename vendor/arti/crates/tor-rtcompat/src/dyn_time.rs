//! Type-erased browser time provider.

use crate::{CoarseInstant, CoarseTimeProvider, Instant, SleepProvider};
use dyn_clone::DynClone;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

type DynSleepFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

trait DynProvider: DynClone + Send + Sync + 'static {
    fn now(&self) -> Instant;
    fn wallclock(&self) -> SystemTime;
    fn sleep(&self, duration: Duration) -> DynSleepFuture;
    fn block_advance(&self, reason: String);
    fn release_advance(&self, reason: String);
    fn allow_one_advance(&self, duration: Duration);
    fn now_coarse(&self) -> CoarseInstant;
}

dyn_clone::clone_trait_object!(DynProvider);

impl<R: SleepProvider + CoarseTimeProvider> DynProvider for R {
    fn now(&self) -> Instant {
        SleepProvider::now(self)
    }

    fn wallclock(&self) -> SystemTime {
        SleepProvider::wallclock(self)
    }

    fn sleep(&self, duration: Duration) -> DynSleepFuture {
        Box::pin(SleepProvider::sleep(self, duration))
    }

    fn block_advance(&self, reason: String) {
        SleepProvider::block_advance(self, reason);
    }

    fn release_advance(&self, reason: String) {
        SleepProvider::release_advance(self, reason);
    }

    fn allow_one_advance(&self, duration: Duration) {
        SleepProvider::allow_one_advance(self, duration);
    }

    fn now_coarse(&self) -> CoarseInstant {
        CoarseTimeProvider::now_coarse(self)
    }
}

/// Type-erased [`SleepProvider`] and [`CoarseTimeProvider`].
#[derive(Clone)]
pub struct DynTimeProvider(Box<dyn DynProvider>);

impl std::fmt::Debug for DynTimeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DynTimeProvider")
    }
}

impl DynTimeProvider {
    /// Erase the concrete provider type.
    pub fn new<R: SleepProvider + CoarseTimeProvider>(provider: R) -> Self {
        Self(Box::new(provider))
    }
}

impl SleepProvider for DynTimeProvider {
    type SleepFuture = DynSleepFuture;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        self.0.sleep(duration)
    }

    fn now(&self) -> Instant {
        self.0.now()
    }

    fn wallclock(&self) -> SystemTime {
        self.0.wallclock()
    }

    fn block_advance<T: Into<String>>(&self, reason: T) {
        self.0.block_advance(reason.into());
    }

    fn release_advance<T: Into<String>>(&self, reason: T) {
        self.0.release_advance(reason.into());
    }

    fn allow_one_advance(&self, duration: Duration) {
        self.0.allow_one_advance(duration);
    }
}

impl CoarseTimeProvider for DynTimeProvider {
    fn now_coarse(&self) -> CoarseInstant {
        self.0.now_coarse()
    }
}
