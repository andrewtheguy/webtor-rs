//! Reduced-precision-compatible time wrappers backed by the WASM clock.

use crate::CoarseTimeProvider;
use std::time::Duration;

/// Duration used with [`CoarseInstant`].
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CoarseDuration(Duration);

/// Monotonic timestamp used by the Tor protocol implementation.
#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct CoarseInstant(web_time::Instant);

impl From<Duration> for CoarseDuration {
    fn from(duration: Duration) -> Self {
        Self(duration)
    }
}

impl From<CoarseDuration> for Duration {
    fn from(duration: CoarseDuration) -> Self {
        duration.0
    }
}

impl std::ops::Add<CoarseDuration> for CoarseInstant {
    type Output = Self;

    fn add(self, duration: CoarseDuration) -> Self {
        Self(self.0 + duration.0)
    }
}

impl std::ops::AddAssign<CoarseDuration> for CoarseInstant {
    fn add_assign(&mut self, duration: CoarseDuration) {
        *self = *self + duration;
    }
}

impl std::ops::Sub<CoarseDuration> for CoarseInstant {
    type Output = Self;

    fn sub(self, duration: CoarseDuration) -> Self {
        Self(self.0 - duration.0)
    }
}

impl std::ops::SubAssign<CoarseDuration> for CoarseInstant {
    fn sub_assign(&mut self, duration: CoarseDuration) {
        *self = *self - duration;
    }
}

impl std::ops::Sub<CoarseInstant> for CoarseInstant {
    type Output = CoarseDuration;

    fn sub(self, other: CoarseInstant) -> CoarseDuration {
        CoarseDuration(self.0 - other.0)
    }
}

/// Provider using the browser-compatible monotonic clock.
#[derive(Default, Clone, Debug)]
pub struct RealCoarseTimeProvider;

impl RealCoarseTimeProvider {
    /// Construct a provider.
    pub const fn new() -> Self {
        Self
    }
}

impl CoarseTimeProvider for RealCoarseTimeProvider {
    fn now_coarse(&self) -> CoarseInstant {
        CoarseInstant(web_time::Instant::now())
    }
}
