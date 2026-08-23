//! Browser time utilities.

use std::time::Duration;

fn get_performance_now_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}

#[derive(Clone, Copy, Debug)]
pub struct Instant(f64);

impl Instant {
    pub fn now() -> Self {
        Instant(get_performance_now_ms())
    }

    pub fn elapsed(&self) -> Duration {
        let now = get_performance_now_ms();
        Duration::from_secs_f64((now - self.0) / 1000.0)
    }

}

impl std::ops::Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, other: Duration) -> Instant {
        Instant(self.0 + other.as_secs_f64() * 1000.0)
    }
}

impl std::ops::Sub<Duration> for Instant {
    type Output = Instant;
    fn sub(self, other: Duration) -> Instant {
        Instant((self.0 - other.as_secs_f64() * 1000.0).max(0.0))
    }
}

pub fn system_time_now() -> std::time::SystemTime {
    let ms = js_sys::Date::now();
    std::time::UNIX_EPOCH + Duration::from_millis(ms as u64)
}
