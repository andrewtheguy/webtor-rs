use crate::time::system_time_now;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tor_rtcompat::CoarseInstant;
use tor_rtcompat::RealCoarseTimeProvider;
use tor_rtcompat::{CoarseTimeProvider, SleepProvider};

#[derive(Clone, Debug)]
pub struct WasmRuntime {
    coarse: RealCoarseTimeProvider,
}

impl WasmRuntime {
    pub fn new() -> Self {
        Self {
            coarse: RealCoarseTimeProvider::new(),
        }
    }
}

impl CoarseTimeProvider for WasmRuntime {
    fn now_coarse(&self) -> CoarseInstant {
        self.coarse.now_coarse()
    }
}

impl SleepProvider for WasmRuntime {
    type SleepFuture = WasmSleep;

    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        WasmSleep::new(duration)
    }

    fn wallclock(&self) -> std::time::SystemTime {
        system_time_now()
    }
}

pub struct WasmSleep {
    rx: futures::channel::oneshot::Receiver<()>,
}

impl WasmSleep {
    fn new(duration: Duration) -> Self {
        let (tx, rx) = futures::channel::oneshot::channel();

        // `setTimeout` takes a signed 32-bit delay and treats an overflow as
        // zero, which would turn a very long sleep into a busy loop.
        let millis = u32::try_from(duration.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX as u32);

        // The oneshot is what makes this future `Send`, as `SleepProvider`
        // requires; the timer itself is a JavaScript object and cannot be.
        // gloo schedules on `globalThis`, so this sleeps in a worker as well.
        gloo_timers::callback::Timeout::new(millis, move || {
            let _ = tx.send(());
        })
        .forget();

        Self { rx }
    }
}

impl Future for WasmSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use futures::FutureExt;
        match self.rx.poll_unpin(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}
