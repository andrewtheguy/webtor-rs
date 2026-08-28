use crate::error::{Result, TorError};
use std::future::Future;
use std::time::Duration;

pub(crate) async fn sleep(duration: Duration) {
    let milliseconds = duration.as_millis().min(u32::MAX as u128) as u32;
    gloo_timers::future::TimeoutFuture::new(milliseconds).await;
}

pub async fn with_timeout<F, T>(duration: Duration, operation: &str, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    use futures::future::{select, Either};
    use std::pin::pin;

    let milliseconds = duration.as_millis().min(u32::MAX as u128) as u32;
    let future = pin!(future);
    let timeout = pin!(gloo_timers::future::TimeoutFuture::new(milliseconds));
    match select(future, timeout).await {
        Either::Left((result, _)) => result,
        Either::Right((_, _)) => Err(TorError::timeout(format!(
            "{operation} timed out after {duration:?}"
        ))),
    }
}
