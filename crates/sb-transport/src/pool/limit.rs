use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::dialer::{DialError, Dialer, IoStream};

/// Dialer wrapper with concurrency limiting and queue timeout.
#[derive(Clone)]
pub struct LimitedDialer<D: Dialer + Clone> {
    inner: D,
    sem: Arc<Semaphore>,
    queue_ms: u64,
}

impl<D: Dialer + Clone> LimitedDialer<D> {
    pub fn new(inner: D, max: usize, queue_ms: u64) -> Self {
        let max = max.max(1);
        Self { inner, sem: Arc::new(Semaphore::new(max)), queue_ms }
    }

    pub fn from_env(inner: D) -> Self {
        let max = std::env::var("SB_DIAL_MAX_CONCURRENCY").ok().and_then(|v| v.parse().ok()).unwrap_or(128);
        let q = std::env::var("SB_DIAL_QUEUE_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
        Self::new(inner, max, q)
    }
}

#[async_trait::async_trait]
impl<D: Dialer + Clone + Send + Sync> Dialer for LimitedDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        let permit = match tokio::time::timeout(std::time::Duration::from_millis(self.queue_ms), self.sem.acquire()).await {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into()),
            Err(_elapsed) => return Err(DialError::Other("queue_timeout".into())),
        };
        let res = self.inner.connect(host, port).await;
        drop(permit); // release
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::{FnDialer, DialError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn reject_when_queue_times_out() {
        let ctr = Arc::new(AtomicUsize::new(0));
        let d = FnDialer::new({ let ctr=ctr.clone(); move |_h,_p| { ctr.fetch_add(1, Ordering::Relaxed); async { tokio::time::sleep(std::time::Duration::from_millis(100)).await; Err(DialError::Other("x".into())) }}});
        let ld = LimitedDialer::new(d, 1, 10);
        let t1 = ld.connect("h", 1);
        let t2 = ld.connect("h", 1);
        let (_r1, r2) = tokio::join!(t1, t2);
        assert!(matches!(r2, Err(DialError::Other(ref s)) if s=="queue_timeout"));
    }

    #[tokio::test]
    async fn queued_then_ok() {
        let d = FnDialer::new(|_h,_p| async { tokio::time::sleep(std::time::Duration::from_millis(5)).await; Err(DialError::Other("x".into())) });
        let ld = LimitedDialer::new(d, 1, 50);
        let _ = ld.connect("h",1); // in-flight
        let r = ld.connect("h",1).await; // queued then dequeued
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn cancel_releases_queue() {
        let d = FnDialer::new(|_h,_p| async { tokio::time::sleep(std::time::Duration::from_millis(50)).await; Err(DialError::Other("x".into())) });
        let ld = LimitedDialer::new(d, 1, 50);
        let h = tokio::spawn({ let ld=ld.clone(); async move { let _ = ld.connect("h",1).await; }});
        // Immediately try another but cancel by timing out
        let r = tokio::time::timeout(std::time::Duration::from_millis(10), ld.connect("h",1)).await;
        assert!(r.is_err());
        let _ = h.await;
        // Subsequent acquire should work
        let _ = ld.connect("h",1).await;
    }
}
