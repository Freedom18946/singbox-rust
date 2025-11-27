//! # Concurrency Limiting Dialer / 并发限制拨号器
//!
//! This module provides a dialer wrapper that limits the number of concurrent connection attempts.
//! 该模块提供了一个拨号器包装器，用于限制并发连接尝试的次数。
//!
//! ## Strategic Relevance / 战略关联
//! - **Resource Protection**: Prevents the system from being overwhelmed by too many simultaneous connection attempts.
//!   **资源保护**: 防止系统因过多的同时连接尝试而不堪重负。
//! - **Stability**: Helps maintain stable performance under high load by smoothing out traffic spikes.
//!   **稳定性**: 通过平滑流量峰值，帮助在高负载下保持稳定的性能。

use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::dialer::{DialError, Dialer, IoStream};

/// Dialer wrapper with concurrency limiting and queue timeout.
/// 具有并发限制和队列超时的拨号器包装器。
#[derive(Clone)]
pub struct LimitedDialer<D: Dialer + Clone> {
    inner: D,
    sem: Arc<Semaphore>,
    queue_ms: u64,
}

impl<D: Dialer + Clone> LimitedDialer<D> {
    /// Create a new limited dialer
    /// 创建一个新的受限拨号器
    pub fn new(inner: D, max: usize, queue_ms: u64) -> Self {
        let max = max.max(1);
        Self {
            inner,
            sem: Arc::new(Semaphore::new(max)),
            queue_ms,
        }
    }

    /// Create with configuration from environment variables
    /// 使用环境变量中的配置创建
    pub fn from_env(inner: D) -> Self {
        let max = std::env::var("SB_DIAL_MAX_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(128);
        let q = std::env::var("SB_DIAL_QUEUE_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5000);
        Self::new(inner, max, q)
    }
}

#[async_trait::async_trait]
impl<D: Dialer + Clone + Send + Sync> Dialer for LimitedDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // Acquire a permit from the semaphore
        // 从信号量获取许可
        let permit = match tokio::time::timeout(
            std::time::Duration::from_millis(self.queue_ms),
            self.sem.acquire(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into()),
            Err(_elapsed) => return Err(DialError::Other("queue_timeout".into())),
        };
        // Proceed with connection
        // 继续连接
        let res = self.inner.connect(host, port).await;
        drop(permit); // release
        res
    }
}

#[cfg(test)]
mod tests {
    #[cfg(disabled_tests)]
    use super::LimitedDialer;
    #[cfg(disabled_tests)]
    use std::sync::Arc;

    #[cfg(disabled_tests)]
    #[tokio::test]
    async fn reject_when_queue_times_out() {
        use crate::dialer::{DialError, FnDialer};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let ctr = Arc::new(AtomicUsize::new(0));
        let d = FnDialer::new({
            let ctr = ctr.clone();
            move |_h, _p| {
                ctr.fetch_add(1, Ordering::Relaxed);
                Box::pin(async {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    Err(DialError::Other("x".into()))
                })
            }
        });
        let ld = LimitedDialer::new(d, 1, 10);
        let t1 = ld.connect("h", 1);
        let t2 = ld.connect("h", 1);
        let (_r1, r2): (
            Result<crate::dialer::IoStream, DialError>,
            Result<crate::dialer::IoStream, DialError>,
        ) = tokio::join!(t1, t2);
        assert!(matches!(r2, Err(DialError::Other(ref s)) if s=="queue_timeout"));
    }

    #[cfg(disabled_tests)]
    #[tokio::test]
    async fn queued_then_ok() {
        use crate::dialer::{DialError, FnDialer};
        let d = FnDialer::new(|_h, _p| {
            Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                Err(DialError::Other("x".into()))
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = Result<crate::dialer::IoStream, DialError>>
                            + Send
                            + 'static,
                    >,
                >
        });
        let ld = LimitedDialer::new(d, 1, 50);
        let _ = ld.connect("h", 1); // in-flight
        let r = ld.connect("h", 1).await; // queued then dequeued
        assert!(r.is_err());
    }

    #[cfg(disabled_tests)]
    #[tokio::test]
    async fn cancel_releases_queue() {
        use crate::dialer::{DialError, FnDialer};
        let d = FnDialer::new(|_h, _p| {
            Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Err(DialError::Other("x".into()))
            })
                as std::pin::Pin<
                    Box<
                        dyn std::future::Future<Output = Result<crate::dialer::IoStream, DialError>>
                            + Send
                            + 'static,
                    >,
                >
        });
        let ld = LimitedDialer::new(d, 1, 50);
        let h = tokio::spawn({
            let ld = ld.clone();
            async move {
                let _ = ld.connect("h", 1).await;
            }
        });
        // Immediately try another but cancel by timing out
        let r =
            tokio::time::timeout(std::time::Duration::from_millis(10), ld.connect("h", 1)).await;
        assert!(r.is_err());
        let _ = h.await;
        // Subsequent acquire should work
        let _ = ld.connect("h", 1).await;
    }
}
