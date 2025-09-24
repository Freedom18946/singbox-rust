use std::time::Duration;
use tokio::time::{timeout, error::Elapsed, Instant};

/// 竞速超时：在超时内完成 `fut`，否则返回 Elapsed
pub async fn race_timeout<F, T>(d: Duration, fut: F) -> Result<T, Elapsed>
where
    F: std::future::Future<Output = T>,
{
    timeout(d, fut).await
}

/// 计时结果
pub struct Timed<T> {
    pub value: T,
    pub elapsed: Duration,
}

/// 执行并统计耗时
pub async fn measure<F, T>(fut: F) -> Timed<T>
where
    F: std::future::Future<Output = T>,
{
    let t0 = Instant::now();
    let value = fut.await;
    Timed {
        value,
        elapsed: t0.elapsed(),
    }
}