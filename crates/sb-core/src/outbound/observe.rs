use std::time::Instant;

use super::selector::Selector;

/// Wrap an async operation, measure its duration, and report observation
/// to the selector. This is a lightweight helper with zero behavior change
/// when P2 is disabled via env.
pub async fn with_observation<T, E, F, Fut>(
    selector: &Selector,
    pool_name: &str,
    endpoint_index: usize,
    f: F,
) -> Result<T, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let start = Instant::now();
    let ret = f().await;
    let dur = start.elapsed();
    let dur_ms = dur.as_millis().min(u128::from(u64::MAX)) as u64;
    match &ret {
        Ok(_) => selector.on_observation(pool_name, endpoint_index, dur_ms, true),
        Err(_) => selector.on_observation(pool_name, endpoint_index, dur_ms, false),
    }
    ret
}
