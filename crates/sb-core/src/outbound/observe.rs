use std::time::Instant;

use super::selector::{Selector, PoolSelector};

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

/// Pool selector version of with_observation that accepts immutable reference
/// Since static PoolSelector cannot be mutated, this version just logs the observation
pub async fn with_pool_observation<T, E, F, Fut>(
    _selector: &PoolSelector,
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

    // Log the observation since we can't mutate static selector
    match &ret {
        Ok(_) => {
            tracing::debug!(
                pool = pool_name,
                endpoint = endpoint_index,
                duration_ms = dur_ms,
                "Pool observation: success"
            );
        }
        Err(_) => {
            tracing::debug!(
                pool = pool_name,
                endpoint = endpoint_index,
                duration_ms = dur_ms,
                "Pool observation: failure"
            );
        }
    }
    ret
}
