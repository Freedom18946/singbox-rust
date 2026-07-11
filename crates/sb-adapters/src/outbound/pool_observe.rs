//! Observation helper for adapter-owned endpoint pools.

use super::pool_selector::PoolSelector;
use std::time::Instant;

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
    let result = f().await;
    let duration_ms = start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    match &result {
        Ok(_) => tracing::debug!(
            pool = pool_name,
            endpoint = endpoint_index,
            duration_ms,
            "pool observation: success"
        ),
        Err(_) => tracing::debug!(
            pool = pool_name,
            endpoint = endpoint_index,
            duration_ms,
            "pool observation: failure"
        ),
    }
    result
}
