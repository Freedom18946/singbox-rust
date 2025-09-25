//! 通用小工具
#![allow(dead_code)]
use std::time::Duration;

pub mod env;
#[cfg(feature = "chaos")]
pub mod failpoint;
pub mod token_bucket;
pub mod fs_atomic;

pub fn secs_opt_to_duration(v: Option<u64>, default: u64) -> Duration {
    Duration::from_secs(v.unwrap_or(default))
}

/// Simple fast random index function for load balancing
/// Uses a mix of hash and timestamp for pseudo-randomness
pub fn fast_rand_idx(slice_len: usize) -> usize {
    if slice_len == 0 {
        return 0;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = now.wrapping_mul(2654435761u128) ^ now.wrapping_shr(32);
    (hash as usize) % slice_len
}

/// Alternative fast random index function (used by P2 selector)
pub fn fast_rand_idx2(slice_len: usize) -> usize {
    fast_rand_idx(slice_len)
}
