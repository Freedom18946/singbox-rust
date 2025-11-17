//! Server metrics module
//!
//! Placeholder for future server-specific metrics collection.

use prometheus::{opts, register_int_counter, IntCounter};
use std::sync::LazyLock;

/// Total number of server requests handled
pub static SERVER_REQUESTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!("server_requests_total", "Total server requests")).unwrap_or_else(
        |_| {
            #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
            IntCounter::new("dummy_counter", "dummy").unwrap()
        },
    )
});
