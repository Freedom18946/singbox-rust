//! Server metrics module placeholder
use prometheus::{opts, register_int_counter, IntCounter};
use std::sync::LazyLock;

/// Placeholder server metrics
pub static SERVER_REQUESTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!("server_requests_total", "Total server requests"))
        .expect("register server_requests_total")
});
