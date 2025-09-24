//! Server metrics module placeholder
use once_cell::sync::Lazy;
use prometheus::{opts, register_int_counter, IntCounter};

/// Placeholder server metrics
pub static SERVER_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(opts!("server_requests_total", "Total server requests"))
        .expect("register server_requests_total")
});
