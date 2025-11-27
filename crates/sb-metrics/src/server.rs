//! Server metrics module / 服务器指标模块
//!
//! Placeholder for future server-specific metrics collection.
//! 未来服务器特定指标收集的占位符。
//!
//! ## Strategic Logic / 战略逻辑
//! "Monitoring the Monitor". We need to know if the metrics server itself is under load,
//! as a slow metrics endpoint can cause gaps in observability data.
//!
//! "监控监控者"。我们需要知道指标服务器本身是否处于负载之下，
//! 因为缓慢的指标端点会导致观测数据出现缺口。

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
