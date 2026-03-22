//! SOCKS metrics module.
//! SOCKS 指标模块。
//!
//! Provides common metrics for TCP/UDP (connections, errors, NAT, packet counts).
//! Designed as "opt-in wiring": adapters can gradually adopt without breaking functionality.
//! 提供 TCP/UDP 常用指标（连接、错误、NAT、数据包计数）。
//! 设计为"可选接线"：适配器可以逐步引入，不会影响功能。
//!
//! ## Strategic Logic / 战略逻辑
//! SOCKS is the baseline protocol for proxying.
//! Accurate UDP NAT tracking (`UDP_NAT_SIZE`) is crucial for resource management in high-concurrency scenarios (e.g., gaming, voice chat).
//!
//! SOCKS 是代理的基准协议。
//! 准确的 UDP NAT 跟踪 (`UDP_NAT_SIZE`) 对于高并发场景（例如游戏、语音聊天）中的资源管理至关重要。
//!
//! ## Migration Note / 迁移说明
//! TCP connection metrics have been consolidated into `lib.rs::socks_in` module.
//! Use `sb_metrics::inc_socks_tcp_conn()` from the parent module instead.
//! TCP 连接指标已合并到 `lib.rs::socks_in` 模块中。
//! 请改用父模块中的 `sb_metrics::inc_socks_tcp_conn()`。
//!
//! ## Usage Example / 使用示例
//! ```rust
//! use sb_metrics::socks::{set_udp_nat_size, inc_udp_out, inc_udp_in, add_udp_nat_evictions};
//!
//! // Set NAT table size / 设置 NAT 表大小
//! set_udp_nat_size(100);
//!
//! // Record UDP packets / 记录 UDP 包
//! inc_udp_out();
//! inc_udp_in();
//!
//! // Record NAT evictions / 记录 NAT 淘汰
//! add_udp_nat_evictions(5);
//! ```

use crate::{guarded_int_counter, guarded_int_gauge, registered_collector};
use prometheus::{IntCounter, IntGauge};
use std::sync::LazyLock;

// =============================
// UDP 侧
// =============================

/// 当前 UDP NAT 表大小
pub static UDP_NAT_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    registered_collector(
        "socks_udp_nat_size",
        guarded_int_gauge("socks_udp_nat_size", "Current UDP NAT entries"),
    )
});

/// UDP NAT 淘汰条目累计
pub static UDP_NAT_EVICTIONS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    registered_collector(
        "socks_udp_nat_evictions_total",
        guarded_int_counter(
            "socks_udp_nat_evictions_total",
            "Total UDP NAT eviction entries",
        ),
    )
});

/// 从客户端发往远端的 UDP 包总数（out）
pub static UDP_PKTS_OUT_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    registered_collector(
        "socks_udp_pkts_out_total",
        guarded_int_counter(
            "socks_udp_pkts_out_total",
            "Total UDP packets forwarded from client to remote",
        ),
    )
});

/// 从远端返回到客户端的 UDP 包总数（in）
pub static UDP_PKTS_IN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    registered_collector(
        "socks_udp_pkts_in_total",
        guarded_int_counter(
            "socks_udp_pkts_in_total",
            "Total UDP packets forwarded from remote to client",
        ),
    )
});

// =============================
// 便捷函数
// =============================
// Note: TCP convenience functions removed - use parent module functions instead:
// - sb_metrics::inc_socks_tcp_conn()
// - No direct TCP error function in parent, consider using appropriate classifier

/// Set the current UDP NAT table size
pub fn set_udp_nat_size(sz: usize) {
    // For values exceeding i64::MAX, clamp to i64::MAX
    let value = i64::try_from(sz).unwrap_or(i64::MAX);
    UDP_NAT_SIZE.set(value);
}

/// Increment UDP NAT evictions by n
pub fn add_udp_nat_evictions(n: u64) {
    UDP_NAT_EVICTIONS_TOTAL.inc_by(n);
}

/// Increment outbound UDP packet counter
pub fn inc_udp_out() {
    UDP_PKTS_OUT_TOTAL.inc();
}

/// Increment inbound UDP packet counter
pub fn inc_udp_in() {
    UDP_PKTS_IN_TOTAL.inc();
}
