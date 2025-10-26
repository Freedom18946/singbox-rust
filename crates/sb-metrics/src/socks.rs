//! SOCKS 指标模块。
//!
//! 提供 TCP/UDP 常用指标（连接、错误、NAT、数据包计数���。
//! 设计为"可选接线"：适配器可以逐步引入，不会影响功能。
//!
//! ## 模块迁移说明
//! TCP connection metrics have been consolidated into `lib.rs::socks_in` module.
//! Use `sb_metrics::inc_socks_tcp_conn()` from the parent module instead.
//!
//! ## 使用示例
//! ```rust
//! use sb_metrics::socks::{set_udp_nat_size, inc_udp_out, inc_udp_in, add_udp_nat_evictions};
//!
//! // 设置 NAT 表大小
//! set_udp_nat_size(100);
//!
//! // 记录 UDP 包
//! inc_udp_out();
//! inc_udp_in();
//!
//! // 记录 NAT 淘汰
//! add_udp_nat_evictions(5);
//! ```

use prometheus::{opts, register_int_counter, register_int_gauge, IntCounter, IntGauge};
use std::sync::LazyLock;

// =============================
// UDP 侧
// =============================

/// 当前 UDP NAT 表大小
pub static UDP_NAT_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(opts!("socks_udp_nat_size", "Current UDP NAT entries"))
        .unwrap_or_else(|_| {
            #[allow(clippy::unwrap_used)] // Fallback dummy gauge initialization
            IntGauge::new("dummy_gauge", "dummy").unwrap()
        })
});

/// UDP NAT 淘汰条目累计
pub static UDP_NAT_EVICTIONS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "socks_udp_nat_evictions_total",
        "Total UDP NAT eviction entries"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 从客户端发往远端的 UDP 包总数（out）
pub static UDP_PKTS_OUT_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "socks_udp_pkts_out_total",
        "Total UDP packets forwarded from client to remote"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
});

/// 从远端返回到客户端的 UDP 包总数（in）
pub static UDP_PKTS_IN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(opts!(
        "socks_udp_pkts_in_total",
        "Total UDP packets forwarded from remote to client"
    ))
    .unwrap_or_else(|_| {
        #[allow(clippy::unwrap_used)] // Fallback dummy counter initialization
        IntCounter::new("dummy_counter", "dummy").unwrap()
    })
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
