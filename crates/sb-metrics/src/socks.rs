//! SOCKS 指标模块。
//! 提供 TCP/UDP 常用指标（连接、错误、NAT、数据包计数）。
//! 设计为"可选接线"：适配器可以逐步引入，不会影响功能。
use prometheus::{opts, register_int_counter, register_int_gauge, IntCounter, IntGauge};
use std::sync::LazyLock;

// =============================
// TCP 侧
// =============================
/// 新建的 TCP 连接总数
pub static TCP_CONN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "socks_tcp_conn_total",
        "Total TCP connections accepted by SOCKS inbound"
    ))
    .expect("register socks_tcp_conn_total")
});

/// TCP 层错误总数
pub static TCP_ERROR_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "socks_tcp_error_total",
        "Total TCP errors observed by SOCKS inbound"
    ))
    .expect("register socks_tcp_error_total")
});

// =============================
// UDP 侧
// =============================
/// 当前 UDP NAT 表大小
pub static UDP_NAT_SIZE: LazyLock<IntGauge> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_gauge!(opts!("socks_udp_nat_size", "Current UDP NAT entries"))
        .expect("register socks_udp_nat_size")
});

/// UDP NAT 淘汰条目累计
pub static UDP_NAT_EVICTIONS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "socks_udp_nat_evictions_total",
        "Total UDP NAT eviction entries"
    ))
    .expect("register socks_udp_nat_evictions_total")
});

/// 从客户端发往远端的 UDP 包总数（out）
pub static UDP_PKTS_OUT_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "socks_udp_pkts_out_total",
        "Total UDP packets forwarded from client to remote"
    ))
    .expect("register socks_udp_pkts_out_total")
});

/// 从远端返回到客户端的 UDP 包总数（in）
pub static UDP_PKTS_IN_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    register_int_counter!(opts!(
        "socks_udp_pkts_in_total",
        "Total UDP packets forwarded from remote to client"
    ))
    .expect("register socks_udp_pkts_in_total")
});

// =============================
// 便捷函数（可选）
// =============================
pub fn inc_tcp_conn() {
    TCP_CONN_TOTAL.inc();
}
pub fn inc_tcp_error() {
    TCP_ERROR_TOTAL.inc();
}
pub fn set_udp_nat_size(sz: usize) {
    UDP_NAT_SIZE.set(i64::try_from(sz).unwrap_or(i64::MAX));
}
pub fn add_udp_nat_evictions(n: u64) {
    UDP_NAT_EVICTIONS_TOTAL.inc_by(n);
}
pub fn inc_udp_out() {
    UDP_PKTS_OUT_TOTAL.inc();
}
pub fn inc_udp_in() {
    UDP_PKTS_IN_TOTAL.inc();
}
