//! Metrics constants & label whitelist governance.
//! 新增/修改需评审；CI 可对本文件做变更检测。
#![allow(dead_code)]

/// 基础信息
pub const BUILD_INFO: &str = "sb_build_info";

/// 路由
pub const ROUTE_MATCH_TOTAL: &str = "route_match_total";
pub const ROUTE_EXPLAIN_TOTAL: &str = "route_explain_total";

/// 传输/TLS
pub const TCP_CONNECT_DURATION: &str = "tcp_connect_duration_seconds";
pub const TLS_HANDSHAKE_FAIL_TOTAL: &str = "tls_handshake_fail_total";

/// UDP NAT
pub const UDP_UPSTREAM_MAP_SIZE: &str = "udp_upstream_map_size";
pub const UDP_EVICT_TOTAL: &str = "udp_evict_total";
pub const UDP_TTL_SECONDS: &str = "udp_ttl_seconds";
pub const UDP_UPSTREAM_FAIL_TOTAL: &str = "udp_upstream_fail_total";

/// 选择器（可选）
pub const PROXY_SELECT_SCORE: &str = "proxy_select_score";
pub const PROXY_SELECT_TOTAL: &str = "proxy_select_total";

/// 健康探测
pub const OUTBOUND_UP: &str = "outbound_up";

/// Prom 导出失败（降噪分类）
pub const PROM_HTTP_FAIL: &str = "__PROM_HTTP_FAIL__";

/// 统一标签键
pub const LABEL_RULE: &str = "rule";
pub const LABEL_REASON: &str = "reason";
pub const LABEL_CLASS: &str = "class";
pub const LABEL_OUTBOUND: &str = "outbound";

/// 标签白名单（防止标签爆炸）
pub const LABEL_WHITELIST: &[&str] = &[LABEL_RULE, LABEL_REASON, LABEL_CLASS, LABEL_OUTBOUND];

/// 校验给定标签是否在白名单中
#[must_use]
pub fn is_label_allowed(k: &str) -> bool {
    LABEL_WHITELIST.contains(&k)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labels_are_whitelisted() {
        assert!(is_label_allowed("rule"));
        assert!(!is_label_allowed("tenant_id"));
    }
}
