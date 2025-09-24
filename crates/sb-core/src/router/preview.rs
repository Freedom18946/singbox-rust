//! R113: 订阅→DSL（外部完成）后的"临时索引"预览：构建索引并做 explain，不触全局状态
use super::*;

#[cfg(feature = "dsl_derive")]
pub use super::dsl_derive::{derive_compare_targets, derive_targets};
#[cfg(feature = "dsl_analyze")]
pub use super::dsl_inspect::{analysis_to_json, analyze_dsl};
#[cfg(feature = "dsl_plus")]
use super::dsl_plus::expand_dsl_plus;

/// 从 DSL 文本构建 RouterIndex；失败返回 Err 字符串
pub fn build_index_from_rules(text: &str) -> Result<Arc<RouterIndex>, String> {
    // 采用环境变量或默认上限
    let max = std::env::var("SB_ROUTER_RULES_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(8192);
    match router_build_index_from_str(text, max) {
        Ok(idx) => Ok(idx),
        Err(e) => Err(format!("{:?}", e)),
    }
}

/// 在给定索引上进行 HTTP 决策 explain（纯离线，不触 DNS）
pub fn preview_decide_http(
    idx: &Arc<RouterIndex>,
    target: &str,
) -> crate::router::engine::DecisionExplain {
    let (host_raw, port_opt) = if let Some((h, p)) = target.rsplit_once(':') {
        (h, p.parse::<u16>().ok())
    } else {
        (target, None)
    };
    let host = normalize_host(host_raw);
    if let Some(d) = super::router_index_decide_exact_suffix(idx, &host) {
        let k = if idx.exact.contains_key(&host) {
            "exact"
        } else {
            "suffix"
        };
        return crate::router::engine::DecisionExplain {
            decision: d.to_string(),
            reason: format!("{} matched host={}", k, host),
            reason_kind: k.into(),
        };
    }
    #[cfg(feature = "router_keyword")]
    {
        if let Some(index) = &idx.keyword_idx {
            if let Some(i) = index.find_idx(&host) {
                let dec = index
                    .decs
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| idx.default.to_string());
                return crate::router::engine::DecisionExplain {
                    decision: dec,
                    reason: format!("keyword matched host={}", host),
                    reason_kind: "keyword".into(),
                };
            }
        }
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(d) = super::router_index_decide_ip(idx, ip) {
            return crate::router::engine::DecisionExplain {
                decision: d.to_string(),
                reason: format!("ip matched ip={}", ip),
                reason_kind: "ip".into(),
            };
        }
    }
    if let Some(d) = super::router_index_decide_transport_port(idx, port_opt, Some("tcp")) {
        let k = if port_opt.is_some() {
            "port"
        } else {
            "transport"
        };
        return crate::router::engine::DecisionExplain {
            decision: d.to_string(),
            reason: format!("transport/port matched transport=tcp port={:?}", port_opt),
            reason_kind: k.into(),
        };
    }
    crate::router::engine::DecisionExplain {
        decision: idx.default.to_string(),
        reason: "default".into(),
        reason_kind: "default".into(),
    }
}

/// 在给定索引上进行 UDP 决策 explain（纯离线，不触 DNS）
pub fn preview_decide_udp(
    idx: &Arc<RouterIndex>,
    host: &str,
) -> crate::router::engine::DecisionExplain {
    let host_norm = normalize_host(host);
    if let Some(d) = super::router_index_decide_exact_suffix(idx, &host_norm) {
        let k = if idx.exact.contains_key(&host_norm) {
            "exact"
        } else {
            "suffix"
        };
        return crate::router::engine::DecisionExplain {
            decision: d.to_string(),
            reason: format!("{} matched host={}", k, host_norm),
            reason_kind: k.into(),
        };
    }
    #[cfg(feature = "router_keyword")]
    {
        if let Some(index) = &idx.keyword_idx {
            if let Some(i) = index.find_idx(&host_norm) {
                let dec = index
                    .decs
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| idx.default.to_string());
                return crate::router::engine::DecisionExplain {
                    decision: dec,
                    reason: format!("keyword matched host={}", host_norm),
                    reason_kind: "keyword".into(),
                };
            }
        }
    }
    if let Ok(ip) = host_norm.parse::<IpAddr>() {
        if let Some(d) = super::router_index_decide_ip(idx, ip) {
            return crate::router::engine::DecisionExplain {
                decision: d.to_string(),
                reason: format!("ip matched ip={}", ip),
                reason_kind: "ip".into(),
            };
        }
    }
    if let Some(d) = super::router_index_decide_transport_port(idx, None, Some("udp")) {
        return crate::router::engine::DecisionExplain {
            decision: d.to_string(),
            reason: "transport/port matched transport=udp".into(),
            reason_kind: "transport".into(),
        };
    }
    crate::router::engine::DecisionExplain {
        decision: idx.default.to_string(),
        reason: "default".into(),
        reason_kind: "default".into(),
    }
}

/// 在启用 dsl_plus 时，先展开 DSL+，再复用原构建器。
/// cwd 为相对 include 的根目录（通常来自 CLI 的 --cwd 或 dsl 文件所在目录）。
#[cfg(feature = "dsl_plus")]
pub fn build_index_from_rules_plus(
    dsl_text: &str,
    cwd: Option<&std::path::Path>,
) -> Result<Arc<RouterIndex>, String> {
    let expanded = expand_dsl_plus(dsl_text, cwd)?;
    build_index_from_rules(&expanded)
}

/// R139: 批量预演多个 HTTP 目标
pub fn preview_decide_many_http(
    idx: &Arc<RouterIndex>,
    targets: &[String],
) -> Vec<crate::router::engine::DecisionExplain> {
    targets
        .iter()
        .map(|target| preview_decide_http(idx, target))
        .collect()
}
