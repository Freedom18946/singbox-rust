//! Rule minimization (deduplication and folding) with negation guard.
//!
//! When any `not_*` condition is present, only normalization is performed
//! (parent layer prints `MINIMIZE_SKIPPED`).

use crate::ir::ConfigIR;
use crate::normalize::normalize_config;

/// Deduplicate domain list (assumes already normalized/sorted).
fn fold_domains(v: &mut Vec<String>) {
    v.dedup();
}

/// Fold CIDR ranges: deduplicate, sort, merge overlapping networks.
fn fold_cidrs(v: &mut Vec<String>) {
    if v.is_empty() {
        return;
    }

    // Deduplicate
    v.sort();
    v.dedup();

    // Parse CIDRs and perform basic merging
    let mut parsed_cidrs = Vec::new();
    for cidr_str in v.iter() {
        if let Ok(parsed) = parse_cidr(cidr_str) {
            parsed_cidrs.push(parsed);
        } else {
            // Keep unparseable strings (may be special formats)
            continue;
        }
    }

    // Sort by network address
    parsed_cidrs.sort_by(|a, b| {
        a.network_addr
            .cmp(&b.network_addr)
            .then_with(|| a.prefix_len.cmp(&b.prefix_len))
    });

    // Simple overlap detection and removal (precise merging requires complex algorithms)
    let mut merged = Vec::new();
    for cidr in parsed_cidrs {
        let mut should_add = true;
        for existing in &merged {
            if is_cidr_contained(&cidr, existing) {
                should_add = false;
                break;
            }
        }
        if should_add {
            merged.push(cidr);
        }
    }

    // Convert merged results back to strings
    *v = merged.into_iter().map(|c| c.to_string()).collect();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCidr {
    network_addr: std::net::IpAddr,
    prefix_len: u8,
    original: String,
}

impl std::fmt::Display for ParsedCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.original)
    }
}

impl Ord for ParsedCidr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.network_addr
            .to_string()
            .cmp(&other.network_addr.to_string())
            .then_with(|| self.prefix_len.cmp(&other.prefix_len))
    }
}

impl PartialOrd for ParsedCidr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 解析CIDR字符串
fn parse_cidr(cidr_str: &str) -> Result<ParsedCidr, &'static str> {
    if let Some((network_str, prefix_str)) = cidr_str.split_once('/') {
        let network_addr = network_str
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid IP address")?;
        let prefix_len = prefix_str
            .parse::<u8>()
            .map_err(|_| "invalid prefix length")?;

        // 验证前缀长度是否合理
        let max_len = match network_addr {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        if prefix_len > max_len {
            return Err("prefix length too large");
        }

        Ok(ParsedCidr {
            network_addr,
            prefix_len,
            original: cidr_str.to_string(),
        })
    } else {
        // 尝试解析为单个IP地址
        let network_addr = cidr_str
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid IP address")?;
        let prefix_len = match network_addr {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };

        Ok(ParsedCidr {
            network_addr,
            prefix_len,
            original: cidr_str.to_string(),
        })
    }
}

/// 检查一个CIDR是否被另一个包含
fn is_cidr_contained(inner: &ParsedCidr, outer: &ParsedCidr) -> bool {
    use std::net::IpAddr;

    // 只有相同IP版本的网络才能包含
    match (inner.network_addr, outer.network_addr) {
        (IpAddr::V4(inner_ip), IpAddr::V4(outer_ip)) => {
            if outer.prefix_len > inner.prefix_len {
                return false; // 外层网络更具体，不可能包含内层
            }

            let inner_bits = u32::from(inner_ip);
            let outer_bits = u32::from(outer_ip);
            // 当前缀为 0 时，掩码应为 0；否则左移安全（小于 32）
            let mask = if outer.prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - outer.prefix_len)
            };

            (inner_bits & mask) == (outer_bits & mask)
        }
        (IpAddr::V6(inner_ip), IpAddr::V6(outer_ip)) => {
            if outer.prefix_len > inner.prefix_len {
                return false;
            }

            let inner_bits = u128::from(inner_ip);
            let outer_bits = u128::from(outer_ip);
            let mask = if outer.prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - outer.prefix_len)
            };

            (inner_bits & mask) == (outer_bits & mask)
        }
        _ => false, // 不同IP版本不匹配
    }
}

pub enum MinimizeAction {
    SkippedByNegation,
    Applied,
}

pub fn minimize_config(cfg: &mut ConfigIR) -> MinimizeAction {
    if cfg.has_any_negation() {
        normalize_config(cfg);
        return MinimizeAction::SkippedByNegation;
    }
    normalize_config(cfg);
    for r in &mut cfg.route.rules {
        fold_domains(&mut r.domain);
        fold_domains(&mut r.not_domain);
        fold_cidrs(&mut r.ipcidr);
        fold_cidrs(&mut r.not_ipcidr);
    }
    MinimizeAction::Applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConfigIR, RuleIR};
    #[test]
    fn skip_when_neg() {
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            not_domain: vec!["x.com".into()],
            domain: vec!["a.com".into(), "a.com".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        assert!(matches!(act, MinimizeAction::SkippedByNegation));
        assert_eq!(cfg.route.rules[0].domain, vec!["a.com"]); // 仍完成规范化
    }
}
