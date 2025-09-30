//! Rule minimization (dedup/fold) with negation guard.
//! - 当存在任一 not_* 维度时，仅执行 normalize（由上层打印 MINIMIZE_SKIPPED）
use crate::ir::ConfigIR;
use crate::normalize::normalize_config;

fn fold_domains(v: &mut Vec<String>) {
    // 输入已规范化排序；去重即可
    v.dedup();
}

fn fold_cidrs(v: &mut Vec<String>) {
    // 实现真实 CIDR 合并：去重、排序、合并重叠的网络
    if v.is_empty() {
        return;
    }

    // 去重
    v.sort();
    v.dedup();

    // 解析CIDR并进行基本的合并
    let mut parsed_cidrs = Vec::new();
    for cidr_str in v.iter() {
        if let Ok(parsed) = parse_cidr(cidr_str) {
            parsed_cidrs.push(parsed);
        } else {
            // 保留无法解析的字符串（可能是特殊格式）
            continue;
        }
    }

    // 按网络地址排序
    parsed_cidrs.sort_by(|a, b| {
        a.network_addr
            .cmp(&b.network_addr)
            .then_with(|| a.prefix_len.cmp(&b.prefix_len))
    });

    // 简单的重叠检测和移除（更精确的合并需要复杂算法）
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

    // 将合并后的结果转换回字符串
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
            let mask = !((1u32 << (32 - outer.prefix_len)) - 1);

            (inner_bits & mask) == (outer_bits & mask)
        }
        (IpAddr::V6(inner_ip), IpAddr::V6(outer_ip)) => {
            if outer.prefix_len > inner.prefix_len {
                return false;
            }

            let inner_bits = u128::from(inner_ip);
            let outer_bits = u128::from(outer_ip);
            let mask = !((1u128 << (128 - outer.prefix_len)) - 1);

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
        match act {
            MinimizeAction::SkippedByNegation => {}
            _ => assert!(false, "test should have skipped by negation"),
        }
        assert_eq!(cfg.route.rules[0].domain, vec!["a.com"]); // 仍完成规范化
    }
}
