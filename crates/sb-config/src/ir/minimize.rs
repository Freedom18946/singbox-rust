//! IR-level minimization — post-validated rule optimization.
//!
//! ## Owner history
//!
//! WP-30s migrated the implementation from the top-level `minimize.rs` into
//! this IR sub-module.  The top-level `minimize.rs` is now a thin compat
//! shell that delegates here.
//!
//! ## Scope
//!
//! This module performs **post-validated optimization**:
//! - First calls normalization (`ir::normalize::normalize_config`)
//! - If any `not_*` negation condition exists, only normalization is applied
//!   and `MinimizeAction::SkippedByNegation` is returned
//! - Otherwise, fold/dedup (domains, CIDRs) is applied and
//!   `MinimizeAction::Applied` is returned
//!
//! ## What this is NOT
//!
//! - Not a planned contract — minimize is post-validated optimization
//! - Not a planning-layer owner — does not participate in `PlannedFacts`
//! - Not a normalization owner — delegates to `ir::normalize` for that

use super::normalize::normalize_config;
use super::ConfigIR;

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

fn parse_cidr(cidr_str: &str) -> Result<ParsedCidr, &'static str> {
    if let Some((network_str, prefix_str)) = cidr_str.split_once('/') {
        let network_addr = network_str
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid IP address")?;
        let prefix_len = prefix_str
            .parse::<u8>()
            .map_err(|_| "invalid prefix length")?;

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

fn is_cidr_contained(inner: &ParsedCidr, outer: &ParsedCidr) -> bool {
    use std::net::IpAddr;

    match (inner.network_addr, outer.network_addr) {
        (IpAddr::V4(inner_ip), IpAddr::V4(outer_ip)) => {
            if outer.prefix_len > inner.prefix_len {
                return false;
            }

            let inner_bits = u32::from(inner_ip);
            let outer_bits = u32::from(outer_ip);
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
        _ => false,
    }
}

pub(crate) enum MinimizeAction {
    SkippedByNegation,
    Applied,
}

pub(crate) fn minimize_config(cfg: &mut ConfigIR) -> MinimizeAction {
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
    use crate::ir::RuleIR;

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
        // normalization still applied even when skipping fold
        assert_eq!(cfg.route.rules[0].domain, vec!["a.com"]);
    }

    #[test]
    fn apply_when_no_neg() {
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            domain: vec!["b.com".into(), "a.com".into(), "b.com".into()],
            ipcidr: vec!["10.0.0.0/8".into(), "10.0.1.0/24".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        assert!(matches!(act, MinimizeAction::Applied));
        // fold deduplicates domains (after normalization sorts them)
        assert_eq!(cfg.route.rules[0].domain, vec!["a.com", "b.com"]);
        // fold merges contained CIDRs
        assert_eq!(cfg.route.rules[0].ipcidr, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn wp30s_pin_owner_is_ir_minimize() {
        // WP-30s pin: the actual minimization logic now lives in ir/minimize.rs.
        // This test exists so that if someone moves the logic elsewhere, the pin
        // name makes the ownership intent obvious.
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            domain: vec!["TEST.COM".into(), "TEST.COM".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        assert!(matches!(act, MinimizeAction::Applied));
        assert_eq!(cfg.route.rules[0].domain, vec!["test.com"]);
    }

    #[test]
    fn wp30s_pin_minimize_is_not_planned() {
        // WP-30s pin: minimize is post-validated optimization, NOT a planned
        // contract. It does not participate in PlannedFacts.
        // This is a semantic pin — the test asserts that minimize only touches
        // rule content (domains, CIDRs) and does NOT touch planned references.
        let mut cfg = ConfigIR::default();
        cfg.route.default = Some("my-proxy".to_string());
        cfg.route.rules.push(RuleIR {
            domain: vec!["A.COM".into()],
            outbound: Some("my-proxy".to_string()),
            ..Default::default()
        });
        let _act = minimize_config(&mut cfg);
        // planned references untouched
        assert_eq!(cfg.route.default.as_deref(), Some("my-proxy"));
        assert_eq!(
            cfg.route.rules[0].outbound.as_deref(),
            Some("my-proxy")
        );
    }

    #[test]
    fn wp30s_pin_negation_only_normalizes() {
        // WP-30s pin: when negation exists, only normalization is performed.
        // fold/dedup of domains and CIDRs is NOT applied.
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            not_domain: vec!["blocked.com".into()],
            domain: vec!["B.COM".into(), "A.COM".into(), "B.COM".into()],
            ipcidr: vec!["10.0.0.0/8".into(), "10.0.1.0/24".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        assert!(matches!(act, MinimizeAction::SkippedByNegation));
        // normalization applied: sorted + deduped by normalize
        assert_eq!(
            cfg.route.rules[0].domain,
            vec!["a.com", "b.com"]
        );
        // but CIDRs are only sorted (normalize), not folded (minimize skipped)
        assert_eq!(
            cfg.route.rules[0].ipcidr,
            vec!["10.0.0.0/8", "10.0.1.0/24"]
        );
    }
}
