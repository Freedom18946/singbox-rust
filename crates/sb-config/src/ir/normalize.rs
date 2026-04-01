//! IR-level normalization — canonical rule token rewriting.
//!
//! ## Owner history
//!
//! WP-30r migrated the implementation from the top-level `normalize.rs` into
//! this IR sub-module.  The top-level `normalize.rs` is now a thin compat
//! shell that delegates here.
//!
//! ## Scope
//!
//! This module **only** performs rule token canonicalization:
//! - Domain: lowercase, trim dots, wildcard normalization
//! - Ports: expand ranges, merge, stable ordering
//! - CIDR: sort (strict validation deferred to validator)
//! - Network / protocol: lowercase, sort, dedup
//!
//! It does **not** touch planned-layer references (route.default,
//! rule.outbound, selector members, DNS refs, service refs).

use super::{ConfigIR, RuleIR};
use std::net::Ipv4Addr;

/// Normalize domain: lowercase, trim dots, handle wildcards.
fn norm_domain(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    let t = t.trim_matches('.');
    if t.starts_with("*.") || t == "*" {
        t.into()
    } else {
        t.to_string()
    }
}

/// Normalize port list: expand ranges (e.g., `"80-82"` → `[80,81,82]`),
/// then merge back to stable string representation.
fn norm_port_vec(v: &mut Vec<String>) {
    if v.is_empty() {
        return;
    }
    let mut acc = Vec::<u16>::new();
    for item in v.iter() {
        if let Some((a, b)) = item.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                for p in lo..=hi {
                    acc.push(p);
                }
                continue;
            }
        }
        if let Ok(p) = item.parse::<u16>() {
            acc.push(p);
        }
    }
    acc.sort_unstable();
    acc.dedup();
    let mut out = Vec::<String>::new();
    let mut i = 0usize;
    while i < acc.len() {
        let start = acc[i];
        let mut end = start;
        let mut j = i + 1;
        while j < acc.len() && acc[j] == end + 1 {
            end = acc[j];
            j += 1;
        }
        if start == end {
            out.push(start.to_string());
        } else {
            out.push(format!("{}-{}", start, end));
        }
        i = j;
    }
    *v = out;
}

#[allow(dead_code)]
fn looks_like_cidr(s: &str) -> bool {
    let parts: Vec<_> = s.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    if parts[1].parse::<u8>().ok().filter(|m| *m <= 32).is_none() {
        return false;
    }
    parts[0].parse::<Ipv4Addr>().is_ok()
}

pub(crate) fn normalize_rule(r: &mut RuleIR) {
    for d in &mut r.domain {
        *d = norm_domain(d);
    }
    for d in &mut r.not_domain {
        *d = norm_domain(d);
    }
    r.domain.sort();
    r.domain.dedup();
    r.not_domain.sort();
    r.not_domain.dedup();
    norm_port_vec(&mut r.port);
    norm_port_vec(&mut r.not_port);
    r.ipcidr.sort();
    r.not_ipcidr.sort();
    for x in [&mut r.network, &mut r.protocol] {
        for v in x.iter_mut() {
            *v = v.trim().to_ascii_lowercase();
        }
        x.sort();
        x.dedup();
    }
}

pub(crate) fn normalize_config(cfg: &mut ConfigIR) {
    for r in &mut cfg.route.rules {
        normalize_rule(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{DnsIR, DnsServerIR, RuleIR};

    #[test]
    fn domain_norm_and_ports() {
        let mut r = RuleIR {
            domain: vec![
                "EXAMPLE.COM".into(),
                "a.Example.com".into(),
                "*.Foo.Bar".into(),
            ],
            not_domain: vec![".b.test.".into()],
            port: vec!["80-82".into(), "81".into(), "443".into()],
            ..Default::default()
        };
        normalize_rule(&mut r);
        assert_eq!(r.domain, vec!["*.foo.bar", "a.example.com", "example.com"]);
        assert_eq!(r.not_domain, vec!["b.test"]);
        assert_eq!(r.port, vec!["80-82", "443"]);
    }

    #[test]
    fn wp30r_pin_normalize_only_rewrites_rule_tokens() {
        // WP-30r pin: normalize only canonicalizes rule tokens; it does not
        // bind or rewrite planned-layer references (route.default, rule.outbound,
        // selector members, DNS refs).
        let mut cfg = ConfigIR::default();
        cfg.route.default = Some("Selector-A".to_string());
        cfg.dns = Some(DnsIR {
            servers: vec![DnsServerIR {
                tag: "dns-a".to_string(),
                address: "udp://1.1.1.1".to_string(),
                detour: Some("Selector-A".to_string()),
                ..Default::default()
            }],
            default: Some("dns-a".to_string()),
            final_server: Some("dns-a".to_string()),
            ..Default::default()
        });
        cfg.route.rules.push(RuleIR {
            domain: vec!["EXAMPLE.COM".into()],
            port: vec!["443".into(), "80-81".into(), "81".into()],
            network: vec![" TCP ".into()],
            protocol: vec![" HTTP ".into()],
            outbound: Some("Selector-A".to_string()),
            ..Default::default()
        });

        normalize_config(&mut cfg);

        let rule = &cfg.route.rules[0];
        assert_eq!(rule.domain, vec!["example.com"]);
        assert_eq!(rule.port, vec!["80-81", "443"]);
        assert_eq!(rule.network, vec!["tcp"]);
        assert_eq!(rule.protocol, vec!["http"]);
        // planned references untouched
        assert_eq!(rule.outbound.as_deref(), Some("Selector-A"));
        assert_eq!(cfg.route.default.as_deref(), Some("Selector-A"));
        let dns = cfg.dns.as_ref().expect("dns should remain present");
        assert_eq!(dns.default.as_deref(), Some("dns-a"));
        assert_eq!(dns.final_server.as_deref(), Some("dns-a"));
        assert_eq!(dns.servers[0].detour.as_deref(), Some("Selector-A"));
    }

    #[test]
    fn wp30r_pin_owner_is_ir_normalize() {
        // WP-30r pin: the actual normalization logic now lives in ir/normalize.rs.
        // This test exists so that if someone moves the logic elsewhere, the pin
        // name makes the ownership intent obvious.
        let mut r = RuleIR {
            domain: vec!["TEST.COM".into()],
            ..Default::default()
        };
        normalize_rule(&mut r);
        assert_eq!(r.domain, vec!["test.com"]);
    }
}
