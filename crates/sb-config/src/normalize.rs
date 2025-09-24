//! Canonical normalization helpers for IR.
//! - 域名小写与去点
//! - 通配符规范化（前导 *.* → *.）
//! - 端口集规范化（展开/合并，内部仍存字符串但序列稳定）
//! - CIDR 合法性快速检查（留给校验器严格处理）
use crate::ir::{ConfigIR, RuleIR};
use std::net::Ipv4Addr;

fn norm_domain(s: &str) -> String {
    let t = s.trim().to_ascii_lowercase();
    let t = t.trim_matches('.');
    if t.starts_with("*.") || t == "*" {
        t.into()
    } else {
        t.to_string()
    }
}

fn norm_port_vec(v: &mut Vec<String>) {
    if v.is_empty() {
        return;
    }
    // 将 "80-82" 展开为 [80,81,82] 再合并为区间；最终仍存为字符串，但顺序稳定
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
    // 再压回区间字符串
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
    // 极简检查，仅用于规范化排序；严格性由 v2 校验器负责
    let parts: Vec<_> = s.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    if parts[1].parse::<u8>().ok().filter(|m| *m <= 32).is_none() {
        return false;
    }
    parts[0].parse::<Ipv4Addr>().is_ok()
}

pub fn normalize_rule(r: &mut RuleIR) {
    for d in &mut r.domain {
        *d = norm_domain(d);
    }
    for d in &mut r.not_domain {
        *d = norm_domain(d);
    }
    // 去重 + 排序
    r.domain.sort();
    r.domain.dedup();
    r.not_domain.sort();
    r.not_domain.dedup();
    // 端口规范化
    norm_port_vec(&mut r.port);
    norm_port_vec(&mut r.not_port);
    // CIDR 粗校排序
    r.ipcidr.sort();
    r.not_ipcidr.sort();
    // 其他维度小写化
    for x in [&mut r.network, &mut r.protocol] {
        for v in x.iter_mut() {
            *v = v.trim().to_ascii_lowercase();
        }
        x.sort();
        x.dedup();
    }
}

pub fn normalize_config(cfg: &mut ConfigIR) {
    for r in &mut cfg.route.rules {
        normalize_rule(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConfigIR, RuleIR};
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
}
