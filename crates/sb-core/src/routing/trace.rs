//! Routing explain trace container (opt-in).
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub kind: String,  // e.g. "cidr" | "geoip" | "geosite" | "domain" | ...
    pub value: String, // e.g. "1.2.3.0/24" | "US"
    pub matched: bool, // true if matched
}

#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    pub steps: Vec<Step>,
    pub canonical_rule: String,
    pub matched_rule: String, // sha256-8（与 ExplainResult 一致）
}

pub fn sha8(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    hex::encode(&out[..4])
}

/// 构造 canonical_rule 字符串：实际项目应针对 Rule AST；此处保持兼容接口
pub fn canonicalize_rule_text(parts: &[(&str, &str)]) -> String {
    // kind=value; 按 kind 排序，保证稳定哈希
    let mut v: Vec<(String, String)> = parts
        .iter()
        .map(|(k, val)| (k.to_string(), val.to_string()))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let s = v
        .into_iter()
        .map(|(k, val)| format!("{}={}", k, val))
        .collect::<Vec<_>>()
        .join(";");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_hash_is_stable() {
        let a = canonicalize_rule_text(&[("geoip", "US"), ("cidr", "1.2.3.0/24")]);
        let b = canonicalize_rule_text(&[("cidr", "1.2.3.0/24"), ("geoip", "US")]);
        assert_eq!(a, b);
        assert_eq!(sha8(&a).len(), 8);
    }
}
