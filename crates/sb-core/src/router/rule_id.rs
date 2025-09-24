#![cfg(feature = "explain")]
use serde::Serialize;

#[derive(Serialize)]
pub struct CanonRule<'a> {
    pub kind: &'a str,
    pub when: &'a serde_json::Value,
    pub to: &'a str,
}

/// 规则稳定 ID：对规范化 JSON 取 sha256，输出前 8 hex（sha8）
pub fn rule_sha8(kind: &str, when: &serde_json::Value, to: &str) -> String {
    use sha2::{Digest, Sha256};
    let canon = CanonRule { kind, when, to };
    let payload = serde_json::to_vec(&canon).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(payload);
    let d = h.finalize();
    hex::encode(&d[..4])
}
