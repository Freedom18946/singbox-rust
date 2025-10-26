//! R74: 订阅转换 JSON 视图（无需 serde，复用 sb-core/minijson）
//! R97: 视图功能 behind features（由 lib.rs 控制导出）
use crate::model::Profile;
use sb_core::router::minijson::{arr_str, obj, Val};

#[cfg(feature = "subs_hash")]
fn b3_hex(s: &str) -> String {
    let h = blake3::hash(s.as_bytes());
    h.to_hex().to_string()
}

#[cfg(not(feature = "subs_hash"))]
fn b3_hex(_s: &str) -> String {
    "disabled".to_string()
}

/// Build JSON object from key-value pairs: {"key1":val1,"key2":val2}
fn build_count_json(pairs: &[(impl AsRef<str>, u64)]) -> String {
    if pairs.is_empty() {
        return "{}".to_string();
    }

    let capacity = pairs.len() * 20; // Estimate: "key":123,
    let mut result = String::with_capacity(capacity);
    result.push('{');

    for (i, (key, count)) in pairs.iter().enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push('"');
        result.push_str(key.as_ref());
        result.push_str("\":");
        result.push_str(&count.to_string());
    }

    result.push('}');
    result
}

pub fn view_minijson(p: &Profile) -> String {
    // 构造可复现的 rules/outbounds 文本再做 hash
    let estimated_rules_capacity = p.rules.len() * 50;
    let mut rules_join = String::with_capacity(estimated_rules_capacity);
    for (i, r) in p.rules.iter().enumerate() {
        if i > 0 {
            rules_join.push('\n');
        }
        rules_join.push_str(&r.line);
    }

    let estimated_outs_capacity = p.outbounds.len() * 30;
    let mut outs_join = String::with_capacity(estimated_outs_capacity);
    for (i, o) in p.outbounds.iter().enumerate() {
        if i > 0 {
            outs_join.push('\n');
        }
        outs_join.push_str(&o.name);
        outs_join.push(':');
        outs_join.push_str(&o.kind);
    }

    let rules_hash = b3_hex(&rules_join);
    let outs_hash = b3_hex(&outs_join);

    // R82: sample_rules (≤10 items)
    let sample_limit = 10.min(p.rules.len());
    let sample_rules_vec: Vec<&str> = p
        .rules
        .iter()
        .take(sample_limit)
        .map(|r| r.line.as_str())
        .collect();
    let sample_rules_json = arr_str(&sample_rules_vec);

    // R82/R87: kinds_count histogram (统一使用 BTreeMap 保证顺序)
    let mut kind_map: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for ob in &p.outbounds {
        *kind_map.entry(&ob.kind).or_insert(0) += 1;
    }

    let kinds_pairs: Vec<(&str, u64)> = kind_map.iter().map(|(k, v)| (*k, *v)).collect();
    let kinds_count_json = build_count_json(&kinds_pairs);

    obj([
        ("rules", Val::NumU(p.rules_len() as u64)),
        ("outbounds", Val::NumU(p.outbounds.len() as u64)),
        (
            "outbound_kinds",
            Val::Raw(&arr_str(
                &p.outbounds_kinds()
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>(),
            )),
        ),
        ("rules_hash", Val::Str(&rules_hash)),
        ("outbounds_hash", Val::Str(&outs_hash)),
        ("sample_rules", Val::Raw(&sample_rules_json)),
        ("kinds_count", Val::Raw(&kinds_count_json)),
        ("outbound_kinds_count", Val::Raw(&kinds_count_json)),
    ])
}
