//! R74: 订阅转换 JSON 视图（无需 serde，复用 sb-core/minijson）
//! R97: 视图功能 behind features（由 lib.rs 控制导出）
use crate::model::Profile;
use sb_core::router::minijson::{arr_str, obj, Val};

#[cfg(feature = "subs_hash")]
fn b3_hex(s: &str) -> String {
    let h = blake3::hash(s.as_bytes());
    format!("{}", h.to_hex())
}
#[cfg(not(feature = "subs_hash"))]
fn b3_hex(_s: &str) -> String {
    "disabled".to_string()
}

pub fn view_minijson(p: &Profile) -> String {
    // 构造可复现的 rules/outbounds 文本再做 hash
    let rules_join = p
        .rules
        .iter()
        .map(|r| r.line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let outs_join = p
        .outbounds
        .iter()
        .map(|o| format!("{}:{}", o.name, o.kind))
        .collect::<Vec<_>>()
        .join("\n");
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

    // R82: kinds_count histogram
    let mut kinds_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for ob in &p.outbounds {
        *kinds_map.entry(ob.kind.clone()).or_insert(0) += 1;
    }
    let mut kinds_pairs = Vec::new();
    for (kind, count) in kinds_map {
        kinds_pairs.push(format!(r#""{}":{}"#, kind, count));
    }
    let kinds_count_json = format!("{{{}}}", kinds_pairs.join(","));

    // R87: 出站类型直方图：以 kind 聚合（动态对象，直接拼 JSON）
    let mut kind_map: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for o in &p.outbounds {
        *kind_map.entry(o.kind.clone()).or_insert(0) += 1;
    }
    let mut kv_pairs = Vec::with_capacity(kind_map.len());
    for (k, v) in kind_map {
        kv_pairs.push(format!("\"{}\":{}", k, v));
    }
    let outbound_kinds_count = format!("{{{}}}", kv_pairs.join(","));

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
        ("outbound_kinds_count", Val::Raw(&outbound_kinds_count)),
    ])
}
