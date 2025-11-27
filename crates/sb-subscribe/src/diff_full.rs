//! R104: Subscription diffing (purely offline).
//! [Chinese] R104: 订阅差异对比（纯离线）。
//!
//! - Input: lhs/rhs text + format=clash|singbox + keyword/suffix mode + normalize flag.
//! [Chinese] - 输入：lhs/rhs 文本 + format=clash|singbox + keyword/suffix 模式 + 是否 normalize。
//! - Output: minijson: { ok, format, mode, normalized, kinds_count_diff, outbound_kinds_diff, dsl_patch }.
//! [Chinese] - 输出：minijson：{ ok, format, mode, normalized, kinds_count_diff, outbound_kinds_diff, dsl_patch }。
use crate::model::Profile;
use sb_core::router::minijson::{obj, Val};
use serde::{Deserialize, Serialize};
use std::fmt;

fn parse_profile(text: &str, format: &str, use_keyword: bool) -> Result<Profile, String> {
    match format {
        "clash" => {
            #[cfg(feature = "subs_clash")]
            {
                crate::parse_clash::parse_with_mode(text, use_keyword)
                    .map_err(|e| format!("{:?}", e))
            }
            #[cfg(not(feature = "subs_clash"))]
            {
                Err("format clash disabled".into())
            }
        }
        "singbox" | "sing-box" => {
            #[cfg(feature = "subs_singbox")]
            {
                crate::parse_singbox::parse_with_mode(text, use_keyword)
                    .map_err(|e| format!("{:?}", e))
            }
            #[cfg(not(feature = "subs_singbox"))]
            {
                Err("format singbox disabled".into())
            }
        }
        _ => Err("unknown format".into()),
    }
}

fn profile_to_dsl(p: &Profile, normalize: bool) -> String {
    let mut s = String::with_capacity(p.rules.len() * 32);
    for r in &p.rules {
        s.push_str(&r.line);
        s.push('\n');
    }
    if normalize {
        return sb_core::router::rules_normalize(&s);
    }
    s
}

fn kinds_histogram(p: &Profile) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::<String, u64>::new();
    for r in &p.rules {
        let kind = r.line.split(':').next().unwrap_or("other").to_lowercase();
        *m.entry(kind).or_insert(0) += 1;
    }
    m
}

fn outbound_kinds_histogram(p: &Profile) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::<String, u64>::new();
    for o in &p.outbounds {
        *m.entry(o.kind.to_lowercase()).or_insert(0) += 1;
    }
    m
}

/// Naive line-level patch (CLI style): based on lhs, outputs the -/+ set to transform lhs to rhs (deletions before additions).
/// [Chinese] 朴素行级补丁（保持 CLI 风格）：以 lhs 为基准，输出把 lhs 变为 rhs 的 -/+ 集合（删除先于添加）。
fn line_patch(lhs: &str, rhs: &str) -> String {
    use std::collections::BTreeSet;
    let lset: BTreeSet<&str> = lhs.lines().filter(|s| !s.is_empty()).collect();
    let rset: BTreeSet<&str> = rhs.lines().filter(|s| !s.is_empty()).collect();
    let mut dels = Vec::new();
    let mut adds = Vec::new();
    for l in lset.difference(&rset) {
        dels.push(format!("-{}", l));
    }
    for a in rset.difference(&lset) {
        adds.push(format!("+{}", a));
    }
    let mut out = String::new();
    for d in dels {
        out.push_str(&d);
        out.push('\n');
    }
    for a in adds {
        out.push_str(&a);
        out.push('\n');
    }
    if !out.is_empty() {
        out.insert(0, '\n');
    }
    out
}

fn map_hist_to_minijson_obj(m: &std::collections::BTreeMap<String, u64>) -> String {
    // {"kind1":N1,"kind2":N2,...}
    let mut kv = Vec::with_capacity(m.len());
    for (k, v) in m {
        kv.push(format!("\"{}\":{}", k, v));
    }
    format!("{{{}}}", kv.join(","))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DiffOutput {
    pub json: String,
}

impl DiffOutput {
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"_error\":\"serialize_failed\"}".into())
    }
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{\n  \"_error\": \"serialize_failed\" \n}".into())
    }
}

impl fmt::Display for DiffOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_json_string())
    }
}

pub fn diff_full_minijson(
    lhs: &str,
    rhs: &str,
    format: &str,
    use_keyword: bool,
    normalize: bool,
) -> Result<DiffOutput, String> {
    let lp = parse_profile(lhs, format, use_keyword)?;
    let rp = parse_profile(rhs, format, use_keyword)?;
    let l_dsl = profile_to_dsl(&lp, normalize);
    let r_dsl = profile_to_dsl(&rp, normalize);
    let patch = line_patch(&l_dsl, &r_dsl);
    let lk = kinds_histogram(&lp);
    let rk = kinds_histogram(&rp);
    let lo = outbound_kinds_histogram(&lp);
    let ro = outbound_kinds_histogram(&rp);
    // Embed histogram objects using minijson::Raw
    // [Chinese] 以 minijson::Raw 内嵌直方图对象
    let j = obj([
        ("ok", Val::Bool(true)),
        ("format", Val::Str(format)),
        (
            "mode",
            Val::Str(if use_keyword { "keyword" } else { "suffix" }),
        ),
        ("normalized", Val::Bool(normalize)),
        ("kinds_count_lhs", Val::Raw(&map_hist_to_minijson_obj(&lk))),
        ("kinds_count_rhs", Val::Raw(&map_hist_to_minijson_obj(&rk))),
        (
            "outbound_kinds_lhs",
            Val::Raw(&map_hist_to_minijson_obj(&lo)),
        ),
        (
            "outbound_kinds_rhs",
            Val::Raw(&map_hist_to_minijson_obj(&ro)),
        ),
        ("dsl_patch", Val::Str(&patch)),
        (
            "meta",
            Val::Raw(&obj([
                ("hashes", Val::Bool(false)),
                ("ordered", Val::Bool(false)),
                ("normalized", Val::Bool(normalize)),
            ])),
        ),
    ]);
    Ok(DiffOutput { json: j })
}
