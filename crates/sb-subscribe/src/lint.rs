//! R108: 订阅 Lint（纯离线），输出 minijson 报告。
//! 检查项（最小闭环）：
//! - empty_decision：决策为空
//! - dup_rule：完全重复的 DSL 行
//! - reversed_portrange：a-b 中 a>b
//! - shadow_suffix_over_exact：suffix 覆盖 exact
//! - unknown_outbound：规则引用的决策在 outbounds 不存在（best-effort）
//!
//! 报告字段：{ok, format, mode, normalized, totals, issues:[{kind,line|detail}], can_autofix}
use crate::model::Profile;
use sb_core::router::minijson::{obj, Val};
use std::collections::{BTreeMap, BTreeSet};

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

fn to_dsl(p: &Profile, normalize: bool) -> String {
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

#[derive(Default)]
struct Counters {
    empty_decision: u64,
    dup_rule: u64,
    reversed_range: u64,
    shadow: u64,
    unknown_out: u64,
}

pub struct LintResult {
    pub json: String,
    pub dsl: String,
    pub can_autofix: bool,
}

pub fn lint_minijson(
    input: &str,
    format: &str,
    use_keyword: bool,
    normalize: bool,
) -> Result<LintResult, String> {
    let p = parse_profile(input, format, use_keyword)?;
    // 1) 构建 DSL
    let dsl = to_dsl(&p, normalize);
    // 2) 逐行检查
    let mut issues: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut counters = Counters::default();
    // outbounds 集合用于 unknown_outbound
    let outs: BTreeSet<String> = p.outbounds.iter().map(|o| o.name.to_lowercase()).collect();
    for raw in dsl.lines().filter(|l| !l.trim().is_empty()) {
        let line = raw.trim();
        // 空决策
        if let Some(eq) = line.find('=') {
            if eq + 1 >= line.len() {
                counters.empty_decision += 1;
                issues.push(obj([
                    ("kind", Val::Str("empty_decision")),
                    ("line", Val::Str(line)),
                ]));
            }
        } else {
            // 没有 '=' 的行也记为 empty_decision（DSL 期望有 key=value）
            counters.empty_decision += 1;
            issues.push(obj([
                ("kind", Val::Str("empty_decision")),
                ("line", Val::Str(line)),
            ]));
        }
        // 重复行
        if !seen.insert(line.to_string()) {
            counters.dup_rule += 1;
            issues.push(obj([
                ("kind", Val::Str("dup_rule")),
                ("line", Val::Str(line)),
            ]));
        }
        // 反向 portrange + unknown outbound
        if line.starts_with("portrange:") {
            if let Some((k, v)) = line.split_once('=') {
                if let Some((_, r)) = k.split_once(':') {
                    if let Some((a, b)) = r.split_once('-') {
                        if let (Ok(x), Ok(y)) = (a.parse::<u16>(), b.parse::<u16>()) {
                            if x > y {
                                counters.reversed_range += 1;
                                issues.push(obj([
                                    ("kind", Val::Str("reversed_portrange")),
                                    ("line", Val::Str(line)),
                                ]));
                            }
                        }
                    }
                }
                // unknown outbound
                let dec = v.trim().to_lowercase();
                if !dec.is_empty() && dec != "direct" && dec != "reject" && !outs.contains(&dec) {
                    counters.unknown_out += 1;
                    issues.push(obj([
                        ("kind", Val::Str("unknown_outbound")),
                        ("detail", Val::Str(&dec)),
                    ]));
                }
            }
        } else if let Some((_, v)) = line.split_once('=') {
            let dec = v.trim().to_lowercase();
            if !dec.is_empty() && dec != "direct" && dec != "reject" && !outs.contains(&dec) {
                counters.unknown_out += 1;
                issues.push(obj([
                    ("kind", Val::Str("unknown_outbound")),
                    ("detail", Val::Str(&dec)),
                ]));
            }
        }
    }
    // 3) suffix 覆盖 exact（粗粒度：同 host）
    let mut exact: BTreeMap<String, String> = BTreeMap::new();
    let mut suffix: BTreeSet<String> = BTreeSet::new();
    for line in dsl.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let _ = v; // unused
            if let Some((kind, key)) = k.split_once(':') {
                let key = key.to_lowercase();
                if kind == "exact" {
                    exact.insert(key.clone(), String::new());
                }
                if kind == "suffix" {
                    suffix.insert(key.clone());
                }
            }
        }
    }
    for host in exact.keys() {
        // host 以某个 suffix 结尾 → 认为被覆盖
        if suffix.iter().any(|sfx| host.ends_with(sfx)) {
            counters.shadow += 1;
            issues.push(obj([
                ("kind", Val::Str("shadow_suffix_over_exact")),
                ("detail", Val::Str(host)),
            ]));
        }
    }
    // 4) 汇总
    let totals_obj = obj([
        ("empty_decision", Val::NumU(counters.empty_decision)),
        ("dup_rule", Val::NumU(counters.dup_rule)),
        ("reversed_portrange", Val::NumU(counters.reversed_range)),
        ("shadow_suffix_over_exact", Val::NumU(counters.shadow)),
        ("unknown_outbound", Val::NumU(counters.unknown_out)),
    ]);
    let can_autofix = counters.dup_rule > 0 || counters.reversed_range > 0;
    let issues_arr = format!("[{}]", issues.join(","));
    let j = obj([
        ("ok", Val::Bool(true)),
        ("format", Val::Str(format)),
        (
            "mode",
            Val::Str(if use_keyword { "keyword" } else { "suffix" }),
        ),
        ("normalized", Val::Bool(normalize)),
        ("totals", Val::Raw(&totals_obj)),
        ("issues", Val::Raw(&issues_arr)),
        ("can_autofix", Val::Bool(can_autofix)),
        (
            "meta",
            Val::Raw(&obj([
                ("hashes", Val::Bool(false)),
                ("ordered", Val::Bool(false)),
                ("normalized", Val::Bool(normalize)),
            ])),
        ),
    ]);
    Ok(LintResult {
        json: j,
        dsl,
        can_autofix,
    })
}
