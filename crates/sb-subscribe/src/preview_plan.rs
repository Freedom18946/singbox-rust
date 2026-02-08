//! R117: Subscription -> DSL -> Lint -> Plan aggregation (purely offline). Outputs minijson:
//! [Chinese] R117: 订阅→DSL→Lint→Plan 聚合（纯离线）。输出 minijson：
//!
//! { ok, meta{format,mode,normalized,ordered,kinds,apply}, dsl_in, dsl_in_hash, lint, plan_summary, patch, dsl_out? }
use crate::model::Profile;
use sb_common::minijson::{obj, Val};
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

fn blake3_hex(s: &str) -> String {
    #[cfg(feature = "subs_hash")]
    {
        blake3::hash(s.as_bytes()).to_hex().to_string()
    }
    #[cfg(not(feature = "subs_hash"))]
    {
        "disabled".into()
    }
}

/// Plan output (implements Serialize + Display; keeps existing fields and semantics).
/// [Chinese] 计划输出（补齐 Serialize + Display；不改变任何既有字段和语义）。
#[derive(Debug, Serialize, Deserialize)]
pub struct PlanOutput {
    pub json: String,
    pub dsl_in: String,
    pub dsl_out: Option<String>,
    pub patch: String,
}

impl PlanOutput {
    /// Unified JSON string output (pretty=false).
    /// [Chinese] 统一的 JSON 串输出（pretty=false）。
    pub fn to_json_string(&self) -> String {
        match serde_json::to_string(self) {
            Ok(s) => s,
            Err(_) => "{\"_error\":\"serialize_failed\"}".to_string(),
        }
    }
    /// Unified JSON string output (pretty=true).
    /// [Chinese] 统一的 JSON 串输出（pretty=true）。
    pub fn to_json_pretty(&self) -> String {
        match serde_json::to_string_pretty(self) {
            Ok(s) => s,
            Err(_) => "{\n  \"_error\": \"serialize_failed\"\n}".to_string(),
        }
    }
    /// (Optional) Try to fetch common fields, return None if missing; used for CLI `--field`.
    /// [Chinese] （可选）尝试抓取常用字段，缺失即返回 None；供 CLI `--field` 用。
    pub fn field(&self, key: &str) -> Option<String> {
        // Proxy via Value to avoid strong coupling with specific structure
        // [Chinese] 通过 Value 中转，避免对具体结构产生强耦合
        let val = serde_json::to_value(self).ok()?;
        match key {
            "dsl_in" => val
                .get("dsl_in")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            "dsl_out" => val
                .get("dsl_out")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            "ordered" => val.get("ordered").map(|v| v.to_string()),
            "normalize" => val.get("normalize").map(|v| v.to_string()),
            _ => None,
        }
    }
}

/// Provide Display for PlanOutput, supporting `.to_string()` and `println!("{}", out)`.
/// [Chinese] 为 PlanOutput 提供 Display，从而支持 `.to_string()` 与 `println!("{}", out)`。
impl fmt::Display for PlanOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Consistent with CLI default: compact JSON
        // [Chinese] 与 CLI 默认一致：紧凑 JSON
        write!(f, "{}", self.to_json_string())
    }
}

/// kinds: comma separated, default: "port_aggregate,portrange_merge,suffix_shadow_cleanup,lint_autofix".
/// [Chinese] kinds: 逗号分隔，默认："port_aggregate,portrange_merge,suffix_shadow_cleanup,lint_autofix"。
pub fn preview_plan_minijson(
    input: &str,
    format: &str,
    use_keyword: bool,
    normalize: bool,
    kinds: Option<&str>,
    apply: bool,
) -> Result<PlanOutput, String> {
    // Subscription -> Profile
    // [Chinese] 订阅 → Profile
    let p = parse_profile(input, format, use_keyword)?;
    // Profile -> DSL
    // [Chinese] Profile → DSL
    let mut dsl = String::new();
    for r in &p.rules {
        dsl.push_str(&r.line);
        dsl.push('\n');
    }
    if normalize {
        dsl = sb_core::router::rules_normalize(&dsl);
    }
    // Lint report (minijson + DSL text)
    // [Chinese] Lint 报告（minijson + DSL 文本）
    #[cfg(feature = "subs_lint")]
    let lint = crate::lint::lint_minijson(input, format, use_keyword, normalize)?.json;
    #[cfg(not(feature = "subs_lint"))]
    let lint = "{}".to_string();

    // Plan kinds whitelist and filtering
    // [Chinese] 计划 kinds 白名单与过滤
    let whitelist = [
        "portrange_merge",
        "suffix_shadow_cleanup",
        "port_aggregate",
        "lint_autofix",
    ];
    let kinds =
        kinds.unwrap_or("port_aggregate,portrange_merge,suffix_shadow_cleanup,lint_autofix");
    let kinds_vec: Vec<&str> = kinds
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let filtered_kinds: Vec<&str> = kinds_vec
        .iter()
        .filter(|k| whitelist.contains(k))
        .cloned()
        .collect();
    let unknown_kinds: Vec<&str> = kinds_vec
        .iter()
        .filter(|k| !whitelist.contains(k))
        .cloned()
        .collect();

    // Plan generation + Summary (using filtered kinds)
    // [Chinese] Plan 生成 + 摘要（使用过滤后的 kinds）
    let pr = sb_core::router::patch_plan::build_plan(&dsl, &filtered_kinds, Some("rules.conf"));
    let mut patch = pr.patch_text.clone();
    let summary_json = pr.summary.to_json();

    // Enhancement: even if plan is empty, use lint_autofix as fallback to generate "+/-"
    // [Chinese] 补强：即使空计划也用 lint_autofix 兜底产生 "+/-"
    if pr.summary.noop && filtered_kinds.contains(&"lint_autofix") {
        #[allow(unused)]
        {
            if let Some(auto) = Some(crate::lint_fix::make_autofix_patch(&dsl)) {
                if !auto.is_empty() {
                    if !patch.ends_with('\n') {
                        patch.push('\n');
                    }
                    patch.push_str(&auto);
                }
            }
        }
    }

    // dry-run apply (optional)
    // [Chinese] dry-run 应用（可选）
    let applied = if apply && !patch.trim().is_empty() {
        sb_core::router::patch_apply::apply_cli_patch(&dsl, &patch).ok()
    } else {
        None
    };
    let ordered = false; // Plan patch is set-style, unordered; suggest normalize=1. [Chinese] 计划补丁是集合风格，不保序；建议 normalize=1

    // Construct JSON (branch based on whether dsl_out is returned)
    // [Chinese] 构造 JSON（按是否返回 dsl_out 分支）
    let meta = obj([
        ("format", Val::Str(format)),
        (
            "mode",
            Val::Str(if use_keyword { "keyword" } else { "suffix" }),
        ),
        ("normalized", Val::Bool(normalize)),
        ("ordered", Val::Bool(ordered)),
        ("kinds", Val::Str(kinds)),
        ("apply", Val::Bool(apply)),
        ("hashes", Val::Bool(true)),
        (
            "unknown_kinds",
            Val::Raw(&format!(
                "[{}]",
                unknown_kinds
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        ),
    ]);
    let lint_raw = lint; // own
    let plan_summary_raw = summary_json; // own

    let json = if let Some(ref out) = applied {
        let out_hash = blake3_hex(out);
        obj([
            ("ok", Val::Bool(true)),
            ("meta", Val::Raw(&meta)),
            ("dsl_in", Val::Str(&dsl)),
            ("dsl_in_hash", Val::Str(&blake3_hex(&dsl))),
            ("lint", Val::Raw(&lint_raw)),
            ("plan_summary", Val::Raw(&plan_summary_raw)),
            ("patch", Val::Str(&patch)),
            ("dsl_out", Val::Str(out)),
            ("dsl_out_hash", Val::Str(&out_hash)),
        ])
    } else {
        obj([
            ("ok", Val::Bool(true)),
            ("meta", Val::Raw(&meta)),
            ("dsl_in", Val::Str(&dsl)),
            ("dsl_in_hash", Val::Str(&blake3_hex(&dsl))),
            ("lint", Val::Raw(&lint_raw)),
            ("plan_summary", Val::Raw(&plan_summary_raw)),
            ("patch", Val::Str(&patch)),
        ])
    };
    Ok(PlanOutput {
        json,
        dsl_in: dsl,
        dsl_out: applied,
        patch,
    })
}
