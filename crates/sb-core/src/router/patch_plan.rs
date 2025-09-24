//! R37: 组合补丁流水线（计划与顺序应用）
#[cfg(feature = "rules_tool")]
use super::analyze_fix;
use super::minijson;
#[cfg(feature = "rules_tool")]
use super::{analyze, patch_apply};

#[derive(Default, Debug, Clone)]
pub struct PlanSummary {
    pub kinds: Vec<String>,
    pub adds: u64,
    pub dels: u64,
    pub noop: bool,
}

impl PlanSummary {
    pub fn to_json(&self) -> String {
        use minijson::Val;
        let kinds: Vec<String> = self
            .kinds
            .iter()
            .map(|k| minijson::obj([("kind", Val::Str(k))]))
            .collect();
        minijson::obj([
            ("adds", Val::NumU(self.adds)),
            ("dels", Val::NumU(self.dels)),
            ("noop", Val::Bool(self.noop)),
            ("kinds", Val::Raw(&minijson::arr_obj(&kinds))),
        ])
    }
}

pub struct PlanResult {
    pub patch_text: String,
    pub summary: PlanSummary,
}

/// kind 支持：portrange_merge | suffix_shadow_cleanup | port_aggregate | lint_autofix
#[cfg(feature = "rules_tool")]
pub fn build_plan(text: &str, kinds: &[&str], file: Option<&str>) -> PlanResult {
    let mut patch = String::new();
    let mut summary = PlanSummary::default();
    for k in kinds {
        let rep = analyze::analyze(text);
        let next = match *k {
            "portrange_merge" => analyze_fix::build_portrange_merge_patch(&rep, text, file),
            "suffix_shadow_cleanup" => analyze_fix::build_suffix_shadow_cleanup_patch(&rep, file),
            "port_aggregate" => analyze_fix::build_port_aggregate_patch(text, file),
            "lint_autofix" => analyze_fix::build_lint_autofix_patch(text, file),
            _ => None,
        };
        if let Some(p) = next {
            summary.kinds.push(k.to_string());
            // 粗略统计 +/-
            for l in p.patch_text.lines() {
                if l.starts_with('+') {
                    summary.adds += 1;
                }
                if l.starts_with('-') {
                    summary.dels += 1;
                }
            }
            patch.push_str(&p.patch_text);
            if !patch.ends_with('\n') {
                patch.push('\n');
            }
        }
    }
    summary.noop = summary.adds == 0 && summary.dels == 0;
    PlanResult {
        patch_text: if patch.is_empty() {
            "*** rules.txt\n@@\n".into()
        } else {
            patch
        },
        summary,
    }
}

#[cfg(not(feature = "rules_tool"))]
pub fn build_plan(_text: &str, _kinds: &[&str], _file: Option<&str>) -> PlanResult {
    PlanResult {
        patch_text: "*** rules.txt\n@@\n".into(),
        summary: PlanSummary {
            kinds: vec![],
            adds: 0,
            dels: 0,
            noop: true,
        },
    }
}

/// 在内存中顺序应用各子补丁，返回最终文本（只读，不写盘）
#[cfg(feature = "rules_tool")]
pub fn apply_plan(text: &str, kinds: &[&str]) -> String {
    let mut cur = text.to_string();
    for k in kinds {
        let rep = analyze::analyze(&cur);
        let patch = match *k {
            "portrange_merge" => {
                analyze_fix::build_portrange_merge_patch(&rep, &cur, Some("rules.conf"))
            }
            "suffix_shadow_cleanup" => {
                analyze_fix::build_suffix_shadow_cleanup_patch(&rep, Some("rules.conf"))
            }
            "port_aggregate" => analyze_fix::build_port_aggregate_patch(&cur, Some("rules.conf")),
            "lint_autofix" => analyze_fix::build_lint_autofix_patch(&cur, Some("rules.conf")),
            _ => None,
        };
        if let Some(p) = patch {
            if let Ok(next) = patch_apply::apply_cli_patch(&cur, &p.patch_text) {
                cur = next;
            }
        }
    }
    cur
}

#[cfg(not(feature = "rules_tool"))]
pub fn apply_plan(text: &str, _kinds: &[&str]) -> String {
    text.to_string()
}
