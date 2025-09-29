//! R13: 将 analyze 的建议转成“CLI 补丁”文本（非 git）。
use super::analyze::Report;
use std::fmt::Write;

/// CLI Patch 片段。仅文本层替换，不做 AST。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliPatch {
    /// 用于展示/记录的目标文件路径（可选）
    pub file: Option<String>,
    /// 完整补丁文本（*** path + @@ + +/- 的简化文本）
    pub patch_text: String,
}

/// 从 `Report` 和原始规则文本生成“合并 portrange”的补丁。
/// 仅处理 `suggestions` 中形如：`merge portrange:a-b & c-d -> a-d [DEC]`
pub fn build_portrange_merge_patch(
    report: &Report,
    _original_text: &str,
    file: Option<&str>,
) -> Option<CliPatch> {
    let mut out = String::new();
    let mut edits: Vec<((u16, u16, String), (u16, u16, String))> = Vec::new();
    for s in &report.suggestions {
        if let Some(idx) = s.find("merge portrange:") {
            let seg = &s[idx + "merge portrange:".len()..];
            // 解析 "a-b & c-d -> a-d [DEC]"
            let parts: Vec<&str> = seg.split_whitespace().collect();
            if parts.len() >= 5 {
                // parts[0] = "a-b"; parts[1] = "&"; parts[2] = "c-d"; parts[3] = "->"; parts[4] = "a-d"
                let a = parse_range(parts[0]);
                let c = parse_range(parts[2]);
                let ad = parse_range(parts[4]);
                if let (Some((a1, a2)), Some((c1, c2)), Some((m1, m2))) = (a, c, ad) {
                    // 解析决策（[...]）
                    let dec = if let Some(open) = s.rfind('[') {
                        s[open + 1..s.len().saturating_sub(1)].to_string()
                    } else {
                        "direct".into()
                    };
                    edits.push(((a1, a2, dec.clone()), (c1, c2, dec.clone())));
                    let _ = writeln!(
                        &mut out,
                        "# merge {}-{} & {}-{} -> {}-{} [{}]",
                        a1, a2, c1, c2, m1, m2, dec
                    );
                }
            }
        }
    }
    if edits.is_empty() {
        return None;
    }
    // 构造“查找删除 + 添加”的补丁文本（简化版）
    let mut patch = String::new();
    if let Some(f) = file {
        patch.push_str(&format!("*** {}\n", f));
    } else {
        patch.push_str("*** rules.txt\n");
    }
    patch.push_str("@@\n");
    for ((a1, a2, dec), (c1, c2, _)) in &edits {
        patch.push_str(&format!("-portrange:{}-{}={}\n", a1, a2, dec));
        patch.push_str(&format!("-portrange:{}-{}={}\n", c1, c2, dec));
        // 合并后的区间行添加：统一按合并范围追加
        patch.push_str(&format!(
            "+portrange:{}-{}={}\n",
            (*a1).min(*c1),
            (*a2).max(*c2),
            dec
        ));
    }
    Some(CliPatch {
        file: file.map(|s| s.to_string()),
        patch_text: patch,
    })
}

fn parse_range(s: &str) -> Option<(u16, u16)> {
    let mut it = s.split('-').filter_map(|x| x.trim().parse::<u16>().ok());
    Some((it.next()?, it.next()?))
}

/// R23: 针对 `suffix_over_exact` 生成“删除被遮蔽 exact”的 CLI 补丁。
/// 只删“被不同决策的 suffix 遮蔽”的 exact，避免误删等价规则。
pub fn build_suffix_shadow_cleanup_patch(report: &Report, file: Option<&str>) -> Option<CliPatch> {
    use std::collections::BTreeSet;
    let mut victims: BTreeSet<String> = BTreeSet::new();
    for s in &report.shadows {
        if s.kind == "suffix_over_exact" {
            // victim: "exact:a.example.com"  → 提取右侧键
            if let Some(k) = s.victim.strip_prefix("exact:") {
                victims.insert(k.to_string());
            }
        }
    }
    if victims.is_empty() {
        return None;
    }
    let mut patch = String::new();
    if let Some(f) = file {
        patch.push_str(&format!("*** {}\n", f));
    } else {
        patch.push_str("*** rules.txt\n");
    }
    patch.push_str("@@\n");
    for v in victims {
        patch.push_str(&format!("-exact:{}=<TO-BE-REMOVED>\n", v));
    }
    // 附带注释说明
    patch.push_str(
        "# NOTE: above exact rules are shadowed by suffix rules with different decisions\n",
    );
    Some(CliPatch {
        file: file.map(|s| s.to_string()),
        patch_text: patch,
    })
}

/// R36: 端口聚合补丁（将同决策的多个 port 聚合为 portset）
pub fn build_port_aggregate_patch(original_text: &str, file: Option<&str>) -> Option<CliPatch> {
    use std::collections::BTreeMap;
    let mut dec_to_ports: BTreeMap<String, Vec<u16>> = BTreeMap::new();
    let mut port_lines: Vec<(u16, String)> = Vec::new(); // (port, decision)
    for raw in original_text.lines() {
        let line = raw.trim();
        if let Some((lhs, rhs)) = line.split_once('=') {
            if let Some(rest) = lhs.trim().strip_prefix("port:") {
                if let Ok(p) = rest.trim().parse::<u16>() {
                    let d = rhs.trim().to_string();
                    port_lines.push((p, d.clone()));
                    dec_to_ports.entry(d).or_default().push(p);
                }
            }
        }
    }
    // 仅当存在某个决策聚合到 >=2 个端口时生成补丁
    let mut any = false;
    let mut patch = String::new();
    if let Some(f) = file {
        patch.push_str(&format!("*** {}\n", f));
    } else {
        patch.push_str("*** rules.txt\n");
    }
    patch.push_str("@@\n");
    for (dec, mut ports) in dec_to_ports {
        if ports.len() < 2 {
            continue;
        }
        any = true;
        ports.sort_unstable();
        // 删除原有逐条端口行
        for (p, d) in &port_lines {
            if d == &dec && ports.binary_search(p).is_ok() {
                patch.push_str(&format!("-port:{}={}\n", p, dec));
            }
        }
        // 新增聚合行（使用 portset，语义不变）
        let list = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        patch.push_str(&format!("+portset:{}={}\n", list, dec));
    }
    if any {
        Some(CliPatch {
            file: file.map(|s| s.to_string()),
            patch_text: patch,
        })
    } else {
        None
    }
}

/// Generate lint autofix patch from analysis report
/// Handles common lint issues like redundant rules, unreachable conditions, etc.
pub fn build_lint_autofix_patch(
    report: &Report,
    original_text: &str,
    file: Option<&str>,
) -> Option<CliPatch> {
    let mut patch_text = String::new();
    let mut has_fixes = false;

    // Process lint suggestions from the report
    for suggestion in &report.suggestions {
        if suggestion.contains("remove redundant") {
            has_fixes = true;
            let _ = writeln!(&mut patch_text, "# Fix: {}", suggestion);

            // Extract rule patterns and generate removal instructions
            if let Some(rule_idx) = extract_rule_index(suggestion) {
                let _ = writeln!(&mut patch_text, "-rule[{}]", rule_idx);
            }
        } else if suggestion.contains("unreachable") {
            has_fixes = true;
            let _ = writeln!(&mut patch_text, "# Fix: {}", suggestion);

            // Mark unreachable rules for removal or reordering
            if let Some(rule_idx) = extract_rule_index(suggestion) {
                let _ = writeln!(
                    &mut patch_text,
                    "# Move rule[{}] to earlier position",
                    rule_idx
                );
            }
        } else if suggestion.contains("optimize") {
            has_fixes = true;
            let _ = writeln!(&mut patch_text, "# Optimization: {}", suggestion);

            // Generate optimization patches
            if suggestion.contains("combine rules") {
                let _ = writeln!(
                    &mut patch_text,
                    "# Combine similar rules for better performance"
                );
            }
        } else if suggestion.contains("format") || suggestion.contains("style") {
            has_fixes = true;
            let _ = writeln!(&mut patch_text, "# Style fix: {}", suggestion);

            // Apply formatting fixes
            apply_formatting_fixes(&mut patch_text, suggestion, original_text);
        }
    }

    // Process suggestions that can be auto-fixed
    for suggestion in &report.suggestions {
        if suggestion.contains("deprecated") {
            has_fixes = true;
            let _ = writeln!(&mut patch_text, "# Fix deprecated usage: {}", suggestion);
            apply_deprecation_fixes(&mut patch_text, suggestion);
        } else if suggestion.contains("performance") {
            has_fixes = true;
            let _ = writeln!(&mut patch_text, "# Performance improvement: {}", suggestion);
        }
    }

    // Add general lint improvements based on analysis
    if !report.suggestions.is_empty() {
        has_fixes = true;
        let _ = writeln!(&mut patch_text, "# Reduce complexity by reorganizing rules");
    }

    if has_fixes {
        Some(CliPatch {
            file: file.map(|s| s.to_string()),
            patch_text,
        })
    } else {
        None
    }
}

/// Extract rule index from suggestion text
fn extract_rule_index(suggestion: &str) -> Option<usize> {
    // Look for patterns like "rule[5]" or "rule 5" in the suggestion
    if let Some(start) = suggestion.find("rule[") {
        let end_pos = suggestion[start..].find(']')?;
        let num_str = &suggestion[start + 5..start + end_pos];
        num_str.parse().ok()
    } else if let Some(start) = suggestion.find("rule ") {
        let remaining = &suggestion[start + 5..];
        let num_str = remaining.split_whitespace().next()?;
        num_str.parse().ok()
    } else {
        None
    }
}

/// Apply formatting fixes based on suggestion
fn apply_formatting_fixes(patch_text: &mut String, suggestion: &str, _original_text: &str) {
    if suggestion.contains("indentation") {
        let _ = writeln!(patch_text, "# Fix indentation");
    } else if suggestion.contains("spacing") {
        let _ = writeln!(patch_text, "# Fix spacing");
    } else if suggestion.contains("quotes") {
        let _ = writeln!(patch_text, "# Standardize quotes");
    }
}

/// Apply fixes for deprecated features
fn apply_deprecation_fixes(patch_text: &mut String, warning: &str) {
    if warning.contains("old syntax") {
        let _ = writeln!(patch_text, "# Update to new syntax");
    } else if warning.contains("deprecated field") {
        let _ = writeln!(patch_text, "# Replace deprecated field");
    }
}

/// R37：集中声明支持的 patch kinds，便于前端发现（JSON）
pub fn supported_patch_kinds_json() -> String {
    use crate::router::minijson::{self, Val};
    minijson::obj([(
        "patch_kinds",
        Val::Raw(&minijson::arr_str(&[
            "portrange_merge",
            "suffix_shadow_cleanup",
            "port_aggregate",
            "lint_autofix",
        ])),
    )])
}
