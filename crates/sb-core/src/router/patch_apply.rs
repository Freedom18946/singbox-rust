//! R34: 纯文本 CLI 补丁应用器（只读）：根据 -/+ 行对原文本做删除与追加。
//! 兼容我们导出的补丁格式：
//!   *** <file>
//!   @@
//!   -lineA
//!   +lineB
//! 规则：严格按整行匹配删除（trim_end 比较），新增行统一追加到文件尾。
//! 不写盘，只返回 String。
#[derive(Debug)]
pub enum ApplyError {
    EmptySource,
    EmptyPatch,
}

const VALUE_PLACEHOLDER: &str = "<TO-BE-REMOVED>";

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeleteRule {
    Exact(String),
    MatchAnyValue { key_prefix: String },
}

pub fn apply_cli_patch(original: &str, patch: &str) -> Result<String, ApplyError> {
    if original.is_empty() {
        return Err(ApplyError::EmptySource);
    }
    if patch.trim().is_empty() {
        return Err(ApplyError::EmptyPatch);
    }
    let mut dels: Vec<DeleteRule> = Vec::new();
    let mut adds: Vec<String> = Vec::new();
    for raw in patch.lines() {
        let line = raw.trim_end();
        if let Some(stripped) = line.strip_prefix('-') {
            dels.push(parse_delete_rule(stripped));
        } else if let Some(stripped) = line.strip_prefix('+') {
            adds.push(stripped.to_string());
        }
    }
    let mut out =
        String::with_capacity(original.len() + adds.iter().map(|s| s.len() + 1).sum::<usize>() + 8);
    'outer: for raw in original.lines() {
        let l = raw.trim_end();
        for d in &dels {
            if delete_rule_matches(d, l) {
                continue 'outer;
            }
        }
        out.push_str(raw);
        out.push('\n');
    }
    for a in adds {
        if !a.is_empty() {
            out.push_str(&a);
            out.push('\n');
        }
    }
    Ok(out)
}

fn parse_delete_rule(line: &str) -> DeleteRule {
    if let Some(key) = line.strip_suffix(&format!("={VALUE_PLACEHOLDER}")) {
        DeleteRule::MatchAnyValue {
            key_prefix: format!("{key}="),
        }
    } else {
        DeleteRule::Exact(line.to_string())
    }
}

fn delete_rule_matches(rule: &DeleteRule, line: &str) -> bool {
    match rule {
        DeleteRule::Exact(expected) => line == expected,
        DeleteRule::MatchAnyValue { key_prefix } => line.starts_with(key_prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::apply_cli_patch;

    #[test]
    fn placeholder_delete_matches_existing_rule_value() {
        let original = "exact:a.example.com=proxy\nsuffix:example.com=direct\ndefault:direct\n";
        let patch = "*** rules.txt\n@@\n-exact:a.example.com=<TO-BE-REMOVED>\n";

        let out = apply_cli_patch(original, patch).expect("patch should apply");

        assert!(!out.contains("exact:a.example.com=proxy"));
        assert!(out.contains("suffix:example.com=direct"));
        assert!(out.contains("default:direct"));
    }
}
