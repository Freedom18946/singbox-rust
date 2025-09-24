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

pub fn apply_cli_patch(original: &str, patch: &str) -> Result<String, ApplyError> {
    if original.is_empty() {
        return Err(ApplyError::EmptySource);
    }
    if patch.trim().is_empty() {
        return Err(ApplyError::EmptyPatch);
    }
    let mut dels: Vec<String> = Vec::new();
    let mut adds: Vec<String> = Vec::new();
    for raw in patch.lines() {
        let line = raw.trim_end();
        if line.starts_with('-') {
            dels.push(line[1..].to_string());
        } else if line.starts_with('+') {
            adds.push(line[1..].to_string());
        }
    }
    let mut out =
        String::with_capacity(original.len() + adds.iter().map(|s| s.len() + 1).sum::<usize>() + 8);
    'outer: for raw in original.lines() {
        let l = raw.trim_end();
        for d in &dels {
            if l == d {
                continue 'outer;
            } // 删除
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
