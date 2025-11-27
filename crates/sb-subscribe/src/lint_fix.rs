//! R109: Convert lint results to CLI-style patch. Currently supports safe fixes:
//! [Chinese] R109: 将 lint 结果转为 CLI 风格补丁；目前安全修复：
//!
//! - Delete dup_rule / 删除 dup_rule
//! - Adjust reversed_portrange (a-b -> b-a) / 调整 reversed_portrange（a-b → b-a）
//!
//! Others are reported only, no auto-fix (to avoid breaking user space).
//! [Chinese] 其余仅报告不自动改动（避免破坏用户空间）。
pub fn make_autofix_patch(dsl: &str) -> String {
    use std::collections::BTreeSet;
    let mut out = String::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for line in dsl.lines().filter(|l| !l.trim().is_empty()) {
        if !seen.insert(line) {
            out.push('-');
            out.push_str(line);
            out.push('\n'); // Delete duplicate
        }
        if line.starts_with("portrange:") {
            if let Some((k, dec)) = line.split_once('=') {
                if let Some((_, r)) = k.split_once(':') {
                    if let Some((a, b)) = r.split_once('-') {
                        if let (Ok(x), Ok(y)) = (a.parse::<u16>(), b.parse::<u16>()) {
                            if x > y {
                                // Delete original + Add fixed
                                // [Chinese] 删除原行 + 添加修正行
                                out.push('-');
                                out.push_str(line);
                                out.push('\n');
                                out.push_str("+portrange:");
                                out.push_str(&format!("{}-{}", y, x));
                                out.push('=');
                                out.push_str(dec.trim());
                                out.push('\n');
                            }
                        }
                    }
                }
            }
        }
    }
    out
}
