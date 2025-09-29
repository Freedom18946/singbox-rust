//! DSL 目标派生器（从"标准 DSL 文本"派生一组能覆盖规则的目标 host[:port]）
//! 仅做**启发式**派生：exact/suffix 为主；不做 DNS 或网络交互。
//! 目的：为批量预演/回归对比提供"最小但有意义"的目标集。
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Exact,
    Suffix,
    Default,
    Portset,
    Transport,
    Other,
}

#[derive(Debug, Clone)]
struct Rule {
    kind: Kind,
    key: String,
    decision: String,
}

fn parse_kind_prefix(line: &str) -> (Kind, &str) {
    // 形式：prefix:key=decision
    if let Some(rest) = line.strip_prefix("exact:") {
        return (Kind::Exact, rest);
    }
    if let Some(rest) = line.strip_prefix("suffix:") {
        return (Kind::Suffix, rest);
    }
    if let Some(rest) = line.strip_prefix("default:") {
        return (Kind::Default, rest);
    }
    if let Some(rest) = line.strip_prefix("portset:") {
        return (Kind::Portset, rest);
    }
    if let Some(rest) = line.strip_prefix("transport:") {
        return (Kind::Transport, rest);
    }
    (Kind::Other, line)
}

fn parse_rule(line: &str) -> Rule {
    let t = line.trim();
    let (kind, rest) = parse_kind_prefix(t);
    let (key, decision) = match rest.split_once('=') {
        Some((k, d)) => (k.trim().to_string(), d.trim().to_string()),
        None => (rest.trim().to_string(), String::new()),
    };
    Rule {
        kind,
        key,
        decision,
    }
}

fn sanitize_host(h: &str) -> Option<String> {
    let s = h.trim().trim_matches('.');
    if s.is_empty() {
        return None;
    }
    // 非法字符快速过滤（宽松）
    if s.chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
    {
        return None;
    }
    Some(s.to_string())
}

fn derive_from_exact(key: &str) -> Vec<String> {
    // exact: 直接使用 key 与常见 TLS 端口（无端口与 :443 ）
    let mut out = Vec::new();
    if let Some(h) = sanitize_host(key) {
        out.push(h.clone());
        out.push(format!("{h}:443"));
    }
    out
}

fn derive_from_suffix(key: &str) -> Vec<String> {
    // suffix: 生成常见二级/三级前缀组合与 :443
    // 例：example.com -> example.com / www.example.com / api.example.com / cdn.example.com / static.example.com / img.example.com
    let mut out = Vec::new();
    if let Some(base) = sanitize_host(key) {
        let candidates = [
            base.as_str(),
            &format!("www.{base}"),
            &format!("api.{base}"),
            &format!("cdn.{base}"),
            &format!("static.{base}"),
            &format!("img.{base}"),
        ];
        for c in candidates {
            out.push(c.to_string());
            out.push(format!("{c}:443"));
        }
    }
    out
}

/// 从标准 DSL 文本派生目标集合（去重），并按"更可能命中"排序（exact > suffix）。
/// `limit` 为最大产出数量（None 表示不限；仍会自然去重）。
pub fn derive_targets(dsl_text: &str, limit: Option<usize>) -> Vec<String> {
    let mut exacts: BTreeSet<String> = BTreeSet::new();
    let mut suffixes: BTreeSet<String> = BTreeSet::new();
    for raw in dsl_text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let r = parse_rule(line);
        match r.kind {
            Kind::Exact => {
                if let Some(h) = sanitize_host(&r.key) {
                    exacts.insert(h);
                }
            }
            Kind::Suffix => {
                if let Some(h) = sanitize_host(&r.key) {
                    suffixes.insert(h);
                }
            }
            _ => {}
        }
    }
    // 按优先级产出
    let mut out = Vec::<String>::new();
    let mut seen = BTreeSet::<String>::new();
    for k in exacts {
        for t in derive_from_exact(&k) {
            if seen.insert(t.clone()) {
                out.push(t);
                if cut(&out, limit) {
                    return out;
                }
            }
        }
    }
    for k in suffixes {
        for t in derive_from_suffix(&k) {
            if seen.insert(t.clone()) {
                out.push(t);
                if cut(&out, limit) {
                    return out;
                }
            }
        }
    }
    out
}

fn cut<T>(v: &Vec<T>, limit: Option<usize>) -> bool {
    limit.map(|n| v.len() >= n).unwrap_or(false)
}

/// 为"对比两版 DSL"提供的目标集生成器：
// - 若传入 input_targets 非空，优先使用之；
// - 否则对两份 DSL 合并派生（limit 为上限）。
pub fn derive_compare_targets(
    dsl_a: &str,
    dsl_b: &str,
    input_targets: Option<&str>,
    limit: Option<usize>,
) -> Vec<String> {
    if let Some(s) = input_targets {
        let mut out = Vec::new();
        for l in s.lines() {
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            out.push(t.to_string());
        }
        return out;
    }
    // 合并派生（A+B）
    let mut all = String::new();
    all.push_str(dsl_a);
    all.push('\n');
    all.push_str(dsl_b);
    derive_targets(&all, limit)
}
