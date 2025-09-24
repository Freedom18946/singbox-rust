//! 轻量 DSL 诊断（标准 DSL 文本，不含 include/macro；如需，请先经 DSL+ 展开）
//! 目标：生产"可脚本消费"的诊断 JSON 字符串，覆盖：
//!   - 计数统计（exact/suffix/default/portset/transport/other）
//!   - 重复/冲突（同 key 多决策）
//!   - 遮蔽（first-wins 下后续规则不可达）
//! 说明：仅做文本级静态分析，**不改变**任何路由行为。
use std::collections::{BTreeMap, BTreeSet};

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
struct Line {
    lineno: usize,
    raw: String,
    kind: Kind,
    key: String,      // exact/suffix/portset/transport 的 key；default 留空
    decision: String, // = 右侧；无法解析时为空
}

#[derive(Debug, Default)]
pub struct Analysis {
    pub counts: BTreeMap<&'static str, usize>,
    pub duplicates: Vec<String>,
    pub conflicts: Vec<String>,
    pub shadowed: Vec<String>,
}

fn parse_line(lineno: usize, raw: &str) -> Line {
    let t = raw.trim();
    // 忽略注释/空行（上层应已清理；这里防御性处理）
    if t.is_empty() || t.starts_with('#') {
        return Line {
            lineno,
            raw: raw.to_string(),
            kind: Kind::Other,
            key: String::new(),
            decision: String::new(),
        };
    }
    // 形如：prefix:key=value
    let (prefix, rest) = match t.split_once(':') {
        Some(x) => x,
        None => {
            return Line {
                lineno,
                raw: raw.to_string(),
                kind: Kind::Other,
                key: String::new(),
                decision: String::new(),
            };
        }
    };
    // decision
    let (key, decision) = match rest.split_once('=') {
        Some((k, d)) => (k.trim().to_string(), d.trim().to_string()),
        None => (rest.trim().to_string(), String::new()),
    };
    let kind = match prefix.trim() {
        "exact" => Kind::Exact,
        "suffix" => Kind::Suffix,
        "default" => Kind::Default,
        "portset" => Kind::Portset,
        "transport" => Kind::Transport,
        _ => Kind::Other,
    };
    Line {
        lineno,
        raw: t.to_string(),
        kind,
        key,
        decision,
    }
}

fn inc(map: &mut BTreeMap<&'static str, usize>, k: &'static str) {
    *map.entry(k).or_insert(0) += 1;
}

pub fn analyze_dsl(dsl_text: &str) -> Analysis {
    let mut lines = Vec::<Line>::new();
    for (i, raw) in dsl_text.lines().enumerate() {
        let l = parse_line(i + 1, raw);
        // 过滤空白/注释
        if !l.raw.is_empty() && !l.raw.starts_with('#') {
            lines.push(l);
        }
    }
    let mut a = Analysis::default();
    // 计数
    for l in &lines {
        match l.kind {
            Kind::Exact => inc(&mut a.counts, "exact"),
            Kind::Suffix => inc(&mut a.counts, "suffix"),
            Kind::Default => inc(&mut a.counts, "default"),
            Kind::Portset => inc(&mut a.counts, "portset"),
            Kind::Transport => inc(&mut a.counts, "transport"),
            Kind::Other => inc(&mut a.counts, "other"),
        }
    }
    // 重复/冲突（Exact/Suffix）
    let mut seen_exact: BTreeMap<String, String> = BTreeMap::new();
    let mut dup_exact: BTreeSet<String> = BTreeSet::new();
    let mut seen_suffix: BTreeMap<String, String> = BTreeMap::new();
    let mut dup_suffix: BTreeSet<String> = BTreeSet::new();
    for l in &lines {
        match l.kind {
            Kind::Exact => {
                if let Some(prev) = seen_exact.get(&l.key) {
                    if prev == &l.decision {
                        a.duplicates.push(format!(
                            "exact:{k} at L{line} duplicated with same decision `{d}`",
                            k = l.key,
                            line = l.lineno,
                            d = l.decision
                        ));
                        dup_exact.insert(l.key.clone());
                    } else {
                        a.conflicts.push(format!(
                            "exact:{k} at L{line} conflicts: `{d1}` -> `{d2}`",
                            k = l.key,
                            line = l.lineno,
                            d1 = prev,
                            d2 = l.decision
                        ));
                    }
                } else {
                    seen_exact.insert(l.key.clone(), l.decision.clone());
                }
            }
            Kind::Suffix => {
                if let Some(prev) = seen_suffix.get(&l.key) {
                    if prev == &l.decision {
                        a.duplicates.push(format!(
                            "suffix:{k} at L{line} duplicated with same decision `{d}`",
                            k = l.key,
                            line = l.lineno,
                            d = l.decision
                        ));
                        dup_suffix.insert(l.key.clone());
                    } else {
                        a.conflicts.push(format!(
                            "suffix:{k} at L{line} conflicts: `{d1}` -> `{d2}`",
                            k = l.key,
                            line = l.lineno,
                            d1 = prev,
                            d2 = l.decision
                        ));
                    }
                } else {
                    seen_suffix.insert(l.key.clone(), l.decision.clone());
                }
            }
            _ => {}
        }
    }
    // 遮蔽（first-wins）：更粗的前置规则挡住后续更细规则/精确项
    // 规则：
    //   - 早期 suffix:S1 遮蔽后续 exact:K 若 K.ends_with(S1)
    //   - 早期 suffix:S1 遮蔽后续 suffix:S2 若 S2.ends_with(S1)
    //   - 早期 default:* 遮蔽其后的任何行
    let mut prior_suffixes: Vec<(usize, String, String)> = Vec::new(); // (lineno,key,decision)
    let mut seen_default_at: Option<usize> = None;
    for l in &lines {
        match l.kind {
            Kind::Suffix => prior_suffixes.push((l.lineno, l.key.clone(), l.decision.clone())),
            Kind::Default => {
                if seen_default_at.is_none() {
                    seen_default_at = Some(l.lineno);
                } else {
                    a.duplicates.push(format!(
                        "default at L{} duplicated (earlier default at L{})",
                        l.lineno,
                        seen_default_at.unwrap()
                    ));
                }
            }
            _ => {}
        }
    }
    for l in &lines {
        if let Some(dft) = seen_default_at {
            if l.lineno > dft {
                a.shadowed.push(format!(
                    "L{} `{}` shadowed by earlier default at L{}",
                    l.lineno, l.raw, dft
                ));
                continue;
            }
        }
        match l.kind {
            Kind::Exact => {
                for (pl, s, _d) in &prior_suffixes {
                    if l.lineno > *pl && l.key.ends_with(s) {
                        a.shadowed.push(format!(
                            "exact:{k} at L{line} shadowed by suffix:{suf} at L{pl}",
                            k = l.key,
                            line = l.lineno,
                            suf = s,
                            pl = pl
                        ));
                        break;
                    }
                }
            }
            Kind::Suffix => {
                for (pl, s, _d) in &prior_suffixes {
                    if l.lineno > *pl && l.key.ends_with(s) {
                        a.shadowed.push(format!(
                            "suffix:{k} at L{line} shadowed by suffix:{suf} at L{pl}",
                            k = l.key,
                            line = l.lineno,
                            suf = s,
                            pl = pl
                        ));
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    a
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 返回紧凑 JSON 字符串（无 serde 依赖）
pub fn analysis_to_json(a: &Analysis) -> String {
    let mut js = String::new();
    js.push('{');
    // counts
    js.push_str("\"counts\":{");
    let mut first = true;
    for (k, v) in &a.counts {
        if !first {
            js.push(',');
        }
        first = false;
        js.push('"');
        js.push_str(k);
        js.push_str("\":");
        js.push_str(&v.to_string());
    }
    js.push_str("},");
    // arrays
    fn arr(buf: &mut String, name: &str, xs: &Vec<String>) {
        buf.push('"');
        buf.push_str(name);
        buf.push_str("\":[");
        for (i, it) in xs.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            buf.push('"');
            buf.push_str(&esc(it));
            buf.push('"');
        }
        buf.push(']');
    }
    arr(&mut js, "duplicates", &a.duplicates);
    js.push(',');
    arr(&mut js, "conflicts", &a.conflicts);
    js.push(',');
    arr(&mut js, "shadowed", &a.shadowed);
    js.push('}');
    js
}
