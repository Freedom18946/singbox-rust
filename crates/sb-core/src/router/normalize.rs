//! R38: 规则规范化
//! 目标：消除非功能性差异（顺序/空白），便于 CI 与审阅。
//! 策略：
//!  1) 去 BOM，统一 LF；行首尾 trim（但保留内部空格）
//!  2) 丢弃连续空行（折叠为一个），保留注释行次序
//!  3) 规则行按 kind→key→decision 排序，kind 顺序：
//!     exact < suffix < port < portset < portrange < transport < cidr < geoip < include < default
//!  4) 统一格式：kind:key=value；确保 EOF 换行
use std::cmp::Ordering;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Exact,
    Suffix,
    Port,
    Portset,
    Portrange,
    Transport,
    Cidr,
    Geoip,
    Include,
    Default,
    Other,
}

fn classify(line: &str) -> (Kind, String, String) {
    let val = if let Some((_lhs, rhs)) = line.split_once('=') {
        rhs.trim().to_string()
    } else {
        String::new()
    };

    if let Some((lhs, _)) = line.split_once('=') {
        let lhs = lhs.trim();
        macro_rules! m {
            ($p:literal,$k:expr,$kind:expr) => {
                if let Some(rest) = lhs.strip_prefix($p) {
                    let key = $k(rest);
                    return ($kind, key, val.clone());
                }
            };
        }
        m!("exact:", |x: &str| x.trim().to_string(), Kind::Exact);
        m!("suffix:", |x: &str| x.trim().to_string(), Kind::Suffix);
        m!("port:", |x: &str| x.trim().to_string(), Kind::Port);
        m!("portset:", |x: &str| x.trim().to_string(), Kind::Portset);
        m!(
            "portrange:",
            |x: &str| x.trim().to_string(),
            Kind::Portrange
        );
        m!(
            "transport:",
            |x: &str| x.trim().to_string(),
            Kind::Transport
        );
        // 接受 cidr4/cidr6 统一归类为 cidr
        if let Some(rest) = lhs.strip_prefix("cidr4:") {
            let key = rest.trim().to_string();
            return (Kind::Cidr, key, val.clone());
        }
        if let Some(rest) = lhs.strip_prefix("cidr6:") {
            let key = rest.trim().to_string();
            return (Kind::Cidr, key, val.clone());
        }
        m!("geoip:", |x: &str| x.trim().to_string(), Kind::Geoip);
        m!("include:", |x: &str| x.trim().to_string(), Kind::Include);
        m!("default:", |x: &str| x.trim().to_string(), Kind::Default);
    }
    (Kind::Other, line.trim().to_string(), val)
}

pub fn normalize(input: &str) -> String {
    // 1) 去 BOM / 统一行结束
    let s = input
        .trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut comments: Vec<String> = Vec::new();
    let mut rules: Vec<(Kind, String, String)> = Vec::new();
    for raw in s.lines() {
        let line = raw.trim();
        if line.is_empty() {
            comments.push(String::new());
            continue;
        }
        if line.starts_with('#') {
            comments.push(line.to_string());
            continue;
        }
        let (k, key, val) = classify(line);
        rules.push((k, key, val));
    }
    // 2) 注释保持原序写回，空行折叠
    let mut out = String::new();
    let mut last_blank = false;
    for c in comments.iter() {
        if c.is_empty() {
            if !last_blank {
                out.push('\n');
                last_blank = true;
            }
        } else {
            out.push_str(c);
            out.push('\n');
            last_blank = false;
        }
    }
    // 3) 规则排序
    rules.sort_by(|a, b| match a.0.cmp(&b.0) {
        Ordering::Equal => match a.1.cmp(&b.1) {
            Ordering::Equal => a.2.cmp(&b.2),
            o => o,
        },
        o => o,
    });
    // 4) 统一格式写回（去重 default：仅保留最后一个）
    let mut last_default: Option<String> = None;
    for (k, key, val) in rules {
        use Kind::*;
        let prefix = match k {
            Exact => "exact",
            Suffix => "suffix",
            Port => "port",
            Portset => "portset",
            Portrange => "portrange",
            Transport => "transport",
            Cidr => "cidr",
            Geoip => "geoip",
            Include => "include",
            Default => "default",
            Other => "other",
        };
        if prefix == "default" {
            last_default = Some(val);
            continue;
        }
        out.push_str(prefix);
        out.push(':');
        out.push_str(&key);
        out.push('=');
        out.push_str(&val);
        out.push('\n');
    }
    if let Some(v) = last_default {
        out.push_str("default:");
        out.push_str(&v);
        out.push('\n');
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}
