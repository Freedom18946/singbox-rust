use crate::model::{Outbound, Profile, RuleEntry, SubsError};
use crate::MergeStats;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct ClashDoc {
    #[serde(default)]
    proxies: Vec<serde_yaml::Value>,
    #[serde(default)]
    rules: Vec<String>,
}

fn map_rule(line: &str, use_keyword: bool) -> Option<String> {
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if parts.len() < 2 {
        return None;
    }
    let kind = parts[0].to_ascii_uppercase();
    let pat = parts.get(1).copied().unwrap_or("");
    let act = parts
        .get(2)
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "proxy".into());
    let decision = match act.as_str() {
        "direct" => "direct",
        "reject" => "reject",
        other => other,
    };
    match kind.as_str() {
        "DOMAIN" => Some(format!("exact:{}={}", pat, decision)),
        "DOMAIN-SUFFIX" => Some(format!("suffix:{}={}", pat, decision)),
        "DOMAIN-KEYWORD" => {
            if use_keyword {
                Some(format!("keyword:{}={}", pat, decision))
            } else {
                Some(format!("suffix:*{}*={}", pat, decision))
            }
        }
        "NETWORK" => {
            // NETWORK,TCP|UDP,<act>
            let v = pat.to_ascii_lowercase();
            match v.as_str() {
                "tcp" => Some(format!("transport:tcp={}", decision)),
                "udp" => Some(format!("transport:udp={}", decision)),
                _ => None,
            }
        }
        "IP-CIDR" | "IP-CIDR6" => Some(format!("cidr:{}={}", pat, decision)),
        "DST-PORT" => {
            if let Some((a, b)) = pat.split_once('-') {
                if let (Ok(x), Ok(y)) = (a.parse::<u16>(), b.parse::<u16>()) {
                    // 保留原始顺序，交由后续 Lint/Normalize 处理
                    return Some(format!("portrange:{}-{}={}", x, y, decision));
                }
            }
            if let Ok(p) = pat.parse::<u16>() {
                return Some(format!("port:{}={}", p, decision));
            }
            None
        }
        "GEOIP" => Some(format!("geoip:{}={}", pat, decision)),
        "GEOSITE" => Some(format!("suffix:{}={}", pat, decision)),
        _ => None,
    }
}

pub fn parse_with_mode(yaml: &str, use_keyword: bool) -> Result<Profile, SubsError> {
    let doc: ClashDoc = serde_yaml::from_str(yaml).map_err(|e| SubsError::Parse(e.to_string()))?;
    let mut p = Profile::default();
    for r in doc.rules {
        if let Some(line) = map_rule(&r, use_keyword) {
            p.rules.push(RuleEntry { line });
        }
    }
    for v in doc.proxies {
        if let (Some(name), Some(kind)) = (v.get("name"), v.get("type")) {
            let name = name.as_str().unwrap_or_default().to_string();
            let kind = kind.as_str().unwrap_or_default().to_string();
            if !name.is_empty() && !kind.is_empty() {
                p.outbounds.push(Outbound {
                    name,
                    kind,
                    ..Default::default()
                });
            }
        }
    }
    Ok(p)
}

pub fn parse(yaml: &str) -> Result<Profile, SubsError> {
    parse_with_mode(yaml, false)
}

/// R71: 带 providers 的解析与合并（只读，providers 由上层提供）
/// providers key 形如：ruleset:NAME / geosite:NAME，value 为该集合的文本（每行一条 Clash 规则）
pub fn parse_with_providers(
    yaml: &str,
    use_keyword: bool,
    providers: &HashMap<String, String>,
) -> Result<Profile, SubsError> {
    let doc: ClashDoc = serde_yaml::from_str(yaml).map_err(|e| SubsError::Parse(e.to_string()))?;
    let mut p = Profile::default();
    let mut _stats = MergeStats::default();
    // rules
    for r in doc.rules {
        let parts: Vec<&str> = r.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("RULE-SET") {
            let name = parts[1];
            let decision = parts[2].to_ascii_lowercase();
            let key = format!("ruleset:{}", name);
            if let Some(body) = providers.get(&key) {
                for line in body
                    .lines()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                {
                    if let Some(mapped) = map_rule(line, use_keyword) {
                        let mapped = if let Some((lhs, _)) = mapped.split_once('=') {
                            format!("{}={}", lhs, decision)
                        } else {
                            mapped
                        };
                        p.rules.push(RuleEntry { line: mapped });
                        _stats.applied_ruleset += 1;
                    }
                }
            } else {
                _stats.skipped_unknown += 1;
            }
            continue;
        }
        if parts.len() >= 3 && parts[0].eq_ignore_ascii_case("GEOSITE") {
            let name = parts[1];
            let decision = parts[2].to_ascii_lowercase();
            let key = format!("geosite:{}", name);
            if let Some(body) = providers.get(&key) {
                for line in body
                    .lines()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && !s.starts_with('#'))
                {
                    let mapped = format!("suffix:{}={}", line, decision);
                    p.rules.push(RuleEntry { line: mapped });
                    _stats.applied_geosite += 1;
                }
            } else {
                // 无 providers 时保持兼容：退化为原有 GEOSITE→suffix 的单行
                if let Some(mapped) = map_rule(&r, use_keyword) {
                    p.rules.push(RuleEntry { line: mapped });
                } else {
                    _stats.skipped_unknown += 1;
                }
            }
            continue;
        }
        if let Some(mapped) = map_rule(&r, use_keyword) {
            p.rules.push(RuleEntry { line: mapped });
        }
    }
    // proxies passthrough
    for v in doc.proxies {
        if let (Some(name), Some(kind)) = (v.get("name"), v.get("type")) {
            let name = name.as_str().unwrap_or_default().to_string();
            let kind = kind.as_str().unwrap_or_default().to_string();
            if !name.is_empty() && !kind.is_empty() {
                p.outbounds.push(Outbound {
                    name,
                    kind,
                    ..Default::default()
                });
            }
        }
    }
    Ok(p)
}
