use crate::model::{Outbound, Profile, RuleEntry, SubsError};
use serde::Deserialize;

#[derive(Deserialize)]
struct SBoxDoc {
    #[serde(default)]
    outbounds: Vec<serde_json::Value>,
    #[serde(default)]
    route: Option<Route>,
}

#[derive(Deserialize)]
struct Route {
    #[serde(default)]
    rules: Vec<serde_json::Value>,
}

fn push_domains(out: &mut Vec<RuleEntry>, arr: &serde_json::Value, prefix: &str, decision: &str) {
    if let Some(list) = arr.as_array() {
        for d in list {
            if let Some(s) = d.as_str() {
                out.push(RuleEntry {
                    line: format!("{}:{}={}", prefix, s, decision),
                });
            }
        }
    }
}

fn map_rule(v: &serde_json::Value, use_keyword: bool, out: &mut Vec<String>) {
    let decision = v
        .get("outbound")
        .and_then(|x| x.as_str())
        .unwrap_or("default")
        .to_lowercase();
    if let Some(list) = v.get("domain").and_then(|x| x.as_array()) {
        for d in list {
            if let Some(s) = d.as_str() {
                out.push(format!("exact:{}={}", s, decision));
            }
        }
    }
    if let Some(list) = v.get("domain_suffix").and_then(|x| x.as_array()) {
        for d in list {
            if let Some(s) = d.as_str() {
                out.push(format!("suffix:{}={}", s, decision));
            }
        }
    }
    if let Some(list) = v.get("domain_keyword").and_then(|x| x.as_array()) {
        for d in list {
            if let Some(s) = d.as_str() {
                if use_keyword {
                    out.push(format!("keyword:{}={}", s, decision));
                } else {
                    out.push(format!("suffix:*{}*={}", s, decision));
                }
            }
        }
    }
    if let Some(list) = v.get("ip_cidr").and_then(|x| x.as_array()) {
        for d in list {
            if let Some(s) = d.as_str() {
                out.push(format!("cidr:{}={}", s, decision));
            }
        }
    }
    if let Some(list) = v.get("ip_cidr6").and_then(|x| x.as_array()) {
        for d in list {
            if let Some(s) = d.as_str() {
                out.push(format!("cidr:{}={}", s, decision));
            }
        }
    }
    if let Some(net) = v.get("network").and_then(|x| x.as_str()) {
        match net.to_ascii_lowercase().as_str() {
            "tcp" => out.push(format!("transport:tcp={}", decision)),
            "udp" => out.push(format!("transport:udp={}", decision)),
            _ => {}
        }
    }
}

pub fn parse_with_mode(json: &str, use_keyword: bool) -> Result<Profile, SubsError> {
    let doc: SBoxDoc = serde_json::from_str(json).map_err(|e| SubsError::Parse(e.to_string()))?;
    let mut p = Profile::default();
    if let Some(route) = doc.route {
        let mut lines = Vec::new();
        for r in route.rules {
            map_rule(&r, use_keyword, &mut lines);
        }
        p.rules
            .extend(lines.into_iter().map(|line| RuleEntry { line }));
    }
    for v in doc.outbounds {
        if let (Some(name), Some(kind)) = (v.get("tag"), v.get("type")) {
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

pub fn parse(json: &str) -> Result<Profile, SubsError> {
    parse_with_mode(json, false)
}
