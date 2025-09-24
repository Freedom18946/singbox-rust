//! 订阅导入（Clash / Sing-Box 子集）
//! 目标：把第三方订阅（文本）映射为我们内部的 `Config`
//! - Clash: YAML (proxies / proxy-groups / rules)
//! - Sing-Box: JSON/YAML (outbounds / route.rules)
//! 取最常见的子集，保持健壮降级；不做远程下载，这里只做 parse。

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::HashSet;

use crate::{Auth, Config, Outbound, Rule};

/// 入口：根据格式自动探测并解析
pub fn from_subscription(text: &str) -> Result<Config> {
    // 先尝试 Clash YAML
    if let Ok(cfg) = parse_clash_yaml(text) {
        return Ok(cfg);
    }
    // 再尝试 Sing-Box JSON
    if let Ok(cfg) = parse_singbox_json(text) {
        return Ok(cfg);
    }
    // 最后尝试 Sing-Box YAML（将 YAML 转 JSON 再复用解析）
    if let Ok(val_yaml) = serde_yaml::from_str::<serde_yaml::Value>(text) {
        let json = serde_json::to_value(val_yaml).context("yaml->json")?;
        if let Ok(cfg) = parse_singbox_json_value(json) {
            return Ok(cfg);
        }
    }
    Err(anyhow!("unsupported subscription format"))
}

// ---------------- Clash ----------------

#[derive(Debug, Deserialize)]
struct ClashSub {
    #[serde(default)]
    proxies: Vec<ClashProxy>,
    #[serde(default)]
    #[allow(dead_code)]
    proxy_groups: Vec<ClashGroup>,
    #[serde(default)]
    rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClashProxy {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    server: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClashGroup {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    proxies: Vec<String>,
}

fn parse_clash_yaml(text: &str) -> Result<Config> {
    let sub: ClashSub = serde_yaml::from_str(text).context("parse clash yaml")?;

    // 1) 映射节点为 outbounds
    let mut outbounds = Vec::<Outbound>::new();
    let mut names = HashSet::new();
    for p in &sub.proxies {
        if !names.insert(p.name.clone()) {
            return Err(anyhow!("duplicate proxy name in subscription: {}", p.name));
        }
        match p.kind.as_str() {
            "socks" | "socks5" => {
                outbounds.push(Outbound::Socks5 {
                    name: p.name.clone(),
                    server: p.server.clone(),
                    port: p.port,
                    auth: match (&p.username, &p.password) {
                        (Some(u), Some(w)) => Some(Auth {
                            username: u.clone(),
                            password: w.clone(),
                        }),
                        _ => None,
                    },
                });
            }
            "http" | "https" => {
                outbounds.push(Outbound::Http {
                    name: p.name.clone(),
                    server: p.server.clone(),
                    port: p.port,
                    auth: match (&p.username, &p.password) {
                        (Some(u), Some(w)) => Some(Auth {
                            username: u.clone(),
                            password: w.clone(),
                        }),
                        _ => None,
                    },
                });
            }
            _ => {
                // 其他类型忽略（如 vmess/trojan 等），我们当前不支持，留空即可
            }
        }
    }

    // 2) 规则映射（仅识别 DOMAIN-SUFFIX / MATCH）
    let mut rules = Vec::<Rule>::new();
    let mut default_outbound: Option<String> = None;
    for r in &sub.rules {
        // 例：DOMAIN-SUFFIX,example.com,ProxyName
        //     MATCH,ProxyName
        let parts: Vec<&str> = r.split(',').map(|s| s.trim()).collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0] {
            "DOMAIN-SUFFIX" if parts.len() >= 3 => {
                let suf = parts[1];
                let ob = parts[2];
                rules.push(Rule {
                    domain_suffix: vec![suf.to_string()],
                    outbound: ob.to_string(),
                    ..Default::default()
                });
            }
            "MATCH" if parts.len() >= 2 => {
                default_outbound = Some(parts[1].to_string());
            }
            _ => {} // 其余规则类型暂不支持
        }
    }

    // 3) 注入 direct 作为兜底出站，如果订阅没给
    if !outbounds
        .iter()
        .any(|o| matches!(o, Outbound::Direct { .. }))
    {
        outbounds.push(Outbound::Direct {
            name: "direct".into(),
        });
    }

    Ok(Config {
        inbounds: vec![], // 不从订阅生成入站
        outbounds,
        rules,
        default_outbound,
    })
}

// ---------------- Sing-Box ----------------

fn parse_singbox_json(text: &str) -> Result<Config> {
    let val: JsonValue = serde_json::from_str(text).context("parse sing-box json")?;
    parse_singbox_json_value(val)
}

fn parse_singbox_json_value(val: JsonValue) -> Result<Config> {
    // 结构：{ "outbounds": [...], "route": {"rules": [...] } }
    let outbounds = val
        .get("outbounds")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let route_rules = val
        .pointer("/route/rules")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut outs = Vec::<Outbound>::new();
    let mut names = HashSet::new();

    for ob in outbounds {
        let kind = ob.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let name = ob
            .get("tag")
            .or_else(|| ob.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        if !names.insert(name.clone()) {
            return Err(anyhow!("duplicate outbound tag: {}", name));
        }
        match kind {
            "direct" => outs.push(Outbound::Direct { name }),
            "block" => outs.push(Outbound::Block { name }),
            "http" => {
                let server = ob
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let port = ob.get("server_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let auth = match (
                    ob.get("username").and_then(|v| v.as_str()),
                    ob.get("password").and_then(|v| v.as_str()),
                ) {
                    (Some(u), Some(p)) => Some(Auth {
                        username: u.into(),
                        password: p.into(),
                    }),
                    _ => None,
                };
                if !server.is_empty() && port > 0 {
                    outs.push(Outbound::Http {
                        name,
                        server,
                        port,
                        auth,
                    });
                }
            }
            "socks" | "socks5" => {
                let server = ob
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let port = ob.get("server_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let auth = match (
                    ob.get("username").and_then(|v| v.as_str()),
                    ob.get("password").and_then(|v| v.as_str()),
                ) {
                    (Some(u), Some(p)) => Some(Auth {
                        username: u.into(),
                        password: p.into(),
                    }),
                    _ => None,
                };
                if !server.is_empty() && port > 0 {
                    outs.push(Outbound::Socks5 {
                        name,
                        server,
                        port,
                        auth,
                    });
                }
            }
            _ => {}
        }
    }

    // 规则：识别 "domain_suffix": ["example.com"], "outbound": "tag"
    let mut rules = Vec::<Rule>::new();
    for r in route_rules {
        if let Some(ob) = r.get("outbound").and_then(|v| v.as_str()) {
            if let Some(dom) = r.get("domain_suffix").and_then(|v| v.as_array()) {
                let mut ds = Vec::new();
                for d in dom {
                    if let Some(s) = d.as_str() {
                        ds.push(s.to_string());
                    }
                }
                if !ds.is_empty() {
                    rules.push(Rule {
                        domain_suffix: ds,
                        outbound: ob.to_string(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    if !outs.iter().any(|o| matches!(o, Outbound::Direct { .. })) {
        outs.push(Outbound::Direct {
            name: "direct".into(),
        });
    }

    Ok(Config {
        inbounds: vec![],
        outbounds: outs,
        rules,
        default_outbound: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clash_minimal() {
        let y = r#"
proxies:
  - {name: corp-socks, type: socks5, server: 10.0.0.3, port: 1080, username: u, password: p}
rules:
  - DOMAIN-SUFFIX,example.com,corp-socks
  - MATCH,c
"#;
        let cfg = from_subscription(y).unwrap();
        assert!(cfg
            .outbounds
            .iter()
            .any(|o| matches!(o, Outbound::Socks5 {name, ..} if name=="corp-socks")));
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.default_outbound.as_deref(), Some("c"));
    }

    #[test]
    fn singbox_minimal() {
        let j = r#"
{"outbounds":[{"type":"http","tag":"h","server":"1.1.1.1","server_port":3128}],
 "route":{"rules":[{"outbound":"h","domain_suffix":["example.com"]}]}}
"#;
        let cfg = from_subscription(j).unwrap();
        assert!(cfg
            .outbounds
            .iter()
            .any(|o| matches!(o, Outbound::Http {name, ..} if name=="h")));
        assert_eq!(cfg.rules.len(), 1);
    }
}
