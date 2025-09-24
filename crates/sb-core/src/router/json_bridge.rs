#![cfg(feature = "router_json")]
use crate::router::rules::{self as r, Decision, Engine, Rule, RuleKind};
#[cfg(feature = "metrics")]
use metrics::counter;
use serde::Deserialize;
use std::{fs, str::FromStr};

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Clone))]
pub struct JsonRule {
    #[serde(alias = "type")]
    kind: String,
    #[serde(default)]
    value: serde_json::Value,
    #[serde(default)]
    values: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    transport: Option<String>, // "tcp"/"udp"
    #[serde(default)]
    outbound: Option<String>, // "direct"/"proxy"/"reject"
}

#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Clone))]
pub struct JsonDoc {
    #[serde(default)]
    rules: Vec<JsonRule>,
    #[serde(default)]
    default: Option<String>,
}

fn parse_decision(s: &str) -> Option<Decision> {
    match s.to_ascii_lowercase().as_str() {
        "direct" => Some(Decision::Direct),
        "proxy" => Some(Decision::Proxy),
        "reject" => Some(Decision::Reject),
        _ => None,
    }
}

fn as_str(v: &serde_json::Value) -> Option<&str> {
    v.as_str()
}

fn as_u16(v: &serde_json::Value) -> Option<u16> {
    if let Some(n) = v.as_u64() {
        if n <= u16::MAX as u64 {
            return Some(n as u16);
        }
    }
    if let Some(s) = v.as_str() {
        if let Ok(u) = s.parse::<u16>() {
            return Some(u);
        }
    }
    None
}

fn to_rules(mut doc: JsonDoc) -> Vec<Rule> {
    let mut out = Vec::<Rule>::new();
    for jr in doc.rules.drain(..) {
        let decision = jr
            .outbound
            .as_deref()
            .and_then(parse_decision)
            .unwrap_or(Decision::Direct);
        let k = jr.kind.to_ascii_lowercase();
        let xs: Vec<serde_json::Value> = match jr.values {
            Some(vs) if !vs.is_empty() => vs,
            _ => vec![jr.value], // 单值也走统一流程
        };
        // transport 附加成独立规则：transport:tcp/udp
        let t_rule = match jr.transport.as_deref().map(|s| s.to_ascii_lowercase()) {
            Some(ref t) if t == "udp" => Some(Rule {
                kind: RuleKind::TransportUdp,
                decision,
            }),
            Some(ref t) if t == "tcp" => Some(Rule {
                kind: RuleKind::TransportTcp,
                decision,
            }),
            _ => None,
        };
        // 主体规则：支持大量别名
        let mut append = |rk: RuleKind| {
            out.push(Rule { kind: rk, decision });
        };
        match k.as_str() {
            // domain exact
            "domain" | "exact" | "domain_exact" | "host" => {
                for v in xs.iter().filter_map(as_str) {
                    append(RuleKind::Exact(v.to_string()));
                }
            }
            // domain suffix
            "domain_suffix" | "suffix" => {
                for v in xs.iter().filter_map(as_str) {
                    append(RuleKind::Suffix(v.to_string()));
                }
            }
            // domain keyword
            "domain_keyword" | "keyword" => {
                for v in xs.iter().filter_map(as_str) {
                    append(RuleKind::Keyword(v.to_string()));
                }
            }
            // ip cidr
            "ip_cidr" | "ipcidr" | "ip-cidr" => {
                for v in xs.iter().filter_map(as_str) {
                    match ipnet::IpNet::from_str(v) {
                        Ok(n) => append(RuleKind::IpCidr(n)),
                        Err(_) => {
                            #[cfg(feature = "metrics")]
                            counter!("router_json_bridge_errors_total","kind"=>"bad_ip_cidr")
                                .increment(1);
                        }
                    }
                }
            }
            // port, portrange, portset
            "port" => {
                for v in xs.iter().filter_map(as_u16) {
                    append(RuleKind::Port(v));
                }
            }
            "portrange" | "port_range" => {
                // 支持 "1000-2000" 或 [1000,2000]
                for v in xs.iter() {
                    if let Some(s) = v.as_str() {
                        if let Some((a, b)) = s.split_once('-') {
                            if let (Ok(a), Ok(b)) =
                                (a.trim().parse::<u16>(), b.trim().parse::<u16>())
                            {
                                append(RuleKind::PortRange(a, b));
                            } else {
                                #[cfg(feature = "metrics")]
                                counter!("router_json_bridge_errors_total","kind"=>"bad_port")
                                    .increment(1);
                            }
                        }
                    } else if let Some(arr) = v.as_array() {
                        if arr.len() == 2 {
                            if let (Some(a), Some(b)) = (as_u16(&arr[0]), as_u16(&arr[1])) {
                                append(RuleKind::PortRange(a, b));
                            }
                        }
                    }
                }
            }
            "portset" | "port_set" | "ports" => {
                let mut set = Vec::<u16>::new();
                for v in xs.iter().filter_map(as_u16) {
                    if !set.contains(&v) {
                        set.push(v)
                    }
                }
                if !set.is_empty() {
                    append(RuleKind::PortSet(set));
                }
            }
            "default" => {
                // 允许把 default 写成一条规则
                append(RuleKind::Default);
            }
            other => {
                #[cfg(feature = "metrics")]
                counter!("router_json_bridge_errors_total","kind"=>"unknown_rule_type")
                    .increment(1);
                tracing::warn!(rule_kind=%other, "router.json_bridge: unknown rule.kind");
            }
        }
        // 追加 transport 限定（拆分出的独立规则）
        if let Some(tr) = t_rule {
            out.push(tr);
        }
    }
    // 顶层 default
    if let Some(d) = doc.default.as_deref().and_then(parse_decision) {
        out.push(Rule {
            kind: RuleKind::Default,
            decision: d,
        });
    }
    out
}

/// 从 JSON 文本/文件初始化并安装规则引擎（ENV 控制；默认不启用）
/// 优先顺序：若 `rules::global()` 已启（例如 TEXT/FILE 已装），则跳过不覆盖。
pub fn init_from_json_env() {
    if r::global().is_some() {
        return;
    }
    let enable = std::env::var("SB_ROUTER_RULES_FROM_JSON")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enable {
        return;
    }
    // 读取 JSON
    let src = if let Ok(path) = std::env::var("SB_ROUTER_JSON_FILE") {
        match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(%path, error=%e, "router.json_bridge: read file failed");
                return;
            }
        }
    } else if let Ok(text) = std::env::var("SB_ROUTER_JSON_TEXT") {
        text
    } else {
        tracing::warn!("router.json_bridge: enabled but no JSON provided");
        return;
    };
    // 解析
    let doc: JsonDoc = match serde_json::from_str(&src) {
        Ok(d) => d,
        Err(e) => {
            #[cfg(feature = "metrics")]
            counter!("router_json_bridge_errors_total","kind"=>"json_parse").increment(1);
            tracing::warn!(error=%e, "router.json_bridge: parse json failed");
            return;
        }
    };
    let rules = to_rules(doc);
    let n = rules.len();
    if n == 0 {
        tracing::warn!("router.json_bridge: empty rules");
        return;
    }
    let eng = Engine::build(rules);
    r::install_global(eng);
    tracing::info!(
        rules = n,
        "router.json_bridge: global rules engine installed from JSON"
    );
}

// 暴露用于测试的函数
pub fn to_rules_for_test(doc: JsonDoc) -> Vec<Rule> {
    to_rules(doc)
}
