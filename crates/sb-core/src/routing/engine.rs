//! Rule engine over ConfigIR with support for positive/negative dimensions.
//! Inputs: host (domain or ip), port, network ("tcp"|"udp"), protocol ("socks"|"http"|..)
//! Output: outbound name (or type) + trace steps (for opt-in explain).
use crate::routing::trace::{canonicalize_rule_text, sha8, Step, Trace};
use sb_config::ir::{ConfigIR, RuleIR};
use serde::Serialize;
use std::net::IpAddr;

// 供 Engine 等处使用的回调类型（确保可跨线程共享）
pub type ClassifyIpFn = dyn Fn(IpAddr) -> Option<&'static str> + Send + Sync;
pub type MatchHostFn = dyn for<'a> Fn(&'a str) -> bool + Send + Sync;

#[derive(Debug, Clone, Serialize)]
pub struct Decide {
    pub outbound: String,     // outbound name or builtin type ("direct")
    pub matched_rule: String, // sha256-8 of canonical_rule
    pub chain: Vec<String>,   // ["cidr:1.2.3.0/24","geoip:US",...]
    pub trace: Option<Trace>, // detailed steps (opt-in)
}

#[derive(Debug, Clone)]
pub struct Input<'a> {
    pub host: &'a str, // domain or ip string
    pub port: u16,
    pub network: &'a str,  // "tcp"|"udp"
    pub protocol: &'a str, // "socks"|"http"|...
}

pub struct Engine<'a> {
    pub cfg: &'a ConfigIR,
    geoip: Option<&'a ClassifyIpFn>,  // reserved for future
    geosite: Option<&'a MatchHostFn>, // reserved for future
}

impl<'a> std::fmt::Debug for Engine<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("cfg", &self.cfg)
            .field("geoip", &self.geoip.is_some())
            .field("geosite", &self.geosite.is_some())
            .finish()
    }
}

impl<'a> Clone for Engine<'a> {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg,
            geoip: self.geoip,
            geosite: self.geosite,
        }
    }
}

impl<'a> Engine<'a> {
    pub fn new(cfg: &'a ConfigIR) -> Self {
        Self {
            cfg,
            geoip: None,
            geosite: None,
        }
    }

    fn host_is_ip(host: &str) -> Option<IpAddr> {
        host.parse::<IpAddr>().ok()
    }

    fn match_list<T: AsRef<str>>(needle: &str, list: &[T]) -> bool {
        // domain: 末尾匹配；ip: 等值；其他直接等值
        for it in list {
            let v = it.as_ref();
            if v == "*" {
                return true;
            }
            if needle.eq_ignore_ascii_case(v) {
                return true;
            }
            if needle.ends_with(&format!(".{}", v)) {
                return true;
            }
        }
        false
    }

    fn match_port(port: u16, ports: &[String]) -> bool {
        for p in ports {
            if let Some((a, b)) = p.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>()) {
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    if port >= lo && port <= hi {
                        return true;
                    }
                }
            } else if let Ok(x) = p.parse::<u16>() {
                if port == x {
                    return true;
                }
            }
        }
        false
    }

    fn rule_canonical(r: &RuleIR) -> (String, Vec<String>) {
        let mut parts: Vec<(&str, String)> = Vec::new();
        let mut chain = Vec::<String>::new();
        macro_rules! pushv {
            ($k:literal,$v:expr,$prefix:literal) => {
                if !$v.is_empty() {
                    for x in $v.iter() {
                        parts.push(($k, x.clone()));
                        chain.push(format!("{}:{}", $prefix, x));
                    }
                }
            };
        }
        pushv!("domain", &r.domain, "domain");
        pushv!("geosite", &r.geosite, "geosite");
        pushv!("geoip", &r.geoip, "geoip");
        pushv!("ipcidr", &r.ipcidr, "cidr");
        pushv!("port", &r.port, "port");
        pushv!("network", &r.network, "net");
        pushv!("protocol", &r.protocol, "proto");
        let canon = canonicalize_rule_text(
            &parts
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect::<Vec<_>>(),
        );
        (canon, chain)
    }

    fn rule_matches(&self, inp: &Input, r: &RuleIR) -> (bool, Vec<Step>) {
        let mut steps = Vec::<Step>::new();
        let host = inp.host;
        let is_ip = Self::host_is_ip(host);

        // 正向维度
        if !r.domain.is_empty() {
            let m = is_ip.is_none() && Self::match_list(host, &r.domain);
            steps.push(Step {
                kind: "domain".into(),
                value: host.into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.ipcidr.is_empty() {
            // IP CIDR 匹配：使用实际的IP地址进行匹配
            let mut m = false;
            if let Some(ip) = is_ip {
                for c in &r.ipcidr {
                    // 简化的CIDR匹配：先检查IP地址前缀
                    if let Some(prefix_str) = c.split('/').next() {
                        if ip.to_string() == prefix_str {
                            m = true;
                            break;
                        }
                        // TODO: 实现真正的CIDR子网匹配，而不是简单的前缀字符串匹配
                        // 这里应该使用 ipnet crate 进行正确的网络匹配
                        if ip.to_string().starts_with(prefix_str) {
                            m = true;
                            break;
                        }
                    }
                }
            }
            steps.push(Step {
                kind: "cidr".into(),
                value: host.into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.port.is_empty() {
            let m = Self::match_port(inp.port, &r.port);
            steps.push(Step {
                kind: "port".into(),
                value: inp.port.to_string(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.network.is_empty() {
            let m = r
                .network
                .iter()
                .any(|x| x.eq_ignore_ascii_case(inp.network));
            steps.push(Step {
                kind: "network".into(),
                value: inp.network.into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.protocol.is_empty() {
            let m = r
                .protocol
                .iter()
                .any(|x| x.eq_ignore_ascii_case(inp.protocol));
            steps.push(Step {
                kind: "protocol".into(),
                value: inp.protocol.into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }

        // 否定维度
        if !r.not_domain.is_empty() && is_ip.is_none() {
            let m = Self::match_list(host, &r.not_domain);
            steps.push(Step {
                kind: "not_domain".into(),
                value: host.into(),
                matched: !m,
            });
            if m {
                return (false, steps);
            }
        }
        if !r.not_ipcidr.is_empty() {
            let mut n = false;
            if is_ip.is_some() {
                for c in &r.not_ipcidr {
                    if host == c.split('/').next().unwrap_or("") {
                        n = true;
                        break;
                    }
                }
            }
            steps.push(Step {
                kind: "not_cidr".into(),
                value: host.into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_port.is_empty() {
            let n = Self::match_port(inp.port, &r.not_port);
            steps.push(Step {
                kind: "not_port".into(),
                value: inp.port.to_string(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_network.is_empty() {
            let n = r
                .not_network
                .iter()
                .any(|x| x.eq_ignore_ascii_case(inp.network));
            steps.push(Step {
                kind: "not_network".into(),
                value: inp.network.into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_protocol.is_empty() {
            let n = r
                .not_protocol
                .iter()
                .any(|x| x.eq_ignore_ascii_case(inp.protocol));
            steps.push(Step {
                kind: "not_protocol".into(),
                value: inp.protocol.into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }

        (true, steps)
    }

    pub fn decide(&self, inp: &Input, want_trace: bool) -> Decide {
        for r in &self.cfg.route.rules {
            let (ok, steps) = self.rule_matches(inp, r);
            if ok {
                let (canon, chain) = Self::rule_canonical(r);
                let rid = sha8(&canon);
                let out = r.outbound.clone().unwrap_or_else(|| {
                    self.cfg
                        .route
                        .default
                        .clone()
                        .unwrap_or_else(|| "direct".into())
                });
                let trace = if want_trace {
                    Some(Trace {
                        steps,
                        canonical_rule: canon,
                        matched_rule: rid.clone(),
                    })
                } else {
                    None
                };
                return Decide {
                    outbound: out,
                    matched_rule: rid,
                    chain,
                    trace,
                };
            }
        }
        // no rule matched → default
        let out = self
            .cfg
            .route
            .default
            .clone()
            .unwrap_or_else(|| "direct".into());
        Decide {
            outbound: out,
            matched_rule: "00000000".into(),
            chain: vec![],
            trace: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{ConfigIR, RouteIR, RuleIR};

    #[test]
    fn domain_and_not_port() {
        let mut cfg = ConfigIR::default();
        cfg.route = RouteIR {
            rules: vec![RuleIR {
                domain: vec!["example.com".into()],
                not_port: vec!["25".into()],
                outbound: Some("direct".into()),
                ..Default::default()
            }],
            default: Some("direct".into()),
        };
        let eng = Engine::new(&cfg);
        let ok = eng.decide(
            &Input {
                host: "www.example.com",
                port: 443,
                network: "tcp",
                protocol: "socks",
            },
            false,
        );
        assert_eq!(ok.outbound, "direct");
        let skip = eng.decide(
            &Input {
                host: "example.com",
                port: 25,
                network: "tcp",
                protocol: "socks",
            },
            false,
        );
        assert_eq!(skip.matched_rule, "00000000"); // fallback default
    }
}
