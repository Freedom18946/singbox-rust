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

#[derive(Debug, Clone, Copy, Default)]
pub struct Input<'a> {
    pub host: &'a str, // domain or ip string (original target)
    pub port: u16,
    pub network: &'a str,  // "tcp"|"udp"
    pub protocol: &'a str, // "socks"|"http"|...
    /// Optional sniffed host overriding the original host for routing purposes
    pub sniff_host: Option<&'a str>,
    /// Optional sniffed ALPN (e.g., "h2", "http/1.1", "h3")
    pub sniff_alpn: Option<&'a str>,
    /// Optional sniffed protocol (e.g., "tls", "http", "ssh")
    pub sniff_protocol: Option<&'a str>,
    /// Optional WiFi SSID
    pub wifi_ssid: Option<&'a str>,
    /// Optional WiFi BSSID
    pub wifi_bssid: Option<&'a str>,
    /// Optional Process Name
    pub process_name: Option<&'a str>,
    /// Optional Process Path
    pub process_path: Option<&'a str>,
    /// Optional User Agent
    pub user_agent: Option<&'a str>,
    /// Optional Rule Set tags
    pub rule_set: Option<&'a [String]>,
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
        // All domain matching is case-insensitive
        let needle_lower = needle.to_ascii_lowercase();
        for it in list {
            let v = it.as_ref();
            if v == "*" {
                return true;
            }
            let v_lower = v.to_ascii_lowercase();
            if needle_lower == v_lower {
                return true;
            }
            if needle_lower.ends_with(&format!(".{}", v_lower)) {
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
        pushv!("alpn", &r.alpn, "alpn");
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
        let host = inp.sniff_host.unwrap_or(inp.host);
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
                    // 实现真正的CIDR子网匹配
                    if let Ok(network) = c.parse::<std::net::IpAddr>() {
                        // 处理单个IP地址（没有子网掩码）
                        if ip == network {
                            m = true;
                            break;
                        }
                    } else if let Some((network_str, prefix_len_str)) = c.split_once('/') {
                        // 处理CIDR格式（IP/prefix_length）
                        if let (Ok(network_ip), Ok(prefix_len)) = (
                            network_str.parse::<std::net::IpAddr>(),
                            prefix_len_str.parse::<u8>(),
                        ) {
                            if Self::ip_in_cidr(ip, network_ip, prefix_len) {
                                m = true;
                                break;
                            }
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
            let mut m = false;
            if let Some(sniffed) = inp.sniff_protocol {
                m = r.protocol.iter().any(|x| x.eq_ignore_ascii_case(sniffed));
            }
            if !m {
                m = r
                    .protocol
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(inp.protocol));
            }
            steps.push(Step {
                kind: "protocol".into(),
                value: inp.sniff_protocol.unwrap_or(inp.protocol).into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.alpn.is_empty() {
            let m = match inp.sniff_alpn {
                Some(a) => r.alpn.iter().any(|x| x.eq_ignore_ascii_case(a)),
                None => false, // requires sniffed alpn present
            };
            steps.push(Step {
                kind: "alpn".into(),
                value: inp.sniff_alpn.unwrap_or("").into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.wifi_ssid.is_empty() {
            let m = inp
                .wifi_ssid
                .map(|s| r.wifi_ssid.iter().any(|x| x == s))
                .unwrap_or(false);
            steps.push(Step {
                kind: "wifi_ssid".into(),
                value: inp.wifi_ssid.unwrap_or("").into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.wifi_bssid.is_empty() {
            let m = inp
                .wifi_bssid
                .map(|s| r.wifi_bssid.iter().any(|x| x.eq_ignore_ascii_case(s)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "wifi_bssid".into(),
                value: inp.wifi_bssid.unwrap_or("").into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.process_name.is_empty() {
            let m = inp
                .process_name
                .map(|s| r.process_name.iter().any(|x| x.eq_ignore_ascii_case(s)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "process_name".into(),
                value: inp.process_name.unwrap_or("").into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.process_path.is_empty() {
            let m = inp
                .process_path
                .map(|s| r.process_path.iter().any(|x| x.eq_ignore_ascii_case(s)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "process_path".into(),
                value: inp.process_path.unwrap_or("").into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
        }
        if !r.user_agent.is_empty() {
            let m = inp
                .user_agent
                .map(|s| r.user_agent.iter().any(|x| s.contains(x)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "user_agent".into(),
                value: inp.user_agent.unwrap_or("").into(),
                matched: m,
            });
            if !m {
                return (false, steps);
            }
            if !m {
                return (false, steps);
            }
        }
        if !r.rule_set.is_empty() {
            let m = inp
                .rule_set
                .map(|tags| r.rule_set.iter().any(|x| tags.contains(x)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "rule_set".into(),
                value: format!("{:?}", inp.rule_set.unwrap_or(&[])),
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
        if !r.not_alpn.is_empty() {
            let n = match inp.sniff_alpn {
                Some(a) => r.not_alpn.iter().any(|x| x.eq_ignore_ascii_case(a)),
                None => false, // if no alpn, cannot exclude by not_alpn
            };
            steps.push(Step {
                kind: "not_alpn".into(),
                value: inp.sniff_alpn.unwrap_or("").into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_wifi_ssid.is_empty() {
            let n = inp
                .wifi_ssid
                .map(|s| r.not_wifi_ssid.iter().any(|x| x == s))
                .unwrap_or(false);
            steps.push(Step {
                kind: "not_wifi_ssid".into(),
                value: inp.wifi_ssid.unwrap_or("").into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_wifi_bssid.is_empty() {
            let n = inp
                .wifi_bssid
                .map(|s| r.not_wifi_bssid.iter().any(|x| x.eq_ignore_ascii_case(s)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "not_wifi_bssid".into(),
                value: inp.wifi_bssid.unwrap_or("").into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_process_name.is_empty() {
            let n = inp
                .process_name
                .map(|s| r.not_process_name.iter().any(|x| x.eq_ignore_ascii_case(s)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "not_process".into(),
                value: inp.process_name.unwrap_or("").into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_user_agent.is_empty() {
            let n = inp
                .user_agent
                .map(|s| r.not_user_agent.iter().any(|x| s.contains(x)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "not_user_agent".into(),
                value: inp.user_agent.unwrap_or("").into(),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }
        if !r.not_rule_set.is_empty() {
            let n = inp
                .rule_set
                .map(|tags| r.not_rule_set.iter().any(|x| tags.contains(x)))
                .unwrap_or(false);
            steps.push(Step {
                kind: "not_rule_set".into(),
                value: format!("{:?}", inp.rule_set.unwrap_or(&[])),
                matched: !n,
            });
            if n {
                return (false, steps);
            }
        }

        (true, steps)
    }

    fn default_outbound(&self) -> String {
        self.cfg
            .route
            .default
            .clone()
            .or_else(|| self.cfg.route.final_outbound.clone())
            .unwrap_or_else(|| "direct".into())
    }

    pub fn decide(&self, inp: &Input, want_trace: bool) -> Decide {
        for r in &self.cfg.route.rules {
            let (ok, steps) = self.rule_matches(inp, r);
            if ok {
                let (canon, chain) = Self::rule_canonical(r);
                let rid = sha8(&canon);
                let out = r.outbound.clone().unwrap_or_else(|| self.default_outbound());
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
        let out = self.default_outbound();
        Decide {
            outbound: out,
            matched_rule: "00000000".into(),
            chain: vec![],
            trace: None,
        }
    }

    /// 检查IP地址是否在指定的CIDR子网内
    fn ip_in_cidr(ip: std::net::IpAddr, network_ip: std::net::IpAddr, prefix_len: u8) -> bool {
        use std::net::IpAddr;

        match (ip, network_ip) {
            (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
                if prefix_len > 32 {
                    return false;
                }
                if prefix_len == 0 {
                    return true; // 0.0.0.0/0 matches all IPv4
                }

                let ip_bits = u32::from(ip4);
                let net_bits = u32::from(net4);
                let mask = !((1u32 << (32 - prefix_len)) - 1);

                (ip_bits & mask) == (net_bits & mask)
            }
            (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
                if prefix_len > 128 {
                    return false;
                }
                if prefix_len == 0 {
                    return true; // ::/0 matches all IPv6
                }

                let ip_bits = u128::from(ip6);
                let net_bits = u128::from(net6);
                let mask = !((1u128 << (128 - prefix_len)) - 1);

                (ip_bits & mask) == (net_bits & mask)
            }
            // IPv4与IPv6之间不匹配
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{ConfigIR, RouteIR, RuleIR};

    #[test]
    fn domain_and_not_port() {
        let cfg = ConfigIR {
            route: RouteIR {
                rules: vec![RuleIR {
                    domain: vec!["example.com".into()],
                    not_port: vec!["25".into()],
                    outbound: Some("direct".into()),
                    ..Default::default()
                }],
                default: Some("direct".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let eng = Engine::new(&cfg);
        let ok = eng.decide(
            &Input {
                host: "www.example.com",
                port: 443,
                network: "tcp",
                protocol: "socks",
                sniff_host: None,
                sniff_alpn: None,
                sniff_protocol: None,
                wifi_ssid: None,
                wifi_bssid: None,
                process_name: None,
                process_path: None,
                user_agent: None,
                rule_set: None,
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
                sniff_host: None,
                sniff_alpn: None,
                sniff_protocol: None,
                wifi_ssid: None,
                wifi_bssid: None,
                process_name: None,
                process_path: None,
                user_agent: None,
                rule_set: None,
            },
            false,
        );
        assert_eq!(skip.matched_rule, "00000000"); // fallback default
    }

    #[test]
    fn matches_on_sniffed_protocol() {
        let cfg = ConfigIR {
            route: RouteIR {
                rules: vec![RuleIR {
                    protocol: vec!["bittorrent".into()],
                    outbound: Some("block".into()),
                    ..Default::default()
                }],
                default: Some("direct".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let eng = Engine::new(&cfg);
        let decision = eng.decide(
            &Input {
                host: "example.com",
                port: 6881,
                network: "tcp",
                protocol: "socks",
                sniff_host: None,
                sniff_alpn: None,
                sniff_protocol: Some("bittorrent"),
                wifi_ssid: None,
                wifi_bssid: None,
                process_name: None,
                process_path: None,
                user_agent: None,
                rule_set: None,
            },
            false,
        );
        assert_eq!(decision.outbound, "block");
    }

    #[test]
    fn falls_back_to_base_protocol_when_sniff_differs() {
        let cfg = ConfigIR {
            route: RouteIR {
                rules: vec![RuleIR {
                    protocol: vec!["socks".into()],
                    outbound: Some("direct".into()),
                    ..Default::default()
                }],
                default: Some("block".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let eng = Engine::new(&cfg);
        let decision = eng.decide(
            &Input {
                host: "example.com",
                port: 443,
                network: "tcp",
                protocol: "socks",
                sniff_host: None,
                sniff_alpn: None,
                sniff_protocol: Some("tls"),
                wifi_ssid: None,
                wifi_bssid: None,
                process_name: None,
                process_path: None,
                user_agent: None,
                rule_set: None,
            },
            false,
        );
        assert_eq!(decision.outbound, "direct");
    }
}
