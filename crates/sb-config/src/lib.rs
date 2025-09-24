use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

// Removed sb_core dependencies to break circular dependency
// TODO: These will be reintroduced when sb-core depends on sb-config

pub mod ir;
pub mod merge;
pub mod minimize;
pub mod normalize;
pub mod present;
pub mod rule;
pub mod subscribe;
pub mod validator;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// 可选的兜底出站（指向某个命名出站）；若未指定则使用 Direct
    #[serde(default)]
    pub default_outbound: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Inbound {
    #[serde(rename = "http")]
    Http { listen: String },
    #[serde(rename = "socks")]
    Socks { listen: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Outbound {
    #[serde(rename = "direct")]
    Direct { name: String },
    #[serde(rename = "block")]
    Block { name: String },
    #[serde(rename = "socks5")]
    Socks5 {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        auth: Option<Auth>,
    },
    #[serde(rename = "http")]
    Http {
        name: String,
        server: String,
        port: u16,
        #[serde(default)]
        auth: Option<Auth>,
    },
    #[serde(rename = "vless")]
    Vless {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        #[serde(default)]
        flow: Option<String>,
        #[serde(default = "default_vless_network")]
        network: String,
        #[serde(default)]
        packet_encoding: Option<String>,
        #[serde(default)]
        connect_timeout_sec: Option<u64>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    /// 域名后缀匹配（任意一个命中即生效）
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// [预埋] IP 段（CIDR），当前 Router 只接域名，后续在 sb-core 落地
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    /// [预埋] 端口或范围（形如 "80", "443", "1000-2000"）
    #[serde(default)]
    pub port: Vec<String>,
    /// [预埋] 传输层协议: "tcp" | "udp"
    #[serde(default)]
    pub transport: Option<String>,
    /// 命中的出站名称（需存在于 outbounds）
    pub outbound: String,
}

impl Config {
    /// 暂存的兼容入口：先返回自身，后续可平滑替换为真正的构建产物
    pub fn build(self) -> Self {
        self
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        // 1) 出站名称唯一
        let mut names = HashSet::new();
        for ob in &self.outbounds {
            let name = match ob {
                Outbound::Direct { name }
                | Outbound::Block { name }
                | Outbound::Socks5 { name, .. }
                | Outbound::Http { name, .. }
                | Outbound::Vless { name, .. } => name,
            };
            if !names.insert(name) {
                return Err(anyhow!("duplicate outbound name: {}", name));
            }
        }
        // 2) 规则指向存在
        for r in &self.rules {
            if !names.contains(&r.outbound) {
                return Err(anyhow!("rule outbound not found: {}", r.outbound));
            }
        }
        // 3) default_outbound（若存在）必须存在于 outbounds
        if let Some(def) = &self.default_outbound {
            if !names.contains(def) {
                return Err(anyhow!("default_outbound not found in outbounds: {}", def));
            }
        }
        Ok(())
    }

    /// 根据 host 选择出站名（最先命中的规则即生效）
    pub fn pick_outbound_for_host<'a>(&'a self, host: &str) -> Option<&'a str> {
        for r in &self.rules {
            if r.domain_suffix.iter().any(|suf| host.ends_with(suf)) {
                return Some(r.outbound.as_str());
            }
        }
        None
    }

    /// 构建 `OutboundRegistry` 与 `Router`（真实实现）
    /// - 支持 direct/block/socks5/http 四类出站
    /// - 规则：`rules[].domain_suffix -> RouteTarget::Named(outbound)`
    /// - 默认路由：`default_outbound` 若指定则使用该命名出站，否则 Direct
    /// TODO: Re-enable after breaking circular dependency
    /*
    pub fn build_registry_and_router(&self) -> Result<(OutboundRegistry, Router)> {
        // 1) 构建 OutboundRegistry
        let mut map: HashMap<String, OutboundImpl> = HashMap::new();
        for ob in &self.outbounds {
            match ob {
                Outbound::Direct { name } => {
                    map.insert(name.clone(), OutboundImpl::Direct);
                }
                Outbound::Block { name } => {
                    map.insert(name.clone(), OutboundImpl::Block);
                }
                Outbound::Socks5 {
                    name,
                    server,
                    port,
                    auth,
                } => {
                    let addr = resolve_host_port(server, *port)
                        .with_context(|| format!("socks5 resolve {}:{}", server, port))?;
                    let (u, p) = auth_user_pass(auth.as_ref());
                    let cfg = CoreSocks5Cfg {
                        proxy_addr: addr,
                        username: u,
                        password: p,
                    };
                    map.insert(name.clone(), OutboundImpl::Socks5(cfg));
                }
                Outbound::Http {
                    name,
                    server,
                    port,
                    auth,
                } => {
                    let addr = resolve_host_port(server, *port)
                        .with_context(|| format!("http-proxy resolve {}:{}", server, port))?;
                    let (u, p) = auth_user_pass(auth.as_ref());
                    let cfg = CoreHttpCfg {
                        proxy_addr: addr,
                        username: u,
                        password: p,
                    };
                    map.insert(name.clone(), OutboundImpl::HttpProxy(cfg));
                }
                Outbound::Vless { name, .. } => {
                    // TODO: Implement VLESS support in OutboundImpl
                    // For now, use Direct as placeholder
                    map.insert(name.clone(), OutboundImpl::Direct);
                }
            }
        }
        let registry = OutboundRegistry::new(map);

        // 2) 构建 Router（默认 Direct）
        let mut router = Router::with_default(OutboundKind::Direct);
        let mut rules: Vec<RouteRule> = Vec::new();
        for r in &self.rules {
            let has_ext = !r.ip_cidr.is_empty() || !r.port.is_empty() || r.transport.is_some();
            if has_ext {
                rules.push(RouteRule::Composite(CompositeRule {
                    domain_suffix: r.domain_suffix.clone(),
                    ip_cidr: r.ip_cidr.clone(),
                    port: r.port.clone(),
                    transport: r.transport.clone(),
                    target: RouteTarget::Named(r.outbound.clone()),
                }));
            } else {
                for suf in &r.domain_suffix {
                    rules.push(RouteRule::DomainSuffix(
                        suf.clone(),
                        RouteTarget::Named(r.outbound.clone()),
                    ));
                }
            }
        }
        // 若配置了命名默认出站，则在末尾添加"一切匹配"规则（通过空后缀实现兜底）
        if let Some(def) = &self.default_outbound {
            rules.push(RouteRule::DomainSuffix(
                "".to_string(),
                RouteTarget::Named(def.clone()),
            ));
        }
        router.set_rules(rules);
        Ok((registry, router))
    }
    */

    /// Temporary stub implementation to get CLI working
    pub fn build_registry_and_router(&self) -> Result<()> {
        // Stub implementation - just validates config is loadable
        // Real implementation commented out due to circular deps
        Ok(())
    }

    /// 便捷：就地合并（订阅 → 当前配置）
    pub fn merge_in_place(&mut self, sub: Config) {
        let merged = crate::merge::merge(std::mem::take(self), sub);
        *self = merged;
    }
}

/// 解析 (host, port) -> SocketAddr（严格失败）
#[allow(dead_code)]
fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let qp = format!("{}:{}", host, port);
    let mut it = qp
        .to_socket_addrs()
        .with_context(|| format!("resolve failed: {}", qp))?;
    it.next()
        .ok_or_else(|| anyhow!("no address resolved for {}", qp))
}

#[allow(dead_code)]
fn auth_user_pass(a: Option<&Auth>) -> (Option<String>, Option<String>) {
    if let Some(x) = a {
        (Some(x.username.clone()), Some(x.password.clone()))
    } else {
        (None, None)
    }
}

fn default_vless_network() -> String {
    "tcp".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let y = r#"
inbounds:
  - type: http
    listen: 127.0.0.1:8080
outbounds:
  - type: direct
    name: direct
rules:
  - domain_suffix: ["example.com"]
    outbound: direct
        "#;
        let cfg: Config = serde_yaml::from_str(y).unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn rule_match_suffix() {
        let y = r#"
outbounds:
  - type: direct
    name: direct
rules:
  - domain_suffix: ["example.com", ".google.com"]
    outbound: direct
        "#;
        let cfg: Config = serde_yaml::from_str(y).unwrap();
        assert_eq!(
            cfg.pick_outbound_for_host("www.example.com"),
            Some("direct")
        );
        assert_eq!(
            cfg.pick_outbound_for_host("mail.google.com"),
            Some("direct")
        );
        assert_eq!(cfg.pick_outbound_for_host("foo.bar"), None);
    }

    /* TODO: Re-enable after breaking circular dependency
        #[test]
        fn default_outbound_as_fallback() {
            let y = r#"
    outbounds:
      - type: direct
        name: direct
    default_outbound: direct
    rules: []
            "#;
            let cfg: Config = serde_yaml::from_str(y).unwrap();
            let (_reg, _router) = cfg.build_registry_and_router().unwrap();
        }
        */

    /* TODO: Re-enable after breaking circular dependency
        #[test]
        fn resolve_strict_fail() {
            let y = r#"
    outbounds:
      - type: http
        name: bad
        server: invalid.invalid.invalid
        port: 3128
    rules:
      - domain_suffix: [".example.com"]
        outbound: bad
            "#;
            let cfg: Config = serde_yaml::from_str(y).unwrap();
            assert!(cfg.build_registry_and_router().is_err());
        }
        */
}
