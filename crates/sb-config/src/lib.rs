//! Configuration parsing and validation for SingBox
//! SingBox 的配置解析和校验
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This crate acts as the **Configuration Engine** for the application.
//! 本 crate 充当应用程序的 **配置引擎**。
//!
//! ## Strategic Workflow / 战略工作流
//! `Raw Text (JSON/YAML)` -> `Parse` -> `Migrate (V1->V2)` -> `Validate (Schema)` -> `Intermediate Representation (IR)`
//! `原始文本 (JSON/YAML)` -> `解析` -> `迁移 (V1->V2)` -> `校验 (模式)` -> `中间表示 (IR)`
//!
//! ## Strategic Features / 战略特性
//! - **Multi-Format / 多格式**: Supports both JSON (machine-friendly) and YAML (human-friendly).
//!   支持 JSON（机器友好）和 YAML（人类友好）。
//! - **Automatic Migration / 自动迁移**: Seamlessly upgrades legacy V1 configs to the V2 schema, ensuring backward compatibility without user intervention.
//!   无缝将旧版 V1 配置升级到 V2 模式，确保无需用户干预的向后兼容性。
//! - **Strong Validation / 强校验**: Uses a rigorous schema to catch errors early, preventing runtime failures due to misconfiguration.
//!   使用严格的模式尽早捕获错误，防止因配置错误导致的运行时故障。
//!
//! ## Key Modules / 关键模块
//! - [`ir`]: **Intermediate Representation** - The strongly-typed, canonical form of configuration used internally.
//!   **中间表示** - 内部使用的强类型、规范化配置形式。
//! - [`validator`]: **Validation Logic** - Enforces schema constraints and business rules.
//!   **校验逻辑** - 强制执行模式约束和业务规则。
//! - [`compat`]: **Migration Layer** - Handles the transformation from legacy formats.
//!   **迁移层** - 处理从旧格式的转换。

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
// use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

// Removed sb_core dependencies to break circular dependency
// TODO: These will be reintroduced when sb-core depends on sb-config

pub mod compat;
pub mod de;
pub mod defaults;
pub mod inbound;
pub mod ir;
pub mod merge;
pub mod minimize;
pub mod model;
pub mod normalize;
pub mod outbound;
pub mod present;
pub mod rule;
pub mod schema_v2;
pub mod subscribe;
pub mod validator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Schema version (2 by default)
    /// 模式版本（默认为 2）
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Inbound list.
    /// 入站列表。
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    /// Outbound list.
    /// 出站列表。
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    /// Routing rules.
    /// 路由规则。
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Optional default outbound (points to a named outbound); uses Direct if unspecified.
    /// 可选的兜底出站（指向某个命名出站）；若未指定则使用 Direct。
    #[serde(default)]
    pub default_outbound: Option<String>,
    /// Raw JSON value (preserved for partial parsing/debugging).
    /// 原始 JSON 值（保留用于部分解析/调试）。
    #[serde(skip)]
    raw: Value,
    /// Intermediate Representation (IR) of the config.
    /// 配置的中间表示 (IR)。
    #[serde(skip)]
    ir: crate::ir::ConfigIR,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            rules: Vec::new(),
            default_outbound: None,
            raw: Value::Null,
            ir: crate::ir::ConfigIR::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
/// Minimal inbound definition for legacy support.
/// 用于旧版支持的最小入站定义。
pub enum Inbound {
    #[serde(rename = "http")]
    Http { listen: String },
    #[serde(rename = "socks")]
    Socks { listen: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
/// Minimal outbound definition for legacy support.
/// 用于旧版支持的最小出站定义。
pub enum Outbound {
    #[serde(rename = "direct")]
    Direct { name: String },
    #[serde(rename = "block")]
    Block { name: String },
    #[serde(rename = "socks5", alias = "socks")]
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
        // Transport nesting and options (optional)
        #[serde(default)]
        transport: Option<Vec<String>>,
        #[serde(default)]
        ws_path: Option<String>,
        #[serde(default)]
        ws_host: Option<String>,
        #[serde(default)]
        h2_path: Option<String>,
        #[serde(default)]
        h2_host: Option<String>,
        #[serde(default)]
        tls_sni: Option<String>,
        #[serde(default)]
        tls_alpn: Option<String>,
    },
    #[serde(rename = "trojan")]
    Trojan {
        name: String,
        server: String,
        port: u16,
        password: String,
        #[serde(default)]
        transport: Option<Vec<String>>,
        #[serde(default)]
        ws_path: Option<String>,
        #[serde(default)]
        ws_host: Option<String>,
        #[serde(default)]
        h2_path: Option<String>,
        #[serde(default)]
        h2_host: Option<String>,
        #[serde(default)]
        tls_sni: Option<String>,
        #[serde(default)]
        tls_alpn: Option<String>,
    },
    #[serde(rename = "vmess")]
    Vmess {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        #[serde(default = "default_vmess_security")]
        security: String,
        #[serde(default)]
        alter_id: u16,
        #[serde(default)]
        connect_timeout_sec: Option<u64>,
        // Transport nesting and options (optional)
        #[serde(default)]
        transport: Option<Vec<String>>,
        #[serde(default)]
        ws_path: Option<String>,
        #[serde(default)]
        ws_host: Option<String>,
        #[serde(default)]
        h2_path: Option<String>,
        #[serde(default)]
        h2_host: Option<String>,
        #[serde(default)]
        tls_sni: Option<String>,
        #[serde(default)]
        tls_alpn: Option<String>,
    },
    #[serde(rename = "tuic")]
    Tuic {
        name: String,
        server: String,
        port: u16,
        uuid: String,
        token: String,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        congestion_control: Option<String>,
        #[serde(default)]
        alpn: Option<String>,
        #[serde(default)]
        skip_cert_verify: Option<bool>,
        #[serde(default)]
        udp_relay_mode: Option<String>,
        #[serde(default)]
        udp_over_stream: Option<bool>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Auth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Rule {
    /// 域名后缀匹配（任意一个命中即生效）
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// \[预埋\] IP 段（CIDR），当前 Router 只接域名，后续在 sb-core 落地
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    /// \[预埋\] 端口或范围（形如 "80", "443", "1000-2000"）
    #[serde(default)]
    pub port: Vec<String>,
    /// \[预埋\] 传输层协议: "tcp" | "udp"
    #[serde(default)]
    pub transport: Option<String>,
    /// 命中的出站名称（需存在于 outbounds）
    pub outbound: String,
}

fn rule_from_ir(ir_rule: &crate::ir::RuleIR) -> Option<Rule> {
    let outbound = ir_rule.outbound.clone()?;
    Some(Rule {
        domain_suffix: ir_rule.domain.clone(),
        ip_cidr: ir_rule.ipcidr.clone(),
        port: ir_rule.port.clone(),
        transport: ir_rule.network.first().cloned(),
        outbound,
    })
}

impl Config {
    pub(crate) fn from_value(doc: Value) -> Result<Self> {
        let mut cfg: Config = serde_json::from_value(doc.clone()).unwrap_or_default();
        cfg.raw = doc;
        cfg.ir = crate::validator::v2::to_ir_v1(&cfg.raw);
        if cfg.raw.get("route").is_some() && !cfg.ir.route.rules.is_empty() {
            cfg.rules = cfg.ir.route.rules.iter().filter_map(rule_from_ir).collect();
        }
        if cfg.default_outbound.is_none() && cfg.ir.route.default.is_some() {
            cfg.default_outbound = cfg.ir.route.default.clone();
        }
        Ok(cfg)
    }

    pub fn raw(&self) -> &Value {
        &self.raw
    }

    pub fn ir(&self) -> &crate::ir::ConfigIR {
        &self.ir
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.ir.inbounds.len(),
            self.ir.outbounds.len(),
            self.ir.route.rules.len(),
        )
    }

    /// Legacy helper: project IR inbounds into minimal HTTP/SOCKS entries.
    pub fn legacy_inbounds(&self) -> Vec<Inbound> {
        use crate::ir::InboundType;
        self.ir
            .inbounds
            .iter()
            .filter_map(|ib| match ib.ty {
                InboundType::Http => Some(Inbound::Http {
                    listen: format!("{}:{}", ib.listen, ib.port),
                }),
                InboundType::Socks => Some(Inbound::Socks {
                    listen: format!("{}:{}", ib.listen, ib.port),
                }),
                _ => None,
            })
            .collect()
    }

    /// 暂存的兼容入口：先返回自身，后续可平滑替换为真正的构建产物
    pub fn build(self) -> Self {
        self
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let raw: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => serde_yaml::from_str(&text)?,
        };
        let migrated = compat::migrate_to_v2(&raw);
        let cfg = Self::from_value(migrated)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        use crate::ir::OutboundType;
        // 1) 出站名称唯一
        let mut names = HashSet::new();
        for ob in &self.ir.outbounds {
            if let Some(name) = &ob.name {
                if !names.insert(name.clone()) {
                    return Err(anyhow!("duplicate outbound name: {}", name));
                }
            }
        }
        // 2) Selector/URLTest 成员必须指向已存在的出站
        for ob in &self.ir.outbounds {
            if matches!(ob.ty, OutboundType::Selector | OutboundType::UrlTest) {
                if let Some(members) = &ob.members {
                    for member in members {
                        if !names.contains(member) {
                            return Err(anyhow!(
                                "outbound '{}': member '{}' not found",
                                ob.name.as_deref().unwrap_or("unnamed"),
                                member
                            ));
                        }
                    }
                }
            }
        }
        // 2) 规则指向存在
        for r in &self.ir.route.rules {
            if let Some(outbound) = &r.outbound {
                if !names.contains(outbound) {
                    return Err(anyhow!("rule outbound not found: {}", outbound));
                }
            }
        }
        // 3) default_outbound（若存在）必须存在于 outbounds
        if let Some(def) = &self.ir.route.default {
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

    // 构建 `OutboundRegistry` 与 `Router`（真实实现）
    // - 支持 direct/block/socks5/http 四类出站
    // - 规则：`rules[].domain_suffix -> RouteTarget::Named(outbound)`
    // - 默认路由：`default_outbound` 若指定则使用该命名出站，否则 Direct
    // TODO: Re-enable after breaking circular dependency
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
                    // VLESS configuration should be handled in sb-core to avoid circular dependency
                    // For now, return error indicating VLESS needs to be processed by sb-core
                    return Err(anyhow::anyhow!("VLESS outbound '{}' requires runtime processing in sb-core", name));
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

    /// Build-time validation + IR 编译（不引入 sb-core 以避免环依赖）
    ///
    /// 作用：
    /// - 复用现有 validate 进行强校验
    /// - 将 Config 转换为 IR（ConfigIR/RouteIR/RuleIR），保证规则可被路由层消费
    /// - 为上层提供"构建已通过"的语义（此处不返回具体路由器实例）
    pub fn build_registry_and_router(&self) -> Result<()> {
        // Delegate to present::to_ir for complete conversion (including inbounds)
        // This eliminates code duplication and ensures all fields are properly converted
        let _cfg_ir = crate::present::to_ir(self)?;
        // Discard IR (actual consumption happens in sb-core), validation passed
        Ok(())
    }

    /// 便捷：就地合并（订阅 → 当前配置）
    pub fn merge_in_place(&mut self, sub: Config) {
        let merged_raw = merge_raw(&self.raw, &sub.raw);
        match Config::from_value(merged_raw) {
            Ok(cfg) => {
                *self = cfg;
            }
            Err(e) => {
                let merged = crate::merge::merge(std::mem::take(self), sub);
                *self = merged;
                let _ = e;
                self.raw =
                    compat::migrate_to_v2(&serde_json::to_value(&*self).unwrap_or(Value::Null));
                self.ir = crate::validator::v2::to_ir_v1(&self.raw);
            }
        }
    }
}

/*
fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let qp = format!("{}:{}", host, port);
    let mut it = qp
        .to_socket_addrs()
        .with_context(|| format!("resolve failed: {}", qp))?;
    it.next()
        .ok_or_else(|| anyhow!("no address resolved for {}", qp))
}
*/

pub(crate) fn merge_raw(base: &Value, sub: &Value) -> Value {
    use serde_json::Map;

    let mut merged: Map<String, Value> = base.as_object().cloned().unwrap_or_else(Map::new);

    if let Some(sub_obj) = sub.as_object() {
        if let Some(outbounds) = sub_obj.get("outbounds") {
            merged.insert("outbounds".to_string(), outbounds.clone());
        }
        if let Some(route) = sub_obj.get("route") {
            merged.insert("route".to_string(), route.clone());
        }
        if let Some(default_outbound) = sub_obj.get("default_outbound") {
            merged.insert("default_outbound".to_string(), default_outbound.clone());
        }
        for (k, v) in sub_obj {
            if matches!(
                k.as_str(),
                "outbounds" | "route" | "inbounds" | "schema_version" | "default_outbound"
            ) {
                continue;
            }
            merged.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    if !merged.contains_key("inbounds") {
        if let Some(inbounds) = sub.get("inbounds") {
            merged.insert("inbounds".to_string(), inbounds.clone());
        }
    }

    merged.insert("schema_version".to_string(), Value::from(2));
    Value::Object(merged)
}

/*
fn auth_user_pass(a: Option<&Auth>) -> (Option<String>, Option<String>) {
    if let Some(x) = a {
        (Some(x.username.clone()), Some(x.password.clone()))
    } else {
        (None, None)
    }
}
*/

fn default_vless_network() -> String {
    "tcp".to_string()
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

fn default_schema_version() -> u32 {
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() -> anyhow::Result<()> {
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
        let cfg: Config = serde_yaml::from_str(y)?;
        cfg.validate()?;
        Ok(())
    }

    #[test]
    fn rule_match_suffix() -> anyhow::Result<()> {
        let y = r#"
outbounds:
  - type: direct
    name: direct
rules:
  - domain_suffix: ["example.com", ".google.com"]
    outbound: direct
        "#;
        let cfg: Config = serde_yaml::from_str(y)?;
        assert_eq!(
            cfg.pick_outbound_for_host("www.example.com"),
            Some("direct")
        );
        assert_eq!(
            cfg.pick_outbound_for_host("mail.google.com"),
            Some("direct")
        );
        assert_eq!(cfg.pick_outbound_for_host("foo.bar"), None);
        Ok(())
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
