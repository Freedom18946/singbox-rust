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

// sb-config stays independent of sb-core; runtime wiring lives in sb-core.

pub mod compat;
pub mod de;
pub mod defaults;
pub mod inbound;
pub mod ir;
pub mod json_norm;
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
    /// 规则动作 (默认 Route)
    #[serde(default)]
    pub action: crate::ir::RuleAction,
    /// 劫持动作的目标地址 override
    #[serde(default)]
    pub override_address: Option<String>,
    /// 劫持动作的目标端口 override
    #[serde(default)]
    pub override_port: Option<u16>,
    /// 命中的出站名称（需存在于 outbounds），对于 Route 动作通常必需
    #[serde(default)]
    pub outbound: Option<String>,
}

fn rule_from_ir(ir_rule: &crate::ir::RuleIR) -> Option<Rule> {
    // If action is Route, we typically expect an outbound, but we can allow empty (fallback to default)
    // or let runtime handle it.
    let outbound = ir_rule.outbound.clone();
    Some(Rule {
        // Bug fix: use domain_suffix from IR, not domain (PX-003)
        domain_suffix: ir_rule.domain_suffix.clone(),
        ip_cidr: ir_rule.ipcidr.clone(),
        port: ir_rule.port.clone(),
        transport: ir_rule.network.first().cloned(),
        action: ir_rule.action.clone(),
        override_address: ir_rule.override_address.clone(),
        override_port: ir_rule.override_port,
        outbound,
    })
}

fn rule_from_route_value(rule: &Value) -> Option<Rule> {
    let obj = rule.as_object()?;
    let outbound = obj
        .get("outbound")
        .or_else(|| obj.get("to"))
        .and_then(|v| v.as_str())?;
    let outbound = Some(outbound.to_string());
    let mut domain_suffix = Vec::new();
    let mut ip_cidr = Vec::new();
    let mut port = Vec::new();
    let mut transport = None;

    collect_strings(obj.get("domain_suffix"), &mut domain_suffix);
    collect_strings(obj.get("ip_cidr"), &mut ip_cidr);
    collect_strings(obj.get("ipcidr"), &mut ip_cidr);
    collect_strings(obj.get("port"), &mut port);
    transport = first_string(obj.get("network")).or(transport);

    if let Some(when) = obj.get("when").and_then(|v| v.as_object()) {
        collect_strings(when.get("suffix"), &mut domain_suffix);
        collect_strings(when.get("domain_suffix"), &mut domain_suffix);
        collect_strings(when.get("ip_cidr"), &mut ip_cidr);
        collect_strings(when.get("ipcidr"), &mut ip_cidr);
        collect_strings(when.get("port"), &mut port);
        if transport.is_none() {
            transport = first_string(when.get("network"));
        }
    }

    Some(Rule {
        domain_suffix,
        ip_cidr,
        port,
        transport,
        action: crate::ir::RuleAction::Route,
        override_address: None,
        override_port: None,
        outbound,
    })
}

fn collect_strings(value: Option<&Value>, out: &mut Vec<String>) {
    let Some(value) = value else {
        return;
    };
    match value {
        Value::Array(items) => {
            for item in items {
                collect_strings(Some(item), out);
            }
        }
        Value::String(s) => {
            let s = s.trim();
            if !s.is_empty() {
                out.push(s.to_string());
            }
        }
        Value::Number(n) => out.push(n.to_string()),
        _ => {}
    }
}

fn first_string(value: Option<&Value>) -> Option<String> {
    let value = value?;
    match value {
        Value::String(s) => Some(s.to_string()),
        Value::Array(items) => items
            .iter()
            .find_map(|item| item.as_str().map(|s| s.to_string())),
        _ => None,
    }
}

impl Config {
    pub fn from_value(doc: Value) -> Result<Self> {
        let mut cfg: Config = serde_json::from_value(doc.clone()).unwrap_or_default();
        cfg.raw = doc;
        cfg.ir = crate::validator::v2::to_ir_v1(&cfg.raw);
        if cfg.raw.get("route").is_some() && !cfg.ir.route.rules.is_empty() {
            cfg.rules = cfg.ir.route.rules.iter().filter_map(rule_from_ir).collect();
        }
        if cfg.rules.is_empty() {
            if let Some(rules) = cfg
                .raw
                .get("route")
                .and_then(|route| route.get("rules"))
                .and_then(|v| v.as_array())
            {
                cfg.rules = rules.iter().filter_map(rule_from_route_value).collect();
            }
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

        // Go parity: strict validation - unknown fields are errors (DisallowUnknownFields)
        let issues = crate::validator::v2::validate_v2(&migrated, false);
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.get("kind").and_then(|k| k.as_str()) == Some("error"))
            .collect();
        if !errors.is_empty() {
            let first = &errors[0];
            let ptr = first
                .get("ptr")
                .and_then(|p| p.as_str())
                .unwrap_or("/");
            let msg = first
                .get("msg")
                .and_then(|m| m.as_str())
                .unwrap_or("validation error");
            return Err(anyhow!("config validation failed at {}: {}", ptr, msg));
        }

        let cfg = Self::from_value(migrated)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        use crate::ir::OutboundType;
        let mut names = HashSet::new();

        // Go parity: validate inbound tags are unique and don't conflict with outbound names
        for ib in &self.ir.inbounds {
            if let Some(tag) = &ib.tag {
                if !tag.is_empty() && !names.insert(tag.clone()) {
                    return Err(anyhow!("duplicate inbound/outbound tag: {}", tag));
                }
            }
        }

        // 1) 出站名称唯一 (and must not conflict with inbound tags)
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
        // 3) 规则指向存在
        for r in &self.ir.route.rules {
            if let Some(outbound) = &r.outbound {
                if !names.contains(outbound) {
                    return Err(anyhow!("rule outbound not found: {}", outbound));
                }
            }
        }
        // 4) default_outbound（若存在）必须存在于 outbounds
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
                return r.outbound.as_deref();
            }
        }
        None
    }

    /// Build-time validation + IR 编译（不引入 sb-core 以避免环依赖）
    ///
    /// 作用：
    /// - 复用现有 validate 进行强校验
    /// - 将 Config 转换为 IR（ConfigIR/RouteIR/RuleIR），保证规则可被路由层消费
    /// - 为上层提供"构建已通过"的语义（此处不返回具体路由器实例）
    pub fn build_registry_and_router(&self) -> Result<()> {
        self.validate()?;
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

/// Parse a raw JSON Value into Config and ConfigIR with full migration and validation.
///
/// This helper consolidates the complete parsing pipeline:
/// 1. migrate_to_v2 - Migrate from v1 to v2 schema
/// 2. validate_v2 - Strict schema validation (Go parity)
/// 3. Config::from_value - Parse into Config struct
/// 4. cfg.validate() - Semantic validation
/// 5. present::to_ir - Convert to ConfigIR
///
/// # Errors
/// Returns an error if any step fails, with descriptive message including
/// validation pointer and message where applicable.
pub fn config_from_raw_value(raw: Value) -> Result<(Config, ir::ConfigIR)> {
    let migrated = compat::migrate_to_v2(&raw);

    // Strict validation (Go parity)
    let issues = crate::validator::v2::validate_v2(&migrated, false);
    let errors: Vec<_> = issues
        .iter()
        .filter(|i| i.get("kind").and_then(|k| k.as_str()) == Some("error"))
        .collect();
    if !errors.is_empty() {
        let first = &errors[0];
        let ptr = first.get("ptr").and_then(|p| p.as_str()).unwrap_or("/");
        let msg = first.get("msg").and_then(|m| m.as_str()).unwrap_or("validation error");
        return Err(anyhow!("schema validation failed at {}: {}", ptr, msg));
    }

    let cfg = Config::from_value(migrated)?;
    cfg.validate()?;
    let ir = crate::present::to_ir(&cfg)?;
    Ok((cfg, ir))
}


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

    #[test]
    fn default_outbound_as_fallback() {
        let y = r#"
outbounds:
  - type: direct
    name: direct
route:
  default: direct
  rules: []
        "#;
        let raw: Value = serde_yaml::from_str(y).unwrap();
        let cfg = Config::from_value(raw).unwrap();
        cfg.build_registry_and_router().unwrap();
    }

    #[test]
    fn rule_outbound_missing_fails() {
        let y = r#"
outbounds:
  - type: direct
    name: direct
route:
  rules:
    - domain_suffix: [".example.com"]
      outbound: missing
        "#;
        let raw: Value = serde_yaml::from_str(y).unwrap();
        let cfg = Config::from_value(raw).unwrap();
        assert!(cfg.build_registry_and_router().is_err());
    }

    #[test]
    fn test_schema_field_allowed() {
        // $schema should not be flagged as unknown field (Go parity)
        let json = r#"{"$schema": "https://example.com/schema.json", "schema_version": 2}"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let issues = crate::validator::v2::validate_v2(&raw, false);
        // $schema should not be flagged as unknown
        assert!(
            issues.iter().all(|i| {
                let ptr = i.get("ptr").and_then(|p| p.as_str()).unwrap_or("");
                ptr != "/$schema"
            }),
            "$schema should be allowed"
        );
    }

    #[test]
    fn test_duplicate_inbound_tag_rejected() {
        let y = r#"
inbounds:
  - type: http
    tag: proxy
    listen: 127.0.0.1
    port: 8080
  - type: socks
    tag: proxy
    listen: 127.0.0.1
    port: 1080
outbounds:
  - type: direct
    name: direct
        "#;
        let raw: Value = serde_yaml::from_str(y).unwrap();
        let cfg = Config::from_value(raw).unwrap();
        let result = cfg.validate();
        assert!(result.is_err(), "duplicate inbound tags should be rejected");
        assert!(
            result.unwrap_err().to_string().contains("duplicate"),
            "error should mention 'duplicate'"
        );
    }

    #[test]
    fn test_inbound_outbound_tag_conflict_rejected() {
        let y = r#"
inbounds:
  - type: http
    tag: direct
    listen: 127.0.0.1
    port: 8080
outbounds:
  - type: direct
    name: direct
        "#;
        let raw: Value = serde_yaml::from_str(y).unwrap();
        let cfg = Config::from_value(raw).unwrap();
        let result = cfg.validate();
        assert!(
            result.is_err(),
            "inbound tag conflicting with outbound name should be rejected"
        );
    }

    #[test]
    fn test_log_disabled_output_parsed() {
        let json = r#"{"log": {"disabled": true, "output": "/var/log/singbox.log"}}"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let ir = crate::validator::v2::to_ir_v1(&raw);
        assert_eq!(ir.log.as_ref().and_then(|l| l.disabled), Some(true));
        assert_eq!(
            ir.log.as_ref().and_then(|l| l.output.clone()),
            Some("/var/log/singbox.log".to_string())
        );
    }

    #[test]
    fn test_inbound_tag_parsed() {
        let json = r#"{"inbounds": [{"type": "http", "tag": "my-proxy", "listen": "127.0.0.1", "port": 8080}]}"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let ir = crate::validator::v2::to_ir_v1(&raw);
        assert_eq!(ir.inbounds.len(), 1);
        assert_eq!(ir.inbounds[0].tag, Some("my-proxy".to_string()));
    }

    #[test]
    fn test_domain_suffix_mapping_from_ir() {
        // PX-003 bug fix: verify domain_suffix is correctly mapped, not domain
        let json = r#"{
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {
                "rules": [{
                    "domain_suffix": [".example.com", ".google.com"],
                    "domain": ["exact.com"],
                    "outbound": "direct"
                }]
            }
        }"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let cfg = Config::from_value(raw).unwrap();
        
        // The Rule struct's domain_suffix should come from IR's domain_suffix, not domain
        assert_eq!(cfg.rules.len(), 1);
        assert!(cfg.rules[0].domain_suffix.contains(&".example.com".to_string()));
        assert!(cfg.rules[0].domain_suffix.contains(&".google.com".to_string()));
        // domain_suffix should NOT contain "exact.com" (that's from domain field)
        assert!(!cfg.rules[0].domain_suffix.contains(&"exact.com".to_string()));
    }

    #[test]
    fn test_rule_action_reject_parsed() {
        let json = r#"{
            "route": {
                "rules": [
                    {
                        "domain": ["reject.com"],
                        "action": "reject"
                    },
                    {
                        "domain": ["drop.com"],
                        "action": "reject-drop"
                    }
                ]
            }
        }"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let ir = crate::validator::v2::to_ir_v1(&raw);
        assert_eq!(ir.route.rules.len(), 2);
        assert_eq!(ir.route.rules[0].action, crate::ir::RuleAction::Reject);
        assert_eq!(ir.route.rules[1].action, crate::ir::RuleAction::RejectDrop);
    }

    #[test]
    fn test_rule_action_hijack_with_override() {
        let json = r#"{
            "route": {
                "rules": [
                    {
                        "domain": ["hijack.com"],
                        "action": "hijack",
                        "override_address": "1.1.1.1",
                        "override_port": 53
                    }
                ]
            }
        }"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let ir = crate::validator::v2::to_ir_v1(&raw);
        assert_eq!(ir.route.rules.len(), 1);
        assert_eq!(ir.route.rules[0].action, crate::ir::RuleAction::Hijack);
        assert_eq!(ir.route.rules[0].override_address, Some("1.1.1.1".to_string()));
        assert_eq!(ir.route.rules[0].override_port, Some(53));
    }

    #[test]
    fn test_logical_rule_and_mode() {
        let json = r#"{
            "route": {
                "rules": [
                    {
                        "type": "logical",
                        "mode": "and",
                        "rules": [
                            { "domain": ["example.com"] },
                            { "port": 80 }
                        ],
                        "action": "route",
                        "outbound": "direct"
                    }
                ]
            }
        }"#;
        let raw: Value = serde_json::from_str(json).unwrap();
        let ir = crate::validator::v2::to_ir_v1(&raw);
        assert_eq!(ir.route.rules.len(), 1);
        let rule = &ir.route.rules[0];
        assert_eq!(rule.mode.as_deref(), Some("and"));
        assert_eq!(rule.rules.len(), 2);
        assert!(rule.rules[0].domain.contains(&"example.com".to_string()));
        assert!(rule.rules[1].port.contains(&"80".to_string()));
    }
}
