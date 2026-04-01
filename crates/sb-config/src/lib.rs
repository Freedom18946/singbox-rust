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

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
// use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

// sb-config stays independent of sb-core; runtime wiring lives in sb-core.

pub mod compat;
pub mod de;
pub mod defaults;
pub mod deprecation;
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
        let (migrated, _migration_diagnostics) = compat::migrate_to_v2(&raw);

        // Go parity: strict validation - unknown fields are errors (DisallowUnknownFields)
        let issues = crate::validator::v2::validate_v2(&migrated, false);
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.get("kind").and_then(|k| k.as_str()) == Some("error"))
            .collect();
        if !errors.is_empty() {
            let first = &errors[0];
            let ptr = first.get("ptr").and_then(|p| p.as_str()).unwrap_or("/");
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
        // WP-30as: Config::validate() remains a thin entry point. It delegates
        // to the crate-private planned orchestration facade, which keeps the
        // collect/validate stages explicit without introducing a public
        // RuntimePlan or generic query API.
        crate::ir::planned::validate_planned_facts(&self.ir)?;

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
                    compat::migrate_to_v2(&serde_json::to_value(&*self).unwrap_or(Value::Null)).0;
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
    let (migrated, _migration_diagnostics) = compat::migrate_to_v2(&raw);

    // Strict validation (Go parity)
    let issues = crate::validator::v2::validate_v2(&migrated, false);
    let errors: Vec<_> = issues
        .iter()
        .filter(|i| i.get("kind").and_then(|k| k.as_str()) == Some("error"))
        .collect();
    if !errors.is_empty() {
        let first = &errors[0];
        let ptr = first.get("ptr").and_then(|p| p.as_str()).unwrap_or("/");
        let msg = first
            .get("msg")
            .and_then(|m| m.as_str())
            .unwrap_or("validation error");
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
    fn test_inbound_outbound_tag_conflict_allowed() {
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
        assert!(
            cfg.validate().is_ok(),
            "inbound tag may overlap outbound tag (Go parity)"
        );
    }

    #[test]
    fn test_duplicate_outbound_endpoint_tag_rejected() {
        let y = r#"
outbounds:
  - type: direct
    tag: shared
endpoints:
  - type: wireguard
    tag: shared
        "#;
        let raw: Value = serde_yaml::from_str(y).unwrap();
        let cfg = Config::from_value(raw).unwrap();
        let result = cfg.validate();
        assert!(
            result.is_err(),
            "duplicate outbound/endpoint tags should be rejected"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate outbound/endpoint tag"),
            "error should mention 'duplicate outbound/endpoint tag'"
        );
    }

    #[test]
    fn planned_preflight_pin_current_owner_dns_detour_validated_but_not_env_bound() {
        // WP-30k original: dns.detour was only parsed, not validated.
        // WP-30m/WP-30o update: dns.detour reference existence is now checked by
        // planned.rs (PlannedFacts fact graph), but runtime env binding
        // still stays in app::run_engine::apply_dns_env_from_config().
        //
        // This pin confirms: missing detour target is NOW rejected at validate time,
        // but no env variable binding happens in sb-config.
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ],
            "route": {
                "rules": [],
                "default": "direct"
            },
            "dns": {
                "servers": [
                    {
                        "tag": "dns-upstream",
                        "address": "udp://1.1.1.1",
                        "detour": "missing-runtime-owner"
                    }
                ]
            }
        });

        let cfg = Config::from_value(raw).expect("config parses");
        // WP-30m: dns.detour reference existence is now validated
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("detour 'missing-runtime-owner' not found in outbounds"),
            "dns.detour should now be validated by planned.rs cross-reference seam: {}",
            err
        );

        // But the IR still preserves the string — no env binding happens here
        let dns = cfg.ir().dns.as_ref().expect("dns parsed into IR");
        assert_eq!(
            dns.servers[0].detour.as_deref(),
            Some("missing-runtime-owner")
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
        assert!(
            cfg.rules[0]
                .domain_suffix
                .contains(&".example.com".to_string())
        );
        assert!(
            cfg.rules[0]
                .domain_suffix
                .contains(&".google.com".to_string())
        );
        // domain_suffix should NOT contain "exact.com" (that's from domain field)
        assert!(
            !cfg.rules[0]
                .domain_suffix
                .contains(&"exact.com".to_string())
        );
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
        assert_eq!(
            ir.route.rules[0].override_address,
            Some("1.1.1.1".to_string())
        );
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

    #[test]
    fn test_go_format_config_with_schema() {
        // Go sing-box format: uses $schema URL, tag (not name), server_port (not port)
        // GUI.for SingBox generates configs in this format
        let json = r#"{
            "$schema": "https://sing-box.sagernet.org/schemas/config.json",
            "inbounds": [
                {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 8080}
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"}
            ],
            "route": {
                "rules": [
                    {"domain_suffix": [".example.com"], "outbound": "direct"}
                ]
            }
        }"#;
        let raw: Value = serde_json::from_str(json).unwrap();

        // Full pipeline: migrate + validate + parse
        let (migrated, _diags) = crate::compat::migrate_to_v2(&raw);

        // $schema should be preserved but not cause errors
        assert!(migrated.get("$schema").is_some());

        // schema_version should be injected
        assert_eq!(
            migrated.get("schema_version").and_then(|v| v.as_u64()),
            Some(2)
        );

        // tag should be renamed to name
        let first_outbound = &migrated["outbounds"][0];
        assert_eq!(
            first_outbound.get("name").and_then(|v| v.as_str()),
            Some("direct")
        );
        assert!(first_outbound.get("tag").is_none());

        // Validation should pass (no errors)
        let issues = crate::validator::v2::validate_v2(&migrated, false);
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.get("kind").and_then(|k| k.as_str()) == Some("error"))
            .collect();
        assert!(
            errors.is_empty(),
            "Go-format config should validate: {:?}",
            errors
        );

        // Full pipeline should succeed
        let result = config_from_raw_value(raw);
        assert!(
            result.is_ok(),
            "Go-format config should parse: {:?}",
            result.err()
        );
    }

    // ── WP-30l: planned private seam integration tests ──

    /// Integration: duplicate outbound/endpoint tag is still rejected with exact
    /// same error message, now delegated to `ir::planned` seam.
    #[test]
    fn wp30l_duplicate_outbound_tag_error_unchanged() {
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "dup" },
                { "type": "direct", "tag": "dup" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate outbound/endpoint tag: dup",
            "error message must be identical after planned seam migration"
        );
    }

    /// Integration: selector member referencing nonexistent outbound is still
    /// rejected with exact same error message.
    #[test]
    fn wp30l_selector_missing_member_error_unchanged() {
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "selector", "tag": "select", "outbounds": ["direct", "ghost"] }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string().contains("member 'ghost' not found"),
            "error message must be identical after planned seam migration: {}",
            err
        );
    }

    /// Integration: route rule referencing nonexistent outbound is still rejected
    /// with exact same error message.
    #[test]
    fn wp30l_rule_outbound_missing_error_unchanged() {
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ],
            "route": {
                "rules": [
                    { "domain_suffix": [".example.com"], "outbound": "nonexistent" }
                ]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "rule outbound not found: nonexistent",
            "error message must be identical after planned seam migration"
        );
    }

    /// Integration: `route.default` referencing nonexistent outbound is still
    /// rejected with exact same error message.
    #[test]
    fn wp30l_route_default_missing_error_unchanged() {
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ],
            "route": {
                "default": "missing"
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "default_outbound not found in outbounds: missing",
            "error message must be identical after planned seam migration"
        );
    }

    /// Integration: valid outbound + selector + route combo still passes.
    #[test]
    fn wp30l_valid_outbound_selector_route_passes() {
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1080 },
                { "type": "selector", "tag": "select", "outbounds": ["direct", "proxy"] }
            ],
            "route": {
                "rules": [
                    { "domain_suffix": [".example.com"], "outbound": "proxy" }
                ],
                "default": "direct"
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "valid outbound/selector/route combo must pass"
        );
    }

    /// Pin (WP-30p): inbound duplicate tag detection is now owned by the planned
    /// fact graph (`PlannedFacts::collect()`), not by `Config::validate()` directly.
    /// `Config::validate()` is now a thin entry point that delegates to
    /// `validate_planned_facts()`.
    #[test]
    fn wp30p_pin_inbound_duplicate_tag_owned_by_fact_graph() {
        let raw = serde_json::json!({
            "inbounds": [
                { "type": "http", "tag": "dup-ib", "listen": "127.0.0.1", "listen_port": 8080 },
                { "type": "http", "tag": "dup-ib", "listen": "127.0.0.1", "listen_port": 8081 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate inbound tag: dup-ib",
            "inbound tag uniqueness error message must be unchanged (WP-30p)"
        );
    }

    /// Pin (WP-30p): inbound and outbound/endpoint namespaces are independent —
    /// the same tag appearing in both is allowed (Go parity).
    #[test]
    fn wp30p_pin_inbound_outbound_same_tag_allowed() {
        let raw = serde_json::json!({
            "inbounds": [
                { "type": "http", "tag": "shared", "listen": "127.0.0.1", "listen_port": 8080 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "shared" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "inbound and outbound/endpoint are independent namespaces (Go parity)"
        );
    }

    /// Pin (WP-30p): runtime-facing DNS env bridge is still NOT in planned.rs.
    /// This pin confirms the boundary hasn't moved.
    #[test]
    fn wp30p_pin_dns_env_bridge_still_not_moved() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [{ "tag": "dns1", "address": "udp://1.1.1.1", "detour": "direct" }]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "DNS env bridge stays in app::run_engine, not in planned.rs"
        );
    }

    // ── WP-30m integration tests: cross-reference validation via Config::validate() ──

    #[test]
    fn wp30m_dns_detour_missing_outbound_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [{
                    "tag": "google",
                    "address": "udp://8.8.8.8",
                    "detour": "nonexistent-outbound"
                }]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("detour 'nonexistent-outbound' not found in outbounds"),
            "dns server detour must be validated against outbound namespace: {}",
            err
        );
    }

    #[test]
    fn wp30m_dns_address_resolver_missing_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8", "address_resolver": "ghost-dns" },
                    { "tag": "local", "address": "local" }
                ]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("address_resolver 'ghost-dns' not found in dns servers"),
            "dns address_resolver must be validated against dns server namespace: {}",
            err
        );
    }

    #[test]
    fn wp30m_dns_service_missing_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [{
                    "tag": "resolved-dns",
                    "address": "resolved",
                    "service": "nonexistent-service"
                }]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("service 'nonexistent-service' not found in services"),
            "dns service must be validated against service namespace: {}",
            err
        );
    }

    #[test]
    fn wp30m_service_detour_missing_inbound_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "services": [{
                "type": "resolved",
                "tag": "resolved-svc",
                "detour": "nonexistent-inbound"
            }]
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("detour 'nonexistent-inbound' not found in inbounds"),
            "service detour must be validated against inbound namespace: {}",
            err
        );
    }

    #[test]
    fn wp30m_valid_cross_references_pass() {
        let raw = serde_json::json!({
            "inbounds": [
                { "type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 8080 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "socks", "tag": "proxy" }
            ],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8", "detour": "proxy", "address_resolver": "local" },
                    { "tag": "local", "address": "local" }
                ]
            },
            "services": [
                { "type": "resolved", "tag": "resolved-svc", "detour": "http-in" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "valid cross-references must pass validation"
        );
    }

    // ── WP-30n integration tests: DNS server tag reference validation via Config::validate() ──

    #[test]
    fn wp30n_dns_rule_server_missing_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8" }
                ],
                "rules": [
                    { "domain_suffix": [".cn"], "server": "nonexistent-dns" }
                ]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("dns rule: server 'nonexistent-dns' not found in dns servers"),
            "dns rule server must be validated against dns server namespace: {}",
            err
        );
    }

    #[test]
    fn wp30n_dns_default_missing_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8" }
                ],
                "default": "ghost-default"
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("dns: default server 'ghost-default' not found in dns servers"),
            "dns default must be validated against dns server namespace: {}",
            err
        );
    }

    #[test]
    fn wp30n_dns_final_server_missing_rejected() {
        // Note: the validator/v2 maps "final" to both DnsIR.default and DnsIR.final_server.
        // Through the pipeline, check_dns_default fires first (since they share the same tag).
        // The unit test in planned.rs covers final_server independently.
        // Here we verify that "final" pointing to a missing server is rejected.
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8" }
                ],
                "final": "ghost-final"
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        // "final" populates both default and final_server in the validator;
        // check_dns_default fires first with the same tag.
        assert!(
            err.to_string()
                .contains("'ghost-final' not found in dns servers"),
            "dns final must be validated against dns server namespace: {}",
            err
        );
    }

    #[test]
    fn wp30n_valid_dns_rule_default_final_pass() {
        let raw = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "socks", "tag": "proxy" }
            ],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8", "detour": "proxy", "address_resolver": "local" },
                    { "tag": "local", "address": "local" },
                    { "tag": "fallback", "address": "udp://1.1.1.1" }
                ],
                "rules": [
                    { "domain_suffix": [".cn"], "server": "local" },
                    { "domain_suffix": [".com"], "server": "google" }
                ],
                "default": "google",
                "final": "fallback"
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "valid dns rule server + default + final must pass"
        );
    }

    /// Pin: dns.detour as a string is still parsed but NOT bound to runtime env.
    /// planned.rs only checks reference existence, not env bridging.
    /// Runtime-facing DNS env bridge is still in `app::run_engine::apply_dns_env_from_config()`.
    #[test]
    fn wp30m_pin_dns_env_bridge_not_in_planned_seam() {
        // A valid config with dns.detour should pass planned.rs validation.
        // No env variable binding happens in sb-config — that's a runtime concern.
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [{ "tag": "dns1", "address": "udp://1.1.1.1", "detour": "direct" }]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "planned.rs must not attempt DNS env binding — that stays in app::run_engine"
        );
    }

    // ── WP-30q integration tests: DNS server / service tag uniqueness via Config::validate() ──

    #[test]
    fn wp30q_duplicate_dns_server_tag_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8" },
                    { "tag": "google", "address": "udp://8.8.4.4" }
                ]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate dns server tag: google",
            "dns server tag uniqueness error message must be stable (WP-30q)"
        );
    }

    #[test]
    fn wp30q_distinct_dns_server_tags_pass() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8" },
                    { "tag": "cloudflare", "address": "udp://1.1.1.1" }
                ]
            }
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(cfg.validate().is_ok(), "distinct dns server tags must pass");
    }

    #[test]
    fn wp30q_duplicate_service_tag_rejected() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "services": [
                { "type": "resolved", "tag": "my-svc" },
                { "type": "resolved", "tag": "my-svc" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate service tag: my-svc",
            "service tag uniqueness error message must be stable (WP-30q)"
        );
    }

    #[test]
    fn wp30q_distinct_service_tags_pass() {
        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "services": [
                { "type": "resolved", "tag": "svc-a" },
                { "type": "resolved", "tag": "svc-b" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(cfg.validate().is_ok(), "distinct service tags must pass");
    }

    /// Pin (WP-30q): Config::validate() still remains a thin entry point after
    /// DNS server / service uniqueness was absorbed into the fact graph.
    #[test]
    fn wp30q_pin_validate_still_thin_entry_point() {
        let raw = serde_json::json!({
            "inbounds": [
                { "type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 8080 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "socks", "tag": "proxy" }
            ],
            "dns": {
                "servers": [
                    { "tag": "google", "address": "udp://8.8.8.8", "detour": "proxy", "address_resolver": "local" },
                    { "tag": "local", "address": "local", "service": "resolved-svc" },
                    { "tag": "fallback", "address": "udp://1.1.1.1" }
                ],
                "rules": [
                    { "domain_suffix": [".cn"], "server": "local" }
                ],
                "default": "google",
                "final": "fallback"
            },
            "services": [
                { "type": "resolved", "tag": "resolved-svc", "detour": "http-in" }
            ]
        });
        let cfg = Config::from_value(raw).unwrap();
        assert!(
            cfg.validate().is_ok(),
            "full multi-namespace config with all uniqueness checks must pass through thin entry point"
        );
    }
}
