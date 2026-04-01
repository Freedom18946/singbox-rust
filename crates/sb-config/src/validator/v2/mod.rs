mod deprecation;
mod dns;
mod endpoint;
mod inbound;
mod outbound;
mod route;
mod security;
mod service;
mod top_level;

// Re-export outbound TLS capability check for public API stability
pub use outbound::check_tls_capabilities;

use crate::ir::{ConfigIR, Credentials, InboundTlsOptionsIR, Listable};
use sb_types::IssueCode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;

pub(crate) fn object_keys<T>(value: T) -> HashSet<String>
where
    T: Serialize,
{
    let mut set = HashSet::new();
    let val = serde_json::to_value(value).unwrap_or(Value::Null);
    if let Some(map) = val.as_object() {
        for key in map.keys() {
            set.insert(key.clone());
        }
    }
    set
}

pub(crate) fn insert_keys(set: &mut HashSet<String>, keys: &[&str]) {
    for key in keys {
        set.insert((*key).to_string());
    }
}

pub(super) fn extract_string_list(value: Option<&Value>) -> Option<Vec<String>> {
    match value? {
        Value::Array(arr) => {
            let collected: Vec<String> = arr
                .iter()
                .filter_map(|x| match x {
                    Value::String(s) => {
                        let trimmed = s.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(trimmed.to_string())
                        }
                    }
                    Value::Number(n) => Some(n.to_string()),
                    Value::Object(obj) => obj
                        .get("value")
                        .or_else(|| obj.get("address"))
                        .or_else(|| obj.get("url"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    _ => None,
                })
                .collect();
            if collected.is_empty() {
                None
            } else {
                Some(collected)
            }
        }
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(vec![trimmed.to_string()])
            }
        }
        Value::Number(n) => Some(vec![n.to_string()]),
        Value::Object(obj) => obj
            .get("value")
            .or_else(|| obj.get("address"))
            .or_else(|| obj.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| vec![s]),
        _ => None,
    }
}

pub(super) fn extract_listable_strings(value: Option<&Value>) -> Option<Listable<String>> {
    extract_string_list(value).map(|items| Listable { items })
}

pub(super) fn parse_listable<T>(value: Option<&Value>) -> Option<Listable<T>>
where
    T: DeserializeOwned,
{
    let v = value?.clone();
    serde_json::from_value::<Listable<T>>(v).ok()
}

pub(super) fn parse_seconds_field_to_millis(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(num)) => num.as_u64().map(|secs| secs.saturating_mul(1_000)),
        Some(Value::String(s)) => humantime::parse_duration(s)
            .ok()
            .map(|d| d.as_millis() as u64),
        _ => None,
    }
}

pub(super) fn parse_millis_field(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(num)) => num.as_u64(),
        Some(Value::String(s)) => humantime::parse_duration(s)
            .ok()
            .map(|d| d.as_millis() as u64),
        _ => None,
    }
}

pub(super) fn parse_u32_field(value: Option<&Value>) -> Option<u32> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u32::try_from(v).ok()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut lowered = trimmed.to_ascii_lowercase();
            for suffix in ["mbps", "m", "bps"] {
                if lowered.ends_with(suffix) {
                    let len = lowered.len().saturating_sub(suffix.len());
                    lowered = lowered[..len].trim().to_string();
                    break;
                }
            }
            let digits: String = lowered.chars().filter(|c| c.is_ascii_digit()).collect();
            let target = if digits.is_empty() {
                lowered.replace('_', "")
            } else {
                digits
            };
            if target.is_empty() {
                None
            } else {
                target.parse::<u32>().ok()
            }
        }
        _ => None,
    }
}

pub(super) fn parse_u16_field(value: Option<&Value>) -> Option<u16> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u16::try_from(v).ok()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                trimmed.parse::<u16>().ok()
            }
        }
        _ => None,
    }
}

pub(super) fn parse_fwmark_field(value: Option<&Value>) -> Option<u32> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u32::try_from(v).ok()),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let hex = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"));
            if let Some(hex) = hex {
                u32::from_str_radix(hex.trim(), 16).ok()
            } else {
                trimmed.parse::<u32>().ok()
            }
        }
        _ => None,
    }
}

pub(super) fn parse_inbound_tls_options(value: Option<&Value>) -> Option<InboundTlsOptionsIR> {
    let obj = value.and_then(|v| v.as_object())?;

    Some(InboundTlsOptionsIR {
        enabled: obj
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        server_name: obj
            .get("server_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        insecure: obj.get("insecure").and_then(|v| v.as_bool()),
        alpn: extract_string_list(obj.get("alpn")),
        min_version: obj
            .get("min_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        max_version: obj
            .get("max_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        cipher_suites: extract_string_list(obj.get("cipher_suites")),
        certificate: extract_string_list(obj.get("certificate")),
        certificate_path: obj
            .get("certificate_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        key: extract_string_list(obj.get("key")),
        key_path: obj
            .get("key_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

fn resolve_cred(c: &mut Credentials) {
    if let Some(key) = &c.username_env {
        if let Ok(v) = std::env::var(key) {
            c.username = Some(v);
        }
    }
    if let Some(key) = &c.password_env {
        if let Ok(v) = std::env::var(key) {
            c.password = Some(v);
        }
    }
}

/// Parse and normalize credentials (ENV > Plaintext), avoiding downstream duplicate checks.
/// 解析并归一化认证字段（ENV > 明文），避免下游重复判断。
fn normalize_credentials(ir: &mut ConfigIR) {
    for ob in &mut ir.outbounds {
        if let Some(c) = &mut ob.credentials {
            resolve_cred(c);
        }
    }
    for ib in &mut ir.inbounds {
        if let Some(c) = &mut ib.basic_auth {
            resolve_cred(c);
        }
    }
}

/// Convert internal errors to a unified structure.
/// 将内部错误统一转换为固定结构。
pub fn emit_issue(kind: &str, code: IssueCode, ptr: &str, msg: &str, hint: &str) -> Value {
    json!({"kind": kind, "code": code.as_str(), "ptr": ptr, "msg": msg, "hint": hint})
}

/// Lightweight schema validation (placeholder implementation): parses built-in schema, checks against field set for UnknownField/TypeMismatch/MissingRequired.
/// Note: To avoid heavy dependencies, minimal necessary logic is implemented here; can be switched to jsonschema crate later while keeping output structure unchanged.
/// 轻量 schema 校验（占位实现）：解析内置 schema，对照字段集做 UnknownField/TypeMismatch/MissingRequired
/// 说明：为了不引入庞大依赖，这里实现最小必要逻辑；后续可切换 jsonschema crate，保持输出结构不变。
///
/// # Arguments
/// * `doc` - The JSON document to validate / 待验证的 JSON 文档
/// * `allow_unknown` - Whether to treat unknown fields as warnings (true) instead of errors (false) / 是否将未知字段视为警告（true）而非错误（false）
pub fn validate_v2(doc: &serde_json::Value, allow_unknown: bool) -> Vec<Value> {
    let schema_text = include_str!("../v2_schema.json");
    let schema: Value = match serde_json::from_str(schema_text) {
        Ok(v) => v,
        Err(_) => {
            return vec![emit_issue(
                "error",
                IssueCode::Conflict,
                "/",
                "schema load failed",
                "internal",
            )];
        }
    };
    let mut issues = Vec::<Value>::new();
    // 0) schema_version check (must be 2)
    match doc.get("schema_version") {
        Some(v) => {
            if v.as_u64() != Some(2) {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    "/schema_version",
                    "schema_version must be 2",
                    "set to 2",
                ));
            }
        }
        None => {
            // Optional: we accept missing but could warn to migrate
            issues.push(emit_issue(
                "warning",
                IssueCode::MissingRequired,
                "/schema_version",
                "missing schema_version (assuming v2)",
                "add: 2",
            ));
        }
    }
    // 1) 根 additionalProperties=false
    if let (Some(obj), Some(props)) = (
        doc.as_object(),
        schema.get("properties").and_then(|p| p.as_object()),
    ) {
        for k in obj.keys() {
            // Allow $schema (Go optional field for JSON Schema tooling)
            if k == "$schema" {
                continue;
            }
            if !props.contains_key(k) {
                let kind = if allow_unknown { "warning" } else { "error" };
                issues.push(emit_issue(
                    kind,
                    IssueCode::UnknownField,
                    &format!("/{}", k),
                    "unknown field",
                    "remove it",
                ));
            }
        }
    }
    // 2) inbounds type and structure validation (delegated to inbound submodule)
    inbound::validate_inbounds(doc, allow_unknown, &mut issues);

    // 3) outbounds type and structure validation (delegated to outbound submodule)
    outbound::validate_outbounds(doc, allow_unknown, &mut issues);

    // 4) route unknown-field and rule_set validation (delegated to route submodule)
    route::validate_route(doc, allow_unknown, &mut issues);

    // 5) dns unknown-field validation (delegated to dns submodule)
    dns::validate_dns(doc, allow_unknown, &mut issues);

    // 6) service unknown-field validation (delegated to service submodule)
    service::validate_services(doc, allow_unknown, &mut issues);

    // 7) endpoint unknown-field validation (delegated to endpoint submodule)
    endpoint::validate_endpoints(doc, allow_unknown, &mut issues);

    // Deprecation detection pass (delegated to deprecation submodule)
    issues.extend(deprecation::check_deprecations(doc));
    // Security: non-localhost binding warnings (delegated to security submodule)
    issues.extend(security::check_non_localhost_binding_warnings(doc));
    // TLS capability matrix validation
    issues.extend(outbound::check_tls_capabilities(doc));
    issues
}

/// Pack output.
/// 打包输出。
pub fn pack_output(issues: Vec<Value>) -> Value {
    json!({ "issues": issues, "fingerprint": env!("CARGO_PKG_VERSION") })
}

/// Convert V1/V2 raw JSON to IR (excerpt; V1 unknown fields ignored but warning optional).
/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）。
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    let mut ir = crate::ir::ConfigIR::default();
    // Inbound lowering — delegated to inbound.rs (WP-30u)
    inbound::lower_inbounds(doc, &mut ir);
    // Outbound lowering — delegated to outbound.rs (WP-30z)
    outbound::lower_outbounds(doc, &mut ir);

    // Endpoint lowering — delegated to endpoint.rs (WP-30v)
    endpoint::lower_endpoints(doc, &mut ir);

    route::lower_route(doc, &mut ir);

    // Top-level block lowering (experimental/log/ntp/certificate) — delegated to top_level.rs (WP-30ac)
    top_level::lower_top_level_blocks(doc, &mut ir);

    dns::lower_dns(doc, &mut ir);

    service::lower_services(doc, &mut ir);

    normalize_credentials(&mut ir);
    ir
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───── TLS fragment route key acceptance test ─────

    #[test]
    fn test_tls_fragment_route_keys_accepted() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "route": {
                "tls_fragment": true,
                "tls_record_fragment": {
                    "enabled": true,
                    "size_min": 1,
                    "size_max": 5
                },
                "tls_fragment_fallback_delay": "300ms"
            }
        });
        let issues = validate_v2(&doc, false);
        let unknown: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["code"].as_str() == Some("UnknownField")
                    && i["ptr"]
                        .as_str()
                        .is_some_and(|p| p.starts_with("/route/tls_fragment"))
            })
            .collect();
        assert!(
            unknown.is_empty(),
            "tls_fragment keys should be accepted in route, but got unknown field errors: {:?}",
            unknown
        );
    }

    // ───── TLS capability matrix validation tests (L14.1.4) ─────

    #[test]
    fn test_tls_utls_non_chrome_fingerprint_emits_info() {
        let doc = serde_json::json!({
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "my-vless",
                    "server": "example.com",
                    "port": 443,
                    "utls_fingerprint": "firefox"
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let utls_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("info")
                    && i["ptr"]
                        .as_str()
                        .is_some_and(|p| p.contains("utls_fingerprint"))
            })
            .collect();
        assert!(
            !utls_issues.is_empty(),
            "Non-chrome uTLS fingerprint should emit info diagnostic, got: {:?}",
            issues
        );
        // Verify the message mentions the fingerprint
        let msg = utls_issues[0]["msg"].as_str().unwrap_or("");
        assert!(
            msg.contains("firefox"),
            "Info message should mention the fingerprint 'firefox', got: {}",
            msg
        );
    }

    #[test]
    fn test_tls_utls_chrome_fingerprint_no_warning() {
        let doc = serde_json::json!({
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "my-vless",
                    "server": "example.com",
                    "port": 443,
                    "utls_fingerprint": "chrome"
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let utls_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["ptr"]
                    .as_str()
                    .is_some_and(|p| p.contains("utls_fingerprint"))
            })
            .collect();
        assert!(
            utls_issues.is_empty(),
            "'chrome' fingerprint should not emit any diagnostic, got: {:?}",
            utls_issues
        );
    }

    #[test]
    fn test_tls_ech_emits_info() {
        let doc = serde_json::json!({
            "outbounds": [
                {
                    "type": "trojan",
                    "tag": "ech-proxy",
                    "server": "example.com",
                    "port": 443,
                    "encrypted_client_hello": true
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let ech_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("info")
                    && i["ptr"]
                        .as_str()
                        .is_some_and(|p| p.contains("encrypted_client_hello"))
            })
            .collect();
        assert!(
            !ech_issues.is_empty(),
            "ECH enabled should emit info diagnostic, got: {:?}",
            issues
        );
        let msg = ech_issues[0]["msg"].as_str().unwrap_or("");
        assert!(
            msg.contains("ECH") || msg.contains("Encrypted Client Hello"),
            "Info message should mention ECH, got: {}",
            msg
        );
    }

    #[test]
    fn test_tls_quic_ech_reject_mode_emits_error() {
        let doc = serde_json::json!({
            "outbounds": [
                {
                    "type": "tuic",
                    "tag": "quic-ech-out",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "password": "secret",
                    "tls": {
                        "ech": { "enabled": true }
                    }
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let blocked: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("error")
                    && i["ptr"].as_str().is_some_and(|p| p.contains("/tls/ech"))
            })
            .collect();
        assert!(
            !blocked.is_empty(),
            "QUIC + ECH should be hard-blocked, got: {:?}",
            issues
        );
        let msg = blocked[0]["msg"].as_str().unwrap_or("");
        assert!(
            msg.contains("QUIC + ECH") || msg.contains("QUIC"),
            "error message should mention QUIC + ECH, got: {}",
            msg
        );
    }

    #[test]
    fn test_tls_quic_ech_experimental_mode_emits_warning_not_error() {
        let doc = serde_json::json!({
            "experimental": {
                "quic_ech_mode": "experimental"
            },
            "outbounds": [
                {
                    "type": "tuic",
                    "tag": "quic-ech-out",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "password": "secret",
                    "tls": {
                        "ech": { "enabled": true }
                    }
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let warnings: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("warning")
                    && i["ptr"].as_str().is_some_and(|p| p.contains("/tls/ech"))
            })
            .collect();
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("error")
                    && i["ptr"].as_str().is_some_and(|p| p.contains("/tls/ech"))
            })
            .collect();

        assert!(
            !warnings.is_empty(),
            "QUIC + ECH in experimental mode should emit warning, got: {:?}",
            issues
        );
        assert!(
            errors.is_empty(),
            "QUIC + ECH in experimental mode should not emit hard error, got: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_quic_ech_invalid_mode_emits_mode_error() {
        let doc = serde_json::json!({
            "experimental": {
                "quic_ech_mode": "beta"
            },
            "outbounds": [
                {
                    "type": "tuic",
                    "tag": "quic-ech-out",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "password": "secret",
                    "tls": {
                        "ech": { "enabled": true }
                    }
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let mode_errors: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("error")
                    && i["ptr"].as_str() == Some("/experimental/quic_ech_mode")
            })
            .collect();
        assert!(
            !mode_errors.is_empty(),
            "invalid experimental.quic_ech_mode should emit explicit error, got: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_reality_emits_info() {
        let doc = serde_json::json!({
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "reality-proxy",
                    "server": "example.com",
                    "port": 443,
                    "reality_enabled": true,
                    "reality_public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
                    "reality_short_id": "01ab"
                }
            ]
        });
        let issues = check_tls_capabilities(&doc);
        let reality_issues: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("info")
                    && i["ptr"]
                        .as_str()
                        .is_some_and(|p| p.contains("reality_enabled"))
            })
            .collect();
        assert!(
            !reality_issues.is_empty(),
            "REALITY enabled should emit info diagnostic, got: {:?}",
            issues
        );
        let msg = reality_issues[0]["msg"].as_str().unwrap_or("");
        assert!(
            msg.contains("REALITY"),
            "Info message should mention REALITY, got: {}",
            msg
        );
    }

    #[test]
    fn test_tls_capabilities_integrated_in_validate_v2() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "fp-proxy",
                    "server": "example.com",
                    "port": 443,
                    "utls_fingerprint": "safari"
                }
            ]
        });
        let issues = validate_v2(&doc, true);
        let tls_info: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("info")
                    && i["ptr"]
                        .as_str()
                        .is_some_and(|p| p.contains("utls_fingerprint"))
            })
            .collect();
        assert!(
            !tls_info.is_empty(),
            "validate_v2 should include TLS capability info from check_tls_capabilities"
        );
    }

    #[test]
    fn test_tls_quic_ech_integrated_in_validate_v2() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "tuic",
                    "tag": "quic-ech-out",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "password": "secret",
                    "tls": {
                        "ech": { "enabled": true }
                    }
                }
            ]
        });
        let issues = validate_v2(&doc, true);
        let blocked: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("error")
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("QUIC + ECH") || m.contains("QUIC"))
            })
            .collect();
        assert!(
            !blocked.is_empty(),
            "validate_v2 should include QUIC + ECH blocking error, got: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_quic_ech_experimental_integrated_in_validate_v2() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "quic_ech_mode": "experimental"
            },
            "outbounds": [
                {
                    "type": "tuic",
                    "tag": "quic-ech-out",
                    "server": "example.com",
                    "port": 443,
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "password": "secret",
                    "tls": {
                        "ech": { "enabled": true }
                    }
                }
            ]
        });
        let issues = validate_v2(&doc, true);
        let warned: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("warning")
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("experimental mode"))
            })
            .collect();
        let blocked: Vec<_> = issues
            .iter()
            .filter(|i| {
                i["kind"].as_str() == Some("error")
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("QUIC + ECH") || m.contains("QUIC"))
            })
            .collect();
        assert!(
            !warned.is_empty(),
            "validate_v2 should include QUIC + ECH experimental warning, got: {:?}",
            issues
        );
        assert!(
            blocked.is_empty(),
            "validate_v2 should not hard-block QUIC + ECH when experimental mode is set, got: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_no_outbounds_no_crash() {
        // Ensure the function handles missing outbounds gracefully
        let doc = serde_json::json!({
            "schema_version": 2
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.is_empty(),
            "No outbounds should produce no TLS capability issues"
        );
    }
}
