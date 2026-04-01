mod facade;
mod credentials;
mod deprecation;
mod dns;
mod endpoint;
mod inbound;
mod outbound;
mod route;
mod schema_core;
mod security;
mod service;
mod top_level;

// Re-export outbound TLS capability check for public API stability
pub use outbound::check_tls_capabilities;

use crate::ir::{InboundTlsOptionsIR, Listable};
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
    facade::validate_v2(doc, allow_unknown)
}

/// Pack output.
/// 打包输出。
pub fn pack_output(issues: Vec<Value>) -> Value {
    facade::pack_output(issues)
}

/// Convert V1/V2 raw JSON to IR (excerpt; V1 unknown fields ignored but warning optional).
/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）。
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    facade::to_ir_v1(doc)
}
