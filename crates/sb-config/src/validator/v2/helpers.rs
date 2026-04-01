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

pub(crate) fn extract_string_list(value: Option<&Value>) -> Option<Vec<String>> {
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

pub(crate) fn extract_listable_strings(value: Option<&Value>) -> Option<Listable<String>> {
    extract_string_list(value).map(|items| Listable { items })
}

pub(crate) fn parse_listable<T>(value: Option<&Value>) -> Option<Listable<T>>
where
    T: DeserializeOwned,
{
    let v = value?.clone();
    serde_json::from_value::<Listable<T>>(v).ok()
}

pub(crate) fn parse_seconds_field_to_millis(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(num)) => num.as_u64().map(|secs| secs.saturating_mul(1_000)),
        Some(Value::String(s)) => humantime::parse_duration(s)
            .ok()
            .map(|d| d.as_millis() as u64),
        _ => None,
    }
}

pub(crate) fn parse_millis_field(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(num)) => num.as_u64(),
        Some(Value::String(s)) => humantime::parse_duration(s)
            .ok()
            .map(|d| d.as_millis() as u64),
        _ => None,
    }
}

pub(crate) fn parse_u32_field(value: Option<&Value>) -> Option<u32> {
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

pub(crate) fn parse_u16_field(value: Option<&Value>) -> Option<u16> {
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

pub(crate) fn parse_fwmark_field(value: Option<&Value>) -> Option<u32> {
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

pub(crate) fn parse_inbound_tls_options(value: Option<&Value>) -> Option<InboundTlsOptionsIR> {
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

#[cfg(test)]
mod tests {
    use super::{
        emit_issue, extract_listable_strings, extract_string_list, parse_fwmark_field,
        parse_inbound_tls_options, parse_listable, parse_millis_field,
        parse_seconds_field_to_millis, parse_u16_field, parse_u32_field,
    };
    use crate::ir::{Listable, StringOrObj};
    use sb_types::IssueCode;
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct StringValueObj {
        value: String,
    }

    impl From<String> for StringValueObj {
        fn from(value: String) -> Self {
            Self { value }
        }
    }

    #[test]
    fn extract_string_list_preserves_supported_compat_shapes() {
        assert_eq!(
            extract_string_list(Some(&json!([" alpha ", 7, { "address": "beta" }, ""]))),
            Some(vec![
                "alpha".to_string(),
                "7".to_string(),
                "beta".to_string()
            ])
        );
        assert_eq!(
            extract_string_list(Some(&json!({ "url": "https://example.com" }))),
            Some(vec!["https://example.com".to_string()])
        );
    }

    #[test]
    fn extract_listable_and_parse_listable_keep_wrapper_semantics() {
        assert_eq!(
            extract_listable_strings(Some(&json!("alpha"))),
            Some(Listable {
                items: vec!["alpha".to_string()]
            })
        );

        let parsed = parse_listable::<StringOrObj<StringValueObj>>(Some(&json!([
            "alpha",
            { "value": "beta" }
        ])))
        .expect("parse_listable should accept string-or-object wrappers");
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(
            parsed.items[0].clone().into_inner(),
            StringValueObj::from("alpha".to_string())
        );
        assert_eq!(
            parsed.items[1].clone().into_inner(),
            StringValueObj::from("beta".to_string())
        );
    }

    #[test]
    fn parse_numeric_and_duration_helpers_keep_existing_compat() {
        assert_eq!(parse_seconds_field_to_millis(Some(&json!(5))), Some(5_000));
        assert_eq!(
            parse_seconds_field_to_millis(Some(&json!("1500ms"))),
            Some(1_500)
        );
        assert_eq!(parse_millis_field(Some(&json!("2s"))), Some(2_000));
        assert_eq!(parse_u32_field(Some(&json!("100mbps"))), Some(100));
        assert_eq!(parse_u16_field(Some(&json!("443"))), Some(443));
        assert_eq!(parse_fwmark_field(Some(&json!("0x2a"))), Some(42));
    }

    #[test]
    fn parse_inbound_tls_options_keeps_list_fields_and_paths() {
        let tls = parse_inbound_tls_options(Some(&json!({
            "enabled": true,
            "server_name": "example.com",
            "alpn": "h2",
            "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
            "certificate": {"value": "/tmp/cert.pem"},
            "certificate_path": "/tmp/cert-chain.pem",
            "key": ["/tmp/key.pem"],
            "key_path": "/tmp/key-chain.pem"
        })))
        .expect("tls object should parse");

        assert!(tls.enabled);
        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
        assert_eq!(tls.alpn, Some(vec!["h2".to_string()]));
        assert_eq!(
            tls.cipher_suites,
            Some(vec!["TLS_AES_128_GCM_SHA256".to_string()])
        );
        assert_eq!(tls.certificate, Some(vec!["/tmp/cert.pem".to_string()]));
        assert_eq!(tls.certificate_path.as_deref(), Some("/tmp/cert-chain.pem"));
        assert_eq!(tls.key, Some(vec!["/tmp/key.pem".to_string()]));
        assert_eq!(tls.key_path.as_deref(), Some("/tmp/key-chain.pem"));
    }

    #[test]
    fn emit_issue_keeps_schema_shape() {
        let issue = emit_issue(
            "warning",
            IssueCode::UnknownField,
            "/route/extra",
            "unknown field",
            "remove it",
        );
        assert_eq!(issue["kind"], "warning");
        assert_eq!(issue["code"], "UnknownField");
        assert_eq!(issue["ptr"], "/route/extra");
        assert_eq!(issue["msg"], "unknown field");
        assert_eq!(issue["hint"], "remove it");
    }

    #[test]
    fn wp30aq_pin_shared_helper_owner_is_helpers_rs() {
        let source = include_str!("helpers.rs");
        for needle in [
            "pub(crate) fn extract_string_list",
            "pub(crate) fn parse_listable<T>",
            "pub(crate) fn parse_inbound_tls_options",
            "pub fn emit_issue",
        ] {
            assert!(
                source.contains(needle),
                "expected `{needle}` to live in validator/v2/helpers.rs"
            );
        }
    }

    #[test]
    fn wp30aq_pin_mod_rs_is_thin_helper_and_facade_shell() {
        let source = include_str!("mod.rs");
        assert!(
            source.contains("mod helpers;")
                && source.contains("pub use helpers::emit_issue;")
                && source.contains("pub(super) use helpers::{")
                && source.contains("pub use outbound::check_tls_capabilities;")
                && source.contains("facade::validate_v2(doc, allow_unknown)")
                && source.contains("facade::pack_output(issues)")
                && source.contains("facade::to_ir_v1(doc)"),
            "expected validator/v2/mod.rs to stay a thin helper/facade shell"
        );
        for needle in [
            "pub(crate) fn extract_string_list",
            "pub(crate) fn parse_listable<T>",
            "pub(crate) fn parse_inbound_tls_options",
            "pub fn emit_issue",
        ] {
            assert!(
                !source.contains(needle),
                "expected validator/v2/mod.rs to stop owning `{needle}`"
            );
        }
    }
}
