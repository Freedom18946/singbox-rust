use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, insert_keys, object_keys};

fn allowed_outbound_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::OutboundIR::default());
    if set.remove("ty") {
        set.insert("type".to_string());
    }
    set.insert("tag".to_string());
    insert_keys(
        &mut set,
        &[
            "transport",
            "ws",
            "h2",
            "tls",
            "http_upgrade",
            "httpupgrade",
            "grpc",
        ],
    );
    insert_keys(
        &mut set,
        &[
            "user",
            "auth_str",
            "url",
            "interval",
            "interval_ms",
            "timeout",
            "timeout_ms",
            "tolerance",
            "tolerance_ms",
            "outbounds",
            "default",
        ],
    );
    set
}

/// Validate `/outbounds` array structure, types, tags, and unknown fields.
///
/// 校验 `/outbounds` 数组结构、类型、标签及未知字段。
pub(crate) fn validate_outbounds(
    doc: &Value,
    allow_unknown: bool,
    issues: &mut Vec<Value>,
) {
    // /outbounds must be array (if present)
    if let Some(outbounds_val) = doc.get("outbounds") {
        if !outbounds_val.is_array() {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/outbounds",
                "outbounds must be an array",
                "use []",
            ));
        }
    }
    if let Some(arr) = doc.get("outbounds").and_then(|v| v.as_array()) {
        for (i, ob) in arr.iter().enumerate() {
            // Each outbound must be an object
            if !ob.is_object() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/outbounds/{}", i),
                    "outbound item must be an object",
                    "use {}",
                ));
                continue;
            }

            // type is required
            if ob.get("type").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/outbounds/{}/type", i),
                    "missing required field",
                    "add it",
                ));
            } else if let Some(ty) = ob.get("type") {
                if !ty.is_string() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/outbounds/{}/type", i),
                        "type must be a string",
                        "use string value",
                    ));
                }
            }

            // tag/name should be string if present
            if let Some(tag_val) = ob.get("tag") {
                if !tag_val.is_string() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/outbounds/{}/tag", i),
                        "tag must be a string",
                        "use string value",
                    ));
                }
            }

            // additionalProperties=false (V2 allowed fields)
            if let Some(map) = ob.as_object() {
                let allowed = allowed_outbound_keys();
                for k in map.keys() {
                    if !allowed.contains(k) {
                        let kind = if allow_unknown { "warning" } else { "error" };
                        issues.push(emit_issue(
                            kind,
                            IssueCode::UnknownField,
                            &format!("/outbounds/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        ));
                    }
                }
            }
        }
    }
}

/// Check outbound TLS configurations for capabilities that have known
/// limitations in the Rust implementation. Emits info-level diagnostics for:
/// - uTLS fingerprints other than "chrome" or empty (limited support)
/// - ECH (encrypted_client_hello) configuration (behind feature flag)
/// - REALITY TLS (supported, informational notice)
///
/// 检查出站 TLS 配置中在 Rust 实现中有已知限制的功能。
/// 为以下情况发出 info 级别的诊断：
/// - 非 "chrome" 或空的 uTLS 指纹（有限支持）
/// - ECH（encrypted_client_hello）配置（需要 feature flag）
/// - REALITY TLS（已支持，信息通知）
pub fn check_tls_capabilities(doc: &Value) -> Vec<Value> {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum QuicEchMode {
        Reject,
        Experimental,
    }

    fn ech_enabled(ech_val: &Value) -> bool {
        match ech_val {
            Value::Bool(b) => *b,
            Value::Object(o) => o.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
            _ => false,
        }
    }

    fn has_quic_token(value: Option<&Value>) -> bool {
        match value {
            Some(Value::String(s)) => s
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("quic")),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .any(|token| token.eq_ignore_ascii_case("quic")),
            Some(Value::Object(map)) => map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|ty| ty.eq_ignore_ascii_case("quic")),
            _ => false,
        }
    }

    fn outbound_uses_quic(obj: &serde_json::Map<String, Value>) -> bool {
        if obj.get("type").and_then(Value::as_str).is_some_and(|ty| {
            ty.eq_ignore_ascii_case("tuic")
                || ty.eq_ignore_ascii_case("hysteria")
                || ty.eq_ignore_ascii_case("hysteria2")
        }) {
            return true;
        }
        if has_quic_token(obj.get("network")) || has_quic_token(obj.get("transport")) {
            return true;
        }
        obj.get("udp_relay_mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode.eq_ignore_ascii_case("quic"))
    }

    fn read_quic_ech_mode(doc: &Value, issues: &mut Vec<Value>) -> QuicEchMode {
        let Some(exp) = doc.get("experimental") else {
            return QuicEchMode::Reject;
        };
        let Some(raw) = exp.get("quic_ech_mode") else {
            return QuicEchMode::Reject;
        };

        let Some(mode) = raw.as_str() else {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/experimental/quic_ech_mode",
                "experimental.quic_ech_mode must be a string: 'reject' or 'experimental'",
                "set experimental.quic_ech_mode to 'reject' (default) or 'experimental'",
            ));
            return QuicEchMode::Reject;
        };

        match mode.trim().to_ascii_lowercase().as_str() {
            "" | "reject" => QuicEchMode::Reject,
            "experimental" => QuicEchMode::Experimental,
            _ => {
                issues.push(emit_issue(
                    "error",
                    IssueCode::InvalidEnum,
                    "/experimental/quic_ech_mode",
                    "experimental.quic_ech_mode must be 'reject' or 'experimental'",
                    "use 'reject' for production safety; use 'experimental' only for controlled tests",
                ));
                QuicEchMode::Reject
            }
        }
    }

    let mut issues = Vec::new();
    let quic_ech_mode = read_quic_ech_mode(doc, &mut issues);

    let outbounds = match doc.get("outbounds").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return issues,
    };

    for (i, ob) in outbounds.iter().enumerate() {
        let obj = match ob.as_object() {
            Some(o) => o,
            None => continue,
        };

        let outbound_tag = obj
            .get("tag")
            .or_else(|| obj.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");

        // Check uTLS fingerprint
        if let Some(fp_val) = obj.get("utls_fingerprint").or_else(|| {
            // Also check nested tls.utls.fingerprint pattern
            obj.get("tls")
                .and_then(|t| t.get("utls"))
                .and_then(|u| u.get("fingerprint"))
        }) {
            if let Some(fp) = fp_val.as_str() {
                let fp_lower = fp.to_ascii_lowercase();
                if !fp_lower.is_empty() && fp_lower != "chrome" {
                    issues.push(emit_issue(
                        "info",
                        IssueCode::Deprecated,
                        &format!("/outbounds/{}/utls_fingerprint", i),
                        &format!(
                            "outbound '{}': uTLS fingerprint '{}' has limited support in Rust; \
                             'chrome' is the most reliable fingerprint, others may fall back to native TLS",
                            outbound_tag, fp
                        ),
                        "use 'chrome' fingerprint for best compatibility, or omit for native TLS",
                    ));
                }
            }
        }

        // Check ECH (encrypted_client_hello)
        let ech_loc = if let Some(v) = obj.get("encrypted_client_hello") {
            Some(("encrypted_client_hello", v))
        } else if let Some(v) = obj.get("tls").and_then(|t| t.get("ech")) {
            Some(("tls/ech", v))
        } else {
            obj.get("tls")
                .and_then(|t| t.get("encrypted_client_hello"))
                .map(|v| ("tls/encrypted_client_hello", v))
        };

        if let Some((ech_ptr_suffix, ech_val)) = ech_loc {
            let ech_enabled = ech_enabled(ech_val);
            if ech_enabled {
                issues.push(emit_issue(
                    "info",
                    IssueCode::Deprecated,
                    &format!("/outbounds/{}/encrypted_client_hello", i),
                    &format!(
                        "outbound '{}': Encrypted Client Hello (ECH) is behind the 'tls_ech' feature flag; \
                         without it, ECH configuration is silently ignored",
                        outbound_tag
                    ),
                    "enable the 'tls_ech' feature flag at build time for ECH support",
                ));

                if outbound_uses_quic(obj) {
                    match quic_ech_mode {
                        QuicEchMode::Reject => {
                            issues.push(emit_issue(
                                "error",
                                IssueCode::Conflict,
                                &format!("/outbounds/{}/{}", i, ech_ptr_suffix),
                                &format!(
                                    "outbound '{}': QUIC + ECH is not supported in the current Rust implementation; \
                                     configuration is rejected by default to avoid silent fallback",
                                    outbound_tag
                                ),
                                "set experimental.quic_ech_mode='experimental' only for controlled interop tests, \
                                 or use TCP-based TLS ECH outbounds",
                            ));
                        }
                        QuicEchMode::Experimental => {
                            issues.push(emit_issue(
                                "warning",
                                IssueCode::Conflict,
                                &format!("/outbounds/{}/{}", i, ech_ptr_suffix),
                                &format!(
                                    "outbound '{}': QUIC + ECH is in experimental mode; runtime behavior may fail or change and should not be treated as production-ready",
                                    outbound_tag
                                ),
                                "keep experimental scope small, capture handshake evidence, and prefer TCP+TLS ECH for production paths",
                            ));
                        }
                    }
                }
            }
        }

        // Check REALITY TLS
        let reality_enabled = obj
            .get("reality_enabled")
            .or_else(|| {
                obj.get("tls")
                    .and_then(|t| t.get("reality"))
                    .and_then(|r| r.get("enabled"))
            })
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if reality_enabled {
            issues.push(emit_issue(
                "info",
                IssueCode::Deprecated,
                &format!("/outbounds/{}/reality_enabled", i),
                &format!(
                    "outbound '{}': REALITY TLS is supported in Rust via rustls; \
                     verify public_key and short_id are correctly configured",
                    outbound_tag
                ),
                "ensure reality_public_key and reality_short_id are set correctly",
            ));
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_outbounds_not_array() {
        let doc = serde_json::json!({
            "outbounds": "not-an-array"
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("must be an array"))
            }),
            "should report outbounds must be array: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_item_not_object() {
        let doc = serde_json::json!({
            "outbounds": ["not-an-object"]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds/0"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("outbound item must be an object"))
            }),
            "should report item must be object: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_missing_type() {
        let doc = serde_json::json!({
            "outbounds": [{"name": "no-type"}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "MissingRequired"
                    && i["ptr"] == "/outbounds/0/type"
            }),
            "should report missing type: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_type_not_string() {
        let doc = serde_json::json!({
            "outbounds": [{"type": 42}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds/0/type"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("type must be a string"))
            }),
            "should report type must be string: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_tag_not_string() {
        let doc = serde_json::json!({
            "outbounds": [{"type": "direct", "tag": 123}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds/0/tag"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("tag must be a string"))
            }),
            "should report tag must be string: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_unknown_field_strict() {
        let doc = serde_json::json!({
            "outbounds": [
                {"type": "direct", "name": "d", "unknown_outbound_field": "test"}
            ]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "UnknownField"
                    && i["ptr"] == "/outbounds/0/unknown_outbound_field"
            }),
            "should report unknown field as error in strict mode: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_unknown_field_allow_unknown() {
        let doc = serde_json::json!({
            "outbounds": [
                {"type": "direct", "name": "d", "unknown_outbound_field": "test"}
            ]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, true, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "warning"
                    && i["code"] == "UnknownField"
                    && i["ptr"] == "/outbounds/0/unknown_outbound_field"
            }),
            "should report unknown field as warning in allow_unknown mode: {:?}",
            issues
        );
        // No errors
        assert!(
            !issues.iter().any(|i| i["kind"] == "error"),
            "should have no errors in allow_unknown mode: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_valid_direct() {
        let doc = serde_json::json!({
            "outbounds": [{"type": "direct", "name": "direct-out"}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.is_empty(),
            "valid direct outbound should produce no issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_absent() {
        let doc = serde_json::json!({});
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.is_empty(),
            "absent outbounds should produce no issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_no_outbounds_no_crash() {
        let doc = serde_json::json!({
            "schema_version": 2
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.is_empty(),
            "No outbounds should produce no TLS capability issues"
        );
    }

    #[test]
    fn test_tls_utls_non_chrome_fingerprint() {
        let doc = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "name": "test",
                "utls_fingerprint": "firefox"
            }]
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.iter().any(|i| {
                i["code"] == "Deprecated"
                    && i["ptr"] == "/outbounds/0/utls_fingerprint"
                    && i["kind"] == "info"
            }),
            "should warn about non-chrome utls: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_reality_enabled() {
        let doc = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "name": "test",
                "reality_enabled": true
            }]
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.iter().any(|i| {
                i["code"] == "Deprecated"
                    && i["ptr"] == "/outbounds/0/reality_enabled"
                    && i["kind"] == "info"
            }),
            "should report reality info: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_ech_quic_reject() {
        let doc = serde_json::json!({
            "outbounds": [{
                "type": "tuic",
                "name": "test",
                "tls": { "ech": { "enabled": true } }
            }]
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues
                .iter()
                .any(|i| { i["kind"] == "error" && i["code"] == "Conflict" }),
            "should block QUIC+ECH by default: {:?}",
            issues
        );
    }
}
