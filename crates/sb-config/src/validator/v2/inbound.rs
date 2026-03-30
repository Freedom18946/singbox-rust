use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, insert_keys, object_keys};

fn allowed_inbound_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::InboundIR::default());
    // ty → type in JSON
    if set.remove("ty") {
        set.insert("type".to_string());
    }
    // Raw-only / alias fields not present on InboundIR
    insert_keys(
        &mut set,
        &[
            "name",
            "listen_port",
            "override_address",
            "interface_name",
            "inet4_address",
            "inet6_address",
            "auto_route",
            "auth",
            "cert",
            "key",
            "up_mbps",
            "down_mbps",
            "tls",
        ],
    );
    set
}

/// Validate `/inbounds` array structure, types, required fields, and unknown fields.
///
/// 校验 `/inbounds` 数组结构、类型、必填字段及未知字段。
pub(crate) fn validate_inbounds(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    // /inbounds must be an array (if present)
    if let Some(inbounds_val) = doc.get("inbounds") {
        if !inbounds_val.is_array() {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/inbounds",
                "inbounds must be an array",
                "use []",
            ));
        }
    }

    let Some(arr) = doc.get("inbounds").and_then(|v| v.as_array()) else {
        return;
    };

    let allowed = allowed_inbound_keys();

    for (i, ib) in arr.iter().enumerate() {
        // Each inbound must be an object
        if !ib.is_object() {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                &format!("/inbounds/{}", i),
                "inbound item must be an object",
                "use {}",
            ));
            continue;
        }

        // required: type (always required)
        if ib.get("type").is_none() {
            issues.push(emit_issue(
                "error",
                IssueCode::MissingRequired,
                &format!("/inbounds/{}/type", i),
                "missing required field",
                "add it",
            ));
        } else if let Some(ty) = ib.get("type") {
            if !ty.is_string() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}/type", i),
                    "type must be a string",
                    "use string value",
                ));
            }
        }

        // listen is only required for non-tun inbounds
        let is_tun = ib.get("type").and_then(|v| v.as_str()) == Some("tun");
        if !is_tun && ib.get("listen").is_none() {
            issues.push(emit_issue(
                "error",
                IssueCode::MissingRequired,
                &format!("/inbounds/{}/listen", i),
                "missing required field (except for tun type)",
                "add it",
            ));
        }
        if let Some(listen_val) = ib.get("listen") {
            if !listen_val.is_string() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}/listen", i),
                    "listen must be a string",
                    "use string value",
                ));
            }
        }
        if let Some(port_val) = ib.get("port") {
            if !port_val.is_u64() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}/port", i),
                    "port must be a number",
                    "use numeric value",
                ));
            }
        }
        if let Some(port_val) = ib.get("listen_port") {
            if !port_val.is_u64() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/inbounds/{}/listen_port", i),
                    "listen_port must be a number",
                    "use numeric value",
                ));
            }
        }

        // additionalProperties=false (V2 allowed fields)
        if let Some(map) = ib.as_object() {
            for k in map.keys() {
                if !allowed.contains(k) {
                    let kind = if allow_unknown { "warning" } else { "error" };
                    issues.push(emit_issue(
                        kind,
                        IssueCode::UnknownField,
                        &format!("/inbounds/{}/{}", i, k),
                        "unknown field",
                        "remove it",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run_validate(doc: &Value, allow_unknown: bool) -> Vec<Value> {
        let mut issues = vec![];
        validate_inbounds(doc, allow_unknown, &mut issues);
        issues
    }

    // --- /inbounds non-array ---

    #[test]
    fn inbounds_not_array() {
        let doc = json!({"inbounds": "not_array"});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "inbounds must be an array"));
    }

    // --- item non-object ---

    #[test]
    fn inbound_item_not_object() {
        let doc = json!({"inbounds": ["string_item"]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "inbound item must be an object"));
    }

    // --- type missing ---

    #[test]
    fn type_missing() {
        let doc = json!({"inbounds": [{"listen": "0.0.0.0"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/type"
                && i["code"] == "MissingRequired"));
    }

    // --- type non-string ---

    #[test]
    fn type_not_string() {
        let doc = json!({"inbounds": [{"type": 42, "listen": "0.0.0.0"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/type"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "type must be a string"));
    }

    // --- non-tun missing listen ---

    #[test]
    fn non_tun_missing_listen() {
        let doc = json!({"inbounds": [{"type": "http"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/listen"
                && i["code"] == "MissingRequired"));
    }

    // --- tun does NOT require listen ---

    #[test]
    fn tun_no_listen_required() {
        let doc = json!({"inbounds": [{"type": "tun"}]});
        let issues = run_validate(&doc, false);
        assert!(
            !issues.iter().any(|i| i["ptr"] == "/inbounds/0/listen"),
            "tun inbound should not require listen"
        );
    }

    // --- listen non-string ---

    #[test]
    fn listen_not_string() {
        let doc = json!({"inbounds": [{"type": "http", "listen": 123}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/listen"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "listen must be a string"));
    }

    // --- port non-number ---

    #[test]
    fn port_not_number() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "port": "abc"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/port"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "port must be a number"));
    }

    // --- listen_port non-number ---

    #[test]
    fn listen_port_not_number() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": "abc"}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/listen_port"
                && i["code"] == "TypeMismatch"
                && i["msg"] == "listen_port must be a number"));
    }

    // --- unknown field strict → error ---

    #[test]
    fn unknown_field_strict() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "totally_unknown": true}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/totally_unknown"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    // --- unknown field allow_unknown → warning ---

    #[test]
    fn unknown_field_allow_unknown() {
        let doc =
            json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "totally_unknown": true}]});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/inbounds/0/totally_unknown"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    // --- ptr precision ---

    #[test]
    fn ptr_precision_inbound() {
        let doc = json!({
            "inbounds": [
                {"type": "http", "listen": "0.0.0.0", "field_a": 1},
                {"type": "socks", "listen": "0.0.0.0", "field_b": 2}
            ]
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/inbounds/0/field_a"),
            "missing ptr for inbounds/0 unknown field"
        );
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/inbounds/1/field_b"),
            "missing ptr for inbounds/1 unknown field"
        );
    }

    // --- no inbounds → no issues ---

    #[test]
    fn no_inbounds_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no inbound issues when inbounds is absent"
        );
    }

    // --- valid inbound passes ---

    #[test]
    fn valid_inbound_passes() {
        let doc = json!({
            "inbounds": [{"type": "http", "listen": "0.0.0.0", "port": 8080, "tag": "http-in"}]
        });
        let issues = run_validate(&doc, false);
        let errors: Vec<_> = issues.iter().filter(|i| i["kind"] == "error").collect();
        assert!(errors.is_empty(), "valid inbound should produce no errors: {:?}", errors);
    }

    // --- pin: inbound validation owner is in inbound.rs ---

    #[test]
    fn wp30t_pin_inbound_validation_owner_is_inbound_rs() {
        // This test pins that inbound schema/type/required/unknown-field validation
        // is owned by validator/v2/inbound.rs (this file), not mod.rs.
        // If this function compiles and runs, the owner is here.
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let mut issues = vec![];
        validate_inbounds(&doc, false, &mut issues);
        // No errors expected for a valid minimal inbound
        let errors: Vec<_> = issues.iter().filter(|i| i["kind"] == "error").collect();
        assert!(errors.is_empty(), "pin: validate_inbounds owns inbound validation");
    }
}
