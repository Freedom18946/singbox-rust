use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{emit_issue, insert_keys, object_keys};

fn allowed_service_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::ServiceIR::default());
    insert_keys(
        &mut set,
        &[
            "resolved_listen",
            "resolved_listen_port",
            "ssmapi_listen",
            "ssmapi_listen_port",
            "derp_listen",
            "derp_listen_port",
            "ssmapi_tls_cert_path",
            "ssmapi_tls_key_path",
            "ssmapi_cache_path",
            "derp_tls_cert_path",
            "derp_tls_key_path",
            "derp_config_path",
            "derp_server_key_path",
            "derp_verify_client_endpoint",
            "derp_verify_client_url",
            "derp_home",
            "derp_mesh_psk",
            "derp_mesh_psk_file",
            "derp_mesh_with",
            "derp_stun_enabled",
            "derp_stun_listen_port",
        ],
    );
    set
}

/// Validate `/services` unknown fields.
///
/// 校验 `/services` 数组的未知字段。
pub(crate) fn validate_services(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    let Some(services) = doc.get("services").and_then(|v| v.as_array()) else {
        return;
    };

    let allowed = allowed_service_keys();
    for (i, svc) in services.iter().enumerate() {
        if let Some(map) = svc.as_object() {
            for k in map.keys() {
                if !allowed.contains(k) {
                    let kind = if allow_unknown { "warning" } else { "error" };
                    issues.push(emit_issue(
                        kind,
                        IssueCode::UnknownField,
                        &format!("/services/{}/{}", i, k),
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
        validate_services(doc, allow_unknown, &mut issues);
        issues
    }

    // 1) /services/0 unknown field, strict → error
    #[test]
    fn service_unknown_field_strict() {
        let doc = json!({"services": [{"unknown_service_field": true}]});
        let issues = run_validate(&doc, false);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/services/0/unknown_service_field"
                && i["kind"] == "error"
                && i["code"] == "UnknownField"));
    }

    // 2) /services/0 unknown field, allow_unknown → warning
    #[test]
    fn service_unknown_field_allow_unknown() {
        let doc = json!({"services": [{"unknown_service_field": true}]});
        let issues = run_validate(&doc, true);
        assert!(issues
            .iter()
            .any(|i| i["ptr"] == "/services/0/unknown_service_field"
                && i["kind"] == "warning"
                && i["code"] == "UnknownField"));
    }

    // 3) no services block → no issues
    #[test]
    fn no_services_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no service issues when services is absent"
        );
    }

    // 4) ptr precision: verify exact ptr for /services/0/unknown_service_field
    #[test]
    fn ptr_precision_service() {
        let doc = json!({
            "services": [
                {"unknown_service_field": true},
                {"another_unknown": 42}
            ]
        });
        let issues = run_validate(&doc, false);
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/services/0/unknown_service_field"),
            "missing ptr for services/0 unknown field"
        );
        assert!(
            issues
                .iter()
                .any(|i| i["ptr"] == "/services/1/another_unknown"),
            "missing ptr for services/1 unknown field"
        );
        assert_eq!(issues.len(), 2, "expected exactly 2 issues");
    }
}
