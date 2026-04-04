use sb_types::IssueCode;
use serde_json::Value;

/// Returns true if the address string refers to a localhost address.
/// Empty strings are treated as localhost (will bind to loopback by default).
fn is_localhost_addr(addr: &str) -> bool {
    let host = addr.split(':').next().unwrap_or(addr);
    matches!(host, "127.0.0.1" | "::1" | "localhost" | "[::1]" | "")
}

/// Check for services and experimental.clash_api that bind to non-localhost
/// addresses without authentication configured. Emits warnings for each
/// insecure binding found.
///
/// 检查绑定到非本地地址但未配置身份验证的服务和 experimental.clash_api。
/// 为每个发现的不安全绑定发出警告。
pub fn check_non_localhost_binding_warnings(doc: &Value) -> Vec<Value> {
    let mut issues = Vec::new();

    // 1) Check experimental.clash_api.external_controller
    if let Some(clash_api) = doc
        .get("experimental")
        .and_then(|e| e.get("clash_api"))
        .and_then(|c| c.as_object())
    {
        if let Some(ext_ctrl) = clash_api
            .get("external_controller")
            .and_then(|v| v.as_str())
        {
            if !is_localhost_addr(ext_ctrl) {
                let has_secret = clash_api
                    .get("secret")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                if !has_secret {
                    issues.push(super::emit_issue(
                        "warning",
                        IssueCode::InsecureBinding,
                        "/experimental/clash_api/external_controller",
                        &format!(
                            "Clash API binds to non-localhost address '{}' without secret — accessible to the network",
                            ext_ctrl
                        ),
                        "set experimental.clash_api.secret or bind to 127.0.0.1",
                    ));
                }
            }
        }
    }

    // 2) Check each service
    if let Some(services) = doc.get("services").and_then(|v| v.as_array()) {
        for (i, svc) in services.iter().enumerate() {
            let listen = svc.get("listen").and_then(|v| v.as_str()).unwrap_or("");
            if !is_localhost_addr(listen) {
                let has_auth = svc
                    .get("auth_token")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                if !has_auth {
                    let svc_tag = svc
                        .get("tag")
                        .or_else(|| svc.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed");
                    issues.push(super::emit_issue(
                        "warning",
                        IssueCode::InsecureBinding,
                        &format!("/services/{}/listen", i),
                        &format!(
                            "service '{}' binds to non-localhost address '{}' without auth_token — accessible to the network",
                            svc_tag, listen
                        ),
                        "set auth_token or bind to 127.0.0.1",
                    ));
                }
            }
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insecure_binding_clash_api_no_secret() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "clash_api": {
                    "external_controller": "0.0.0.0:9090"
                }
            }
        });
        let issues = check_non_localhost_binding_warnings(&doc);
        let insecure: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("InsecureBinding"))
            .collect();
        assert_eq!(
            insecure.len(),
            1,
            "Expected 1 InsecureBinding warning for clash_api without secret, got: {:?}",
            insecure
        );
        assert_eq!(insecure[0]["kind"].as_str(), Some("warning"));
        assert_eq!(
            insecure[0]["ptr"].as_str(),
            Some("/experimental/clash_api/external_controller")
        );
    }

    #[test]
    fn test_secure_binding_clash_api_localhost() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "clash_api": {
                    "external_controller": "127.0.0.1:9090"
                }
            }
        });
        let issues = check_non_localhost_binding_warnings(&doc);
        let insecure: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("InsecureBinding"))
            .collect();
        assert!(
            insecure.is_empty(),
            "localhost binding should not produce InsecureBinding warning, got: {:?}",
            insecure
        );
    }

    #[test]
    fn test_secure_binding_clash_api_with_secret() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "clash_api": {
                    "external_controller": "0.0.0.0:9090",
                    "secret": "my-secret"
                }
            }
        });
        let issues = check_non_localhost_binding_warnings(&doc);
        let insecure: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("InsecureBinding"))
            .collect();
        assert!(
            insecure.is_empty(),
            "clash_api with secret should not produce InsecureBinding warning, got: {:?}",
            insecure
        );
    }

    #[test]
    fn test_insecure_binding_service_no_auth_token() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "services": [
                {
                    "type": "ssm-api",
                    "tag": "ssm",
                    "listen": "0.0.0.0",
                    "listen_port": 8080
                }
            ]
        });
        let issues = check_non_localhost_binding_warnings(&doc);
        let insecure: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("InsecureBinding"))
            .collect();
        assert_eq!(
            insecure.len(),
            1,
            "Expected 1 InsecureBinding warning for service without auth_token, got: {:?}",
            insecure
        );
        assert_eq!(insecure[0]["kind"].as_str(), Some("warning"));
        assert_eq!(insecure[0]["ptr"].as_str(), Some("/services/0/listen"));
    }

    #[test]
    fn test_secure_binding_service_with_auth_token() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "services": [
                {
                    "type": "ssm-api",
                    "tag": "ssm",
                    "listen": "0.0.0.0",
                    "listen_port": 8080,
                    "auth_token": "secret-token"
                }
            ]
        });
        let issues = check_non_localhost_binding_warnings(&doc);
        let insecure: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("InsecureBinding"))
            .collect();
        assert!(
            insecure.is_empty(),
            "service with auth_token should not produce InsecureBinding warning, got: {:?}",
            insecure
        );
    }

    // ───── WP-30ab pins ─────

    /// Pin: security warning owner is now in security.rs submodule
    #[test]
    fn wp30ab_pin_security_warning_owner_is_security_rs() {
        // check_non_localhost_binding_warnings lives in this file (validator/v2/security.rs).
        // This pin asserts that the non-localhost binding security warning logic
        // is owned by the security submodule, not by mod.rs.
        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "clash_api": {
                    "external_controller": "0.0.0.0:9090"
                }
            }
        });
        let issues = check_non_localhost_binding_warnings(&doc);
        assert!(
            issues
                .iter()
                .any(|i| i["code"].as_str() == Some("InsecureBinding")),
            "check_non_localhost_binding_warnings should produce InsecureBinding issues from security.rs"
        );
    }

    /// Pin: validate_v2() delegates security warning detection to this submodule
    #[test]
    fn wp30ab_pin_validate_v2_delegates_security_warnings() {
        // validate_v2 should include InsecureBinding warnings produced by this submodule.
        // This pin confirms that validate_v2() calls security::check_non_localhost_binding_warnings()
        // rather than implementing security warning detection inline.
        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "clash_api": {
                    "external_controller": "0.0.0.0:9090"
                }
            }
        });
        let issues = crate::validator::v2::validate_v2(&doc, true);
        let insecure: Vec<_> = issues
            .iter()
            .filter(|i| i["code"].as_str() == Some("InsecureBinding"))
            .collect();
        assert!(
            !insecure.is_empty(),
            "validate_v2 should include InsecureBinding warnings via delegation to security submodule"
        );
    }
}
