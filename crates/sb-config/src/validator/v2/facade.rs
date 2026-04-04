use serde_json::{json, Value};

use super::{
    credentials, deprecation, dns, endpoint, inbound, outbound, route, schema_core, security,
    service, top_level,
};

/// Lightweight schema validation (placeholder implementation): parses built-in schema, checks
/// against field set for UnknownField/TypeMismatch/MissingRequired.
/// Note: To avoid heavy dependencies, minimal necessary logic is implemented here; can be
/// switched to jsonschema crate later while keeping output structure unchanged.
///
/// 轻量 schema 校验（占位实现）：解析内置 schema，对照字段集做
/// UnknownField/TypeMismatch/MissingRequired。
/// 说明：为了不引入庞大依赖，这里实现最小必要逻辑；后续可切换 jsonschema crate，
/// 保持输出结构不变。
pub(super) fn validate_v2(doc: &serde_json::Value, allow_unknown: bool) -> Vec<Value> {
    let mut issues = Vec::<Value>::new();

    if !schema_core::validate_root_schema(doc, allow_unknown, &mut issues) {
        return issues;
    }

    inbound::validate_inbounds(doc, allow_unknown, &mut issues);
    outbound::validate_outbounds(doc, allow_unknown, &mut issues);
    route::validate_route(doc, allow_unknown, &mut issues);
    dns::validate_dns(doc, allow_unknown, &mut issues);
    service::validate_services(doc, allow_unknown, &mut issues);
    endpoint::validate_endpoints(doc, allow_unknown, &mut issues);

    issues.extend(deprecation::check_deprecations(doc));
    issues.extend(security::check_non_localhost_binding_warnings(doc));
    issues.extend(outbound::check_tls_capabilities(doc));
    issues
}

/// Pack output.
/// 打包输出。
pub(super) fn pack_output(issues: Vec<Value>) -> Value {
    json!({ "issues": issues, "fingerprint": env!("CARGO_PKG_VERSION") })
}

/// Convert V1/V2 raw JSON to IR (excerpt; V1 unknown fields ignored but warning optional).
/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）。
pub(super) fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    let mut ir = crate::ir::ConfigIR::default();
    inbound::lower_inbounds(doc, &mut ir);
    outbound::lower_outbounds(doc, &mut ir);
    endpoint::lower_endpoints(doc, &mut ir);
    route::lower_route(doc, &mut ir);
    top_level::lower_top_level_blocks(doc, &mut ir);
    dns::lower_dns(doc, &mut ir);
    service::lower_services(doc, &mut ir);
    credentials::normalize_credentials(&mut ir);
    ir
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ConfigIR;

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
        let issues = crate::validator::v2::validate_v2(&doc, false);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
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
    fn validate_v2_assembles_validation_facade_passes() {
        let doc = serde_json::json!({
            "schema_version": 99,
            "bogus_root": true,
            "experimental": {
                "clash_api": {
                    "external_controller": "0.0.0.0:9090"
                }
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "listen": "127.0.0.1",
                    "listen_port": 1080,
                    "bogus_inbound": true
                }
            ],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "deprecated-tag",
                    "server": "example.com",
                    "port": 443,
                    "utls_fingerprint": "safari",
                    "bogus_outbound": true
                }
            ],
            "route": {
                "bogus_route": true
            },
            "dns": {
                "bogus_dns": true,
                "servers": [
                    {
                        "tag": "dns1",
                        "address": "udp://1.1.1.1",
                        "bogus_dns_server": true
                    }
                ]
            },
            "services": [
                {
                    "type": "resolved",
                    "tag": "svc",
                    "listen": "0.0.0.0",
                    "listen_port": 53,
                    "bogus_service": true
                }
            ],
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "ep",
                    "bogus_endpoint": true,
                    "peers": [
                        {
                            "unknown_peer_field": true
                        }
                    ]
                }
            ]
        });

        let mut expected = Vec::<Value>::new();
        assert!(
            schema_core::validate_root_schema(&doc, true, &mut expected),
            "schema validation should not short-circuit on schema_version mismatch"
        );
        inbound::validate_inbounds(&doc, true, &mut expected);
        outbound::validate_outbounds(&doc, true, &mut expected);
        route::validate_route(&doc, true, &mut expected);
        dns::validate_dns(&doc, true, &mut expected);
        service::validate_services(&doc, true, &mut expected);
        endpoint::validate_endpoints(&doc, true, &mut expected);
        expected.extend(deprecation::check_deprecations(&doc));
        expected.extend(security::check_non_localhost_binding_warnings(&doc));
        expected.extend(outbound::check_tls_capabilities(&doc));

        let issues = crate::validator::v2::validate_v2(&doc, true);
        assert_eq!(
            issues, expected,
            "validate_v2 should remain a pure facade over root schema + domain validation + deprecation + security + TLS capability passes"
        );
        assert!(issues
            .iter()
            .any(|i| i["ptr"].as_str() == Some("/bogus_root")
                && i["code"].as_str() == Some("UnknownField")));
        assert!(issues
            .iter()
            .any(|i| i["ptr"].as_str() == Some("/inbounds/0/bogus_inbound")
                && i["code"].as_str() == Some("UnknownField")));
        assert!(issues
            .iter()
            .any(|i| i["ptr"].as_str() == Some("/outbounds/0/tag")
                && i["code"].as_str() == Some("Deprecated")));
        assert!(issues
            .iter()
            .any(|i| i["code"].as_str() == Some("InsecureBinding")));
        assert!(issues.iter().any(|i| {
            i["kind"].as_str() == Some("info")
                && i["ptr"]
                    .as_str()
                    .is_some_and(|p| p.contains("utls_fingerprint"))
        }));
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
        let issues = crate::validator::v2::validate_v2(&doc, true);
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
        let issues = crate::validator::v2::validate_v2(&doc, true);
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
        let issues = crate::validator::v2::validate_v2(&doc, true);
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
        let doc = serde_json::json!({
            "schema_version": 2
        });
        let issues = crate::validator::v2::check_tls_capabilities(&doc);
        assert!(
            issues.is_empty(),
            "No outbounds should produce no TLS capability issues"
        );
    }

    #[test]
    fn to_ir_v1_assembles_lowering_facade_and_credentials_normalization() {
        let username_env = "SB_WP30AF_OB_USER";
        let password_env = "SB_WP30AF_OB_PASS";
        std::env::set_var(username_env, "env-user");
        std::env::set_var(password_env, "env-pass");

        let doc = serde_json::json!({
            "schema_version": 2,
            "experimental": {
                "quic_ech_mode": "experimental"
            },
            "log": {
                "level": "debug"
            },
            "ntp": {
                "enabled": true,
                "server": "time.apple.com",
                "interval": "30m"
            },
            "certificate": {
                "ca_paths": ["/etc/custom/root.pem"]
            },
            "inbounds": [
                {
                    "type": "http",
                    "tag": "http-in",
                    "listen": "127.0.0.1",
                    "listen_port": 1080
                }
            ],
            "outbounds": [
                {
                    "type": "http",
                    "tag": "http-out",
                    "server": "proxy.example.com",
                    "port": 8080,
                    "credentials": {
                        "username_env": "SB_WP30AF_OB_USER",
                        "password_env": "SB_WP30AF_OB_PASS"
                    }
                }
            ],
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "wg-ep",
                    "address": ["10.0.0.2/32"],
                    "listen_port": 51820
                }
            ],
            "route": {
                "default": "http-out",
                "rules": [
                    {
                        "outbound": "http-out"
                    }
                ]
            },
            "dns": {
                "servers": [
                    {
                        "tag": "dns-out",
                        "address": "udp://1.1.1.1"
                    }
                ]
            },
            "services": [
                {
                    "type": "resolved",
                    "tag": "resolved-svc",
                    "listen": "127.0.0.1",
                    "listen_port": 53
                }
            ]
        });

        let mut expected = ConfigIR::default();
        inbound::lower_inbounds(&doc, &mut expected);
        outbound::lower_outbounds(&doc, &mut expected);
        endpoint::lower_endpoints(&doc, &mut expected);
        route::lower_route(&doc, &mut expected);
        top_level::lower_top_level_blocks(&doc, &mut expected);
        dns::lower_dns(&doc, &mut expected);
        service::lower_services(&doc, &mut expected);
        credentials::normalize_credentials(&mut expected);

        let ir = crate::validator::v2::to_ir_v1(&doc);
        assert_eq!(
            ir, expected,
            "to_ir_v1 should remain a pure facade over lowering owners plus credential normalization"
        );
        let creds = ir.outbounds[0]
            .credentials
            .as_ref()
            .expect("credentials should be lowered");
        assert_eq!(creds.username.as_deref(), Some("env-user"));
        assert_eq!(creds.password.as_deref(), Some("env-pass"));
        assert_eq!(ir.route.final_outbound.as_deref(), Some("http-out"));
        assert_eq!(ir.services[0].tag.as_deref(), Some("resolved-svc"));
        assert_eq!(
            ir.dns.as_ref().expect("dns should be lowered").servers[0].tag,
            "dns-out"
        );
        assert_eq!(ir.endpoints[0].tag.as_deref(), Some("wg-ep"));
        assert!(ir.experimental.is_some());
        assert!(ir.log.is_some());
        assert!(ir.ntp.is_some());
        assert!(ir.certificate.is_some());

        std::env::remove_var(username_env);
        std::env::remove_var(password_env);
    }

    #[test]
    fn pack_output_preserves_output_shape() {
        let issues = vec![serde_json::json!({
            "kind": "warning",
            "code": "Deprecated",
            "ptr": "/outbounds/0/tag",
            "msg": "deprecated",
            "hint": "use name"
        })];

        let packed = crate::validator::v2::pack_output(issues.clone());
        assert_eq!(packed["issues"], serde_json::Value::Array(issues));
        assert_eq!(
            packed["fingerprint"].as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn wp30af_pin_facade_owner_is_facade_rs() {
        let source = include_str!("facade.rs");
        assert!(
            source.contains("pub(super) fn validate_v2")
                && source.contains("pub(super) fn pack_output")
                && source.contains("pub(super) fn to_ir_v1"),
            "facade.rs must own validate_v2 / pack_output / to_ir_v1"
        );

        let mod_source = include_str!("mod.rs");
        assert!(
            mod_source.contains("mod facade;"),
            "mod.rs must wire in the facade submodule"
        );
        assert!(
            !mod_source.contains("let mut issues = Vec::<Value>::new();")
                && !mod_source.contains("let mut ir = crate::ir::ConfigIR::default();")
                && !mod_source.contains(
                    "json!({ \"issues\": issues, \"fingerprint\": env!(\"CARGO_PKG_VERSION\") })"
                ),
            "mod.rs must no longer own the facade implementation bodies"
        );
    }

    #[test]
    fn wp30af_pin_mod_rs_facade_api_is_delegate_only() {
        let mod_source = include_str!("mod.rs");
        assert!(
            mod_source.contains("facade::validate_v2(doc, allow_unknown)")
                && mod_source.contains("facade::pack_output(issues)")
                && mod_source.contains("facade::to_ir_v1(doc)"),
            "mod.rs facade API must stay as thin delegates to facade.rs"
        );
        assert!(
            mod_source.contains("pub use outbound::check_tls_capabilities;"),
            "mod.rs must keep the TLS capability re-export"
        );
    }
}
