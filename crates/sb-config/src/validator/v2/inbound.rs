use crate::ir::{ConfigIR, Credentials, InboundType};
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

/// Parse `host:port` or `[ipv6]:port` from a listen string.
fn parse_listen_host_port(listen: &str) -> Option<(String, u16)> {
    if let Some(stripped) = listen.strip_prefix('[') {
        let close = stripped.find(']')?;
        let host = &stripped[..close];
        let rest = &stripped[close + 1..];
        let port_str = rest.strip_prefix(':')?;
        let port = port_str.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port_str) = listen.rsplit_once(':')?;
    let port = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

/// Lower `/inbounds` from raw JSON into `ConfigIR.inbounds`.
///
/// This is the inbound lowering owner — all inbound-specific field parsing
/// and IR population lives here. `to_ir_v1()` in mod.rs delegates to this.
pub(crate) fn lower_inbounds(doc: &Value, ir: &mut ConfigIR) {
    let Some(ins) = doc.get("inbounds").and_then(|v| v.as_array()) else {
        return;
    };
    for i in ins {
        let ty = match i.get("type").and_then(|v| v.as_str()).unwrap_or("socks") {
            "socks" => InboundType::Socks,
            "http" => InboundType::Http,
            "tun" => InboundType::Tun,
            "mixed" => InboundType::Mixed,
            "redirect" => InboundType::Redirect,
            "tproxy" => InboundType::Tproxy,
            "direct" => InboundType::Direct,
            "dns" => InboundType::Dns,
            "ssh" => InboundType::Ssh,
            _ => InboundType::Socks,
        };
        // Common fields
        let mut listen = i
            .get("listen")
            .and_then(|v| v.as_str())
            .unwrap_or("127.0.0.1")
            .to_string();
        let mut port = i
            .get("listen_port")
            .or_else(|| i.get("port"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok());
        if port.is_none() {
            if let Some((host, parsed_port)) = parse_listen_host_port(&listen) {
                listen = host;
                port = Some(parsed_port);
            }
        }
        let port = port.unwrap_or(1080);
        let sniff = i.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false);
        let sniff_override_destination = i
            .get("sniff_override_destination")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Network selection: if network == "udp", set udp=true; if "tcp" or missing, false
        let udp = if let Some(net) = i.get("network").and_then(|v| v.as_str()) {
            net.eq_ignore_ascii_case("udp")
        } else {
            i.get("udp").and_then(|v| v.as_bool()).unwrap_or(false)
        };
        let basic_auth = i.get("basicAuth").map(|a| Credentials {
            username: a
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            password: a
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            username_env: a
                .get("username_env")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            password_env: a
                .get("password_env")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });

        // Direct-only fields
        let (override_host, override_port) = if matches!(ty, InboundType::Direct) {
            let host = i
                .get("override_address")
                .or_else(|| i.get("override_host"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let port = i
                .get("override_port")
                .and_then(|v| v.as_u64())
                .map(|x| x as u16);
            (host, port)
        } else {
            (None, None)
        };

        ir.inbounds.push(crate::ir::InboundIR {
            tag: i.get("tag").and_then(|v| v.as_str()).map(|s| s.to_string()),
            ty,
            listen,
            port,
            sniff,
            sniff_override_destination,
            udp,
            udp_timeout: i
                .get("udp_timeout")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            detour: i
                .get("detour")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            domain_strategy: i
                .get("domain_strategy")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            set_system_proxy: i
                .get("set_system_proxy")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            allow_private_network: i
                .get("allow_private_network")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            basic_auth,
            override_host,
            override_port,
            users: i.get("users").and_then(|v| {
                v.as_array().and_then(|arr| {
                    let users: Vec<_> = arr
                        .iter()
                        .filter_map(|u| {
                            let name = u
                                .get("username")
                                .or_else(|| u.get("name"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let pass = u
                                .get("password")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            if name.is_some() || pass.is_some() {
                                Some(crate::ir::Credentials {
                                    username: name,
                                    password: pass,
                                    username_env: None,
                                    password_env: None,
                                })
                            } else {
                                None
                            }
                        })
                        .collect();
                    if users.is_empty() {
                        None
                    } else {
                        Some(users)
                    }
                })
            }),
            // Protocol-specific fields (all default to None)
            method: None,
            password: None,
            users_shadowsocks: None,
            network: None,
            uuid: None,
            alter_id: None,
            users_vmess: None,
            flow: i
                .get("flow")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            users_vless: None,
            users_trojan: None,
            version: None,
            users_shadowtls: None,
            shadowtls_handshake: None,
            shadowtls_handshake_for_server_name: None,
            shadowtls_strict_mode: None,
            shadowtls_wildcard_sni: None,
            fallback: i
                .get("fallback")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            fallback_for_alpn: i.get("fallback_for_alpn").and_then(|v| {
                v.as_object().map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
            }),
            users_anytls: None,
            anytls_padding: None,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            grpc_service: None,
            tls_enabled: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name: None,
            tls_alpn: None,
            users_hysteria2: None,
            congestion_control: None,
            salamander: None,
            obfs: None,
            brutal_up_mbps: None,
            brutal_down_mbps: None,
            users_tuic: None,
            users_hysteria: None,
            hysteria_protocol: None,
            hysteria_obfs: None,
            hysteria_up_mbps: None,
            hysteria_down_mbps: None,
            hysteria_recv_window_conn: None,
            hysteria_recv_window: None,
            masquerade: None,
            multiplex: None,
            security: i
                .get("security")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tun: None,
            ssh_host_key_path: i
                .get("ssh_host_key_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        });
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

    // ========================================================================
    // WP-30u: Inbound lowering tests
    // ========================================================================

    fn lower(doc: &Value) -> ConfigIR {
        let mut ir = ConfigIR::default();
        lower_inbounds(doc, &mut ir);
        ir
    }

    // --- type mapping ---

    #[test]
    fn lowering_type_mapping() {
        let types = [
            ("socks", InboundType::Socks),
            ("http", InboundType::Http),
            ("tun", InboundType::Tun),
            ("mixed", InboundType::Mixed),
            ("redirect", InboundType::Redirect),
            ("tproxy", InboundType::Tproxy),
            ("direct", InboundType::Direct),
            ("dns", InboundType::Dns),
            ("ssh", InboundType::Ssh),
            ("unknown_type", InboundType::Socks), // fallback
        ];
        for (type_str, expected) in types {
            let doc = json!({"inbounds": [{"type": type_str, "listen": "0.0.0.0"}]});
            let ir = lower(&doc);
            assert_eq!(
                ir.inbounds[0].ty, expected,
                "type '{}' should map to {:?}",
                type_str, expected
            );
        }
    }

    #[test]
    fn lowering_missing_type_defaults_to_socks() {
        let doc = json!({"inbounds": [{"listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].ty, InboundType::Socks);
    }

    // --- listen_port / port / listen host:port priority ---

    #[test]
    fn lowering_listen_port_priority() {
        // listen_port takes precedence over port
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "listen_port": 8080, "port": 9090}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].port, 8080);
    }

    #[test]
    fn lowering_port_fallback() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "port": 9090}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].port, 9090);
    }

    #[test]
    fn lowering_listen_host_port_parsing() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0:3000"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].listen, "0.0.0.0");
        assert_eq!(ir.inbounds[0].port, 3000);
    }

    #[test]
    fn lowering_listen_ipv6_host_port() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "[::1]:4000"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].listen, "::1");
        assert_eq!(ir.inbounds[0].port, 4000);
    }

    #[test]
    fn lowering_default_port_1080() {
        let doc = json!({"inbounds": [{"type": "socks", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].port, 1080);
    }

    // --- direct-only override fields ---

    #[test]
    fn lowering_direct_writes_override() {
        let doc = json!({"inbounds": [{
            "type": "direct", "listen": "0.0.0.0",
            "override_address": "10.0.0.1", "override_port": 443
        }]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].override_host.as_deref(), Some("10.0.0.1"));
        assert_eq!(ir.inbounds[0].override_port, Some(443));
    }

    #[test]
    fn lowering_non_direct_no_override() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "override_address": "10.0.0.1", "override_port": 443
        }]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].override_host.is_none());
        assert!(ir.inbounds[0].override_port.is_none());
    }

    #[test]
    fn lowering_direct_override_host_alias() {
        // override_host is an alias for override_address (with override_address taking precedence)
        let doc = json!({"inbounds": [{
            "type": "direct", "listen": "0.0.0.0",
            "override_host": "10.0.0.2"
        }]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].override_host.as_deref(), Some("10.0.0.2"));
    }

    // --- basicAuth ---

    #[test]
    fn lowering_basic_auth() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "basicAuth": {"username": "alice", "password": "secret"}
        }]});
        let ir = lower(&doc);
        let auth = ir.inbounds[0].basic_auth.as_ref().unwrap();
        assert_eq!(auth.username.as_deref(), Some("alice"));
        assert_eq!(auth.password.as_deref(), Some("secret"));
    }

    #[test]
    fn lowering_basic_auth_env() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "basicAuth": {"username_env": "USER", "password_env": "PASS"}
        }]});
        let ir = lower(&doc);
        let auth = ir.inbounds[0].basic_auth.as_ref().unwrap();
        assert_eq!(auth.username_env.as_deref(), Some("USER"));
        assert_eq!(auth.password_env.as_deref(), Some("PASS"));
    }

    #[test]
    fn lowering_no_basic_auth() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].basic_auth.is_none());
    }

    // --- sniff / sniff_override_destination / udp ---

    #[test]
    fn lowering_sniff_defaults_false() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(!ir.inbounds[0].sniff);
        assert!(!ir.inbounds[0].sniff_override_destination);
    }

    #[test]
    fn lowering_sniff_enabled() {
        let doc = json!({"inbounds": [{
            "type": "http", "listen": "0.0.0.0",
            "sniff": true, "sniff_override_destination": true
        }]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].sniff);
        assert!(ir.inbounds[0].sniff_override_destination);
    }

    #[test]
    fn lowering_udp_via_network() {
        let doc = json!({"inbounds": [{"type": "socks", "listen": "0.0.0.0", "network": "udp"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].udp);
    }

    #[test]
    fn lowering_udp_via_flag() {
        let doc = json!({"inbounds": [{"type": "socks", "listen": "0.0.0.0", "udp": true}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].udp);
    }

    // --- set_system_proxy / allow_private_network ---

    #[test]
    fn lowering_set_system_proxy_default_false() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(!ir.inbounds[0].set_system_proxy);
    }

    #[test]
    fn lowering_set_system_proxy_true() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "set_system_proxy": true}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].set_system_proxy);
    }

    #[test]
    fn lowering_allow_private_network_default_true() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].allow_private_network);
    }

    #[test]
    fn lowering_allow_private_network_false() {
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "allow_private_network": false}]});
        let ir = lower(&doc);
        assert!(!ir.inbounds[0].allow_private_network);
    }

    // --- ssh_host_key_path ---

    #[test]
    fn lowering_ssh_host_key_path() {
        let doc = json!({"inbounds": [{
            "type": "ssh", "listen": "0.0.0.0",
            "ssh_host_key_path": "/etc/ssh/host_key"
        }]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds[0].ssh_host_key_path.as_deref(), Some("/etc/ssh/host_key"));
    }

    #[test]
    fn lowering_ssh_host_key_path_absent() {
        let doc = json!({"inbounds": [{"type": "ssh", "listen": "0.0.0.0"}]});
        let ir = lower(&doc);
        assert!(ir.inbounds[0].ssh_host_key_path.is_none());
    }

    // --- no inbounds → empty ---

    #[test]
    fn lowering_no_inbounds() {
        let doc = json!({"outbounds": []});
        let ir = lower(&doc);
        assert!(ir.inbounds.is_empty());
    }

    // --- parse_listen_host_port unit tests ---

    #[test]
    fn parse_host_port_ipv4() {
        let result = parse_listen_host_port("1.2.3.4:5000").unwrap();
        assert_eq!(result, ("1.2.3.4".to_string(), 5000));
    }

    #[test]
    fn parse_host_port_ipv6() {
        let result = parse_listen_host_port("[::1]:6000").unwrap();
        assert_eq!(result, ("::1".to_string(), 6000));
    }

    #[test]
    fn parse_host_port_no_port() {
        assert!(parse_listen_host_port("0.0.0.0").is_none());
    }

    // ========================================================================
    // WP-30u pins
    // ========================================================================

    #[test]
    fn wp30u_pin_inbound_lowering_owner_is_inbound_rs() {
        // Pin: inbound lowering (lower_inbounds) is owned by this file (inbound.rs).
        // If this compiles and runs, the owner is here.
        let doc = json!({"inbounds": [{"type": "http", "listen": "0.0.0.0", "port": 8080}]});
        let ir = lower(&doc);
        assert_eq!(ir.inbounds.len(), 1);
        assert_eq!(ir.inbounds[0].ty, InboundType::Http);
        assert_eq!(ir.inbounds[0].port, 8080);
    }

    #[test]
    fn wp30u_pin_mod_rs_to_ir_v1_delegates_inbound() {
        // Pin: to_ir_v1() delegates inbound lowering — it should produce
        // the same result as calling lower_inbounds directly.
        let doc = json!({
            "inbounds": [{"type": "mixed", "listen": "0.0.0.0", "port": 7890, "tag": "mix"}]
        });
        let ir_via_to_ir = crate::validator::v2::to_ir_v1(&doc);
        let ir_via_lower = lower(&doc);
        assert_eq!(ir_via_to_ir.inbounds.len(), ir_via_lower.inbounds.len());
        assert_eq!(ir_via_to_ir.inbounds[0].ty, ir_via_lower.inbounds[0].ty);
        assert_eq!(ir_via_to_ir.inbounds[0].port, ir_via_lower.inbounds[0].port);
        assert_eq!(ir_via_to_ir.inbounds[0].tag, ir_via_lower.inbounds[0].tag);
    }
}
