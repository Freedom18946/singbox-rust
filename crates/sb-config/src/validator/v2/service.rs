use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use super::{
    emit_issue, extract_listable_strings, extract_string_list, insert_keys, object_keys,
    parse_fwmark_field, parse_inbound_tls_options, parse_listable, parse_u16_field,
};
use crate::ir::{
    ConfigIR, DerpMeshPeerIR, DerpStunOptionsIR, DerpVerifyClientUrlIR, InboundTlsOptionsIR,
    Listable, StringOrObj,
};

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

// ---------------------------------------------------------------------------
// Service lowering: raw JSON → ServiceIR
// ---------------------------------------------------------------------------

/// Lower `/services` from raw JSON into `ConfigIR.services`.
///
/// This is the service lowering owner. `to_ir_v1()` delegates here via
/// `service::lower_services(doc, &mut ir)`.
pub(crate) fn lower_services(doc: &Value, ir: &mut ConfigIR) {
    let Some(services) = doc.get("services").and_then(|v| v.as_array()) else {
        return;
    };

    for s in services {
        let ty_str = s.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let ty = match ty_str {
            "resolved" => crate::ir::ServiceType::Resolved,
            "ssm-api" | "ssmapi" => crate::ir::ServiceType::Ssmapi,
            "derp" => crate::ir::ServiceType::Derp,
            _ => continue,
        };

        let mut service_ir = crate::ir::ServiceIR {
            ty,
            tag: s
                .get("tag")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            ..Default::default()
        };

        let legacy_listen_key = match ty {
            crate::ir::ServiceType::Resolved => "resolved_listen",
            crate::ir::ServiceType::Ssmapi => "ssmapi_listen",
            crate::ir::ServiceType::Derp => "derp_listen",
        };
        let legacy_listen_port_key = match ty {
            crate::ir::ServiceType::Resolved => "resolved_listen_port",
            crate::ir::ServiceType::Ssmapi => "ssmapi_listen_port",
            crate::ir::ServiceType::Derp => "derp_listen_port",
        };

        service_ir.listen = s
            .get("listen")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                s.get(legacy_listen_key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });
        service_ir.listen_port = parse_u16_field(s.get("listen_port")).or_else(|| {
            parse_u16_field(s.get(legacy_listen_port_key)).or_else(|| {
                s.get(legacy_listen_port_key)
                    .and_then(|v| v.as_u64())
                    .map(|x| x as u16)
            })
        });
        service_ir.bind_interface = s
            .get("bind_interface")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        service_ir.routing_mark = parse_fwmark_field(s.get("routing_mark"));
        service_ir.reuse_addr = s.get("reuse_addr").and_then(|v| v.as_bool());
        service_ir.netns = s
            .get("netns")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        service_ir.tcp_fast_open = s.get("tcp_fast_open").and_then(|v| v.as_bool());
        service_ir.tcp_multi_path = s.get("tcp_multi_path").and_then(|v| v.as_bool());
        service_ir.udp_fragment = s.get("udp_fragment").and_then(|v| v.as_bool());
        service_ir.udp_timeout = s
            .get("udp_timeout")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        service_ir.detour = s
            .get("detour")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        service_ir.sniff = s.get("sniff").and_then(|v| v.as_bool());
        service_ir.sniff_override_destination =
            s.get("sniff_override_destination").and_then(|v| v.as_bool());
        service_ir.sniff_timeout = s
            .get("sniff_timeout")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        service_ir.domain_strategy = s
            .get("domain_strategy")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        service_ir.udp_disable_domain_unmapping =
            s.get("udp_disable_domain_unmapping").and_then(|v| v.as_bool());

        service_ir.tls = parse_inbound_tls_options(s.get("tls"));

        // Legacy TLS path fields (Rust-only schema) -> Go-style `tls`.
        match ty {
            crate::ir::ServiceType::Ssmapi => {
                lower_ssmapi_fields(s, &mut service_ir);
            }
            crate::ir::ServiceType::Derp => {
                lower_derp_fields(s, &mut service_ir);
            }
            crate::ir::ServiceType::Resolved => {
                // Resolved service has only Listen Fields; defaults applied at runtime.
            }
        }

        ir.services.push(service_ir);
    }
}

fn lower_ssmapi_fields(s: &Value, service_ir: &mut crate::ir::ServiceIR) {
    let legacy_cert = s
        .get("ssmapi_tls_cert_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let legacy_key = s
        .get("ssmapi_tls_key_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if (legacy_cert.is_some() || legacy_key.is_some()) && service_ir.tls.is_none() {
        service_ir.tls = Some(InboundTlsOptionsIR {
            enabled: true,
            certificate_path: legacy_cert,
            key_path: legacy_key,
            ..Default::default()
        });
    }
    if let Some(cache) = s
        .get("cache_path")
        .or_else(|| s.get("ssmapi_cache_path"))
        .and_then(|v| v.as_str())
    {
        service_ir.cache_path = Some(cache.to_string());
    }
    if let Some(servers) = s.get("servers").and_then(|v| v.as_object()) {
        let mut map = std::collections::HashMap::new();
        for (k, v) in servers {
            if let Some(tag) = v.as_str() {
                map.insert(k.to_string(), tag.to_string());
            }
        }
        if !map.is_empty() {
            service_ir.servers = Some(map);
        }
    }
}

fn lower_derp_fields(s: &Value, service_ir: &mut crate::ir::ServiceIR) {
    let legacy_cert = s
        .get("derp_tls_cert_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let legacy_key = s
        .get("derp_tls_key_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if (legacy_cert.is_some() || legacy_key.is_some()) && service_ir.tls.is_none() {
        service_ir.tls = Some(InboundTlsOptionsIR {
            enabled: true,
            certificate_path: legacy_cert,
            key_path: legacy_key,
            ..Default::default()
        });
    }

    service_ir.config_path = s
        .get("config_path")
        .or_else(|| s.get("derp_config_path"))
        .or_else(|| s.get("derp_server_key_path"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    service_ir.verify_client_endpoint = extract_listable_strings(
        s.get("verify_client_endpoint")
            .or_else(|| s.get("derp_verify_client_endpoint")),
    );
    service_ir.verify_client_url = parse_derp_verify_client_urls(
        s.get("verify_client_url")
            .or_else(|| s.get("derp_verify_client_url")),
    );
    service_ir.home = s
        .get("home")
        .or_else(|| s.get("derp_home"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    service_ir.mesh_psk = s
        .get("mesh_psk")
        .or_else(|| s.get("derp_mesh_psk"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    service_ir.mesh_psk_file = s
        .get("mesh_psk_file")
        .or_else(|| s.get("derp_mesh_psk_file"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    service_ir.mesh_with =
        parse_derp_mesh_with(s.get("mesh_with").or_else(|| s.get("derp_mesh_with")));
    service_ir.stun = parse_derp_stun_options(s.get("stun")).or_else(|| {
        let enabled = s.get("derp_stun_enabled").and_then(|v| v.as_bool());
        let port = parse_u16_field(s.get("derp_stun_listen_port"));
        if enabled.is_none() && port.is_none() {
            return None;
        }
        Some(DerpStunOptionsIR {
            enabled: enabled.unwrap_or(true),
            listen: None,
            listen_port: port,
            ..Default::default()
        })
    });
}

// ---------------------------------------------------------------------------
// Service-only helpers (migrated from mod.rs)
// ---------------------------------------------------------------------------

fn parse_derp_verify_client_urls(
    value: Option<&Value>,
) -> Option<Listable<StringOrObj<DerpVerifyClientUrlIR>>> {
    if let Some(parsed) = parse_listable::<StringOrObj<DerpVerifyClientUrlIR>>(value) {
        return Some(parsed);
    }
    // Legacy fallback: keep accepting strings/arrays of strings.
    extract_string_list(value).map(|items| Listable {
        items: items
            .into_iter()
            .map(|s| StringOrObj(DerpVerifyClientUrlIR::from(s)))
            .collect(),
    })
}

fn parse_derp_mesh_with(value: Option<&Value>) -> Option<Listable<StringOrObj<DerpMeshPeerIR>>> {
    if let Some(parsed) = parse_listable::<StringOrObj<DerpMeshPeerIR>>(value) {
        return Some(parsed);
    }

    // Legacy fallback: accept strings and array entries as strings; also accept object
    // entries with `server` + optional `server_port`, and convert to the string shorthand.
    let value = value?;
    let mut out: Vec<StringOrObj<DerpMeshPeerIR>> = Vec::new();
    match value {
        Value::String(s) => {
            let s = s.trim();
            if !s.is_empty() {
                out.push(StringOrObj(DerpMeshPeerIR::from(s.to_string())));
            }
        }
        Value::Array(arr) => {
            for item in arr {
                match item {
                    Value::String(s) => {
                        let s = s.trim();
                        if !s.is_empty() {
                            out.push(StringOrObj(DerpMeshPeerIR::from(s.to_string())));
                        }
                    }
                    Value::Object(obj) => {
                        let server = obj.get("server").and_then(|v| v.as_str()).map(str::trim);
                        let port = parse_u16_field(obj.get("server_port"));
                        if let Some(server) = server {
                            if server.is_empty() {
                                continue;
                            }
                            let shorthand = if let Some(port) = port {
                                format!("{server}:{port}")
                            } else {
                                server.to_string()
                            };
                            out.push(StringOrObj(DerpMeshPeerIR::from(shorthand)));
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    if out.is_empty() {
        None
    } else {
        Some(Listable { items: out })
    }
}

fn parse_derp_stun_options(value: Option<&Value>) -> Option<DerpStunOptionsIR> {
    let value = value?;
    match value {
        Value::Number(num) => {
            let port = num.as_u64().and_then(|v| u16::try_from(v).ok())?;
            Some(DerpStunOptionsIR {
                enabled: true,
                listen: None,
                listen_port: Some(port),
                ..Default::default()
            })
        }
        Value::Bool(enabled) => Some(DerpStunOptionsIR {
            enabled: *enabled,
            ..Default::default()
        }),
        Value::Object(obj) => Some(DerpStunOptionsIR {
            enabled: obj
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            listen: obj
                .get("listen")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            listen_port: parse_u16_field(obj.get("listen_port")),
            bind_interface: obj
                .get("bind_interface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            routing_mark: parse_fwmark_field(obj.get("routing_mark")),
            reuse_addr: obj.get("reuse_addr").and_then(|v| v.as_bool()),
            netns: obj
                .get("netns")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }),
        _ => None,
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

    fn lower(doc: &Value) -> ConfigIR {
        let mut ir = ConfigIR::default();
        lower_services(doc, &mut ir);
        ir
    }

    // -----------------------------------------------------------------------
    // Validation tests (existing)
    // -----------------------------------------------------------------------

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

    #[test]
    fn no_services_no_issues() {
        let doc = json!({"outbounds": []});
        let issues = run_validate(&doc, false);
        assert!(
            issues.is_empty(),
            "expected no service issues when services is absent"
        );
    }

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

    // -----------------------------------------------------------------------
    // Lowering tests (WP-30w)
    // -----------------------------------------------------------------------

    #[test]
    fn wp30w_type_resolved_mapping() {
        let doc = json!({"services": [{"type": "resolved", "tag": "r"}]});
        let ir = lower(&doc);
        assert_eq!(ir.services.len(), 1);
        assert_eq!(ir.services[0].ty, crate::ir::ServiceType::Resolved);
        assert_eq!(ir.services[0].tag.as_deref(), Some("r"));
    }

    #[test]
    fn wp30w_type_ssmapi_mapping() {
        let doc = json!({"services": [{"type": "ssm-api", "tag": "s1"}, {"type": "ssmapi", "tag": "s2"}]});
        let ir = lower(&doc);
        assert_eq!(ir.services.len(), 2);
        assert_eq!(ir.services[0].ty, crate::ir::ServiceType::Ssmapi);
        assert_eq!(ir.services[1].ty, crate::ir::ServiceType::Ssmapi);
    }

    #[test]
    fn wp30w_type_derp_mapping() {
        let doc = json!({"services": [{"type": "derp", "tag": "d"}]});
        let ir = lower(&doc);
        assert_eq!(ir.services.len(), 1);
        assert_eq!(ir.services[0].ty, crate::ir::ServiceType::Derp);
    }

    #[test]
    fn wp30w_unknown_type_skipped() {
        let doc = json!({"services": [{"type": "unknown_type", "tag": "u"}]});
        let ir = lower(&doc);
        assert!(ir.services.is_empty(), "unknown service type should be skipped");
    }

    #[test]
    fn wp30w_legacy_resolved_listen_alias() {
        let doc = json!({"services": [{"type": "resolved", "resolved_listen": "1.2.3.4", "resolved_listen_port": 53}]});
        let ir = lower(&doc);
        assert_eq!(ir.services[0].listen.as_deref(), Some("1.2.3.4"));
        assert_eq!(ir.services[0].listen_port, Some(53));
    }

    #[test]
    fn wp30w_legacy_ssmapi_listen_alias() {
        let doc = json!({"services": [{"type": "ssmapi", "ssmapi_listen": "0.0.0.0", "ssmapi_listen_port": 8080}]});
        let ir = lower(&doc);
        assert_eq!(ir.services[0].listen.as_deref(), Some("0.0.0.0"));
        assert_eq!(ir.services[0].listen_port, Some(8080));
    }

    #[test]
    fn wp30w_legacy_derp_listen_alias() {
        let doc = json!({"services": [{"type": "derp", "derp_listen": "127.0.0.1", "derp_listen_port": 443}]});
        let ir = lower(&doc);
        assert_eq!(ir.services[0].listen.as_deref(), Some("127.0.0.1"));
        assert_eq!(ir.services[0].listen_port, Some(443));
    }

    #[test]
    fn wp30w_listen_takes_precedence_over_legacy() {
        let doc = json!({"services": [{"type": "resolved", "listen": "10.0.0.1", "resolved_listen": "1.2.3.4", "listen_port": 80, "resolved_listen_port": 53}]});
        let ir = lower(&doc);
        assert_eq!(ir.services[0].listen.as_deref(), Some("10.0.0.1"));
        assert_eq!(ir.services[0].listen_port, Some(80));
    }

    #[test]
    fn wp30w_common_fields_lowering() {
        let doc = json!({"services": [{
            "type": "resolved",
            "tag": "test",
            "bind_interface": "eth0",
            "routing_mark": 100,
            "reuse_addr": true,
            "netns": "ns1",
            "tcp_fast_open": true,
            "tcp_multi_path": false,
            "udp_fragment": true,
            "udp_timeout": "5m",
            "detour": "proxy-out",
            "sniff": true,
            "sniff_override_destination": false,
            "sniff_timeout": "300ms",
            "domain_strategy": "prefer_ipv4",
            "udp_disable_domain_unmapping": true
        }]});
        let ir = lower(&doc);
        let svc = &ir.services[0];
        assert_eq!(svc.bind_interface.as_deref(), Some("eth0"));
        assert_eq!(svc.routing_mark, Some(100));
        assert_eq!(svc.reuse_addr, Some(true));
        assert_eq!(svc.netns.as_deref(), Some("ns1"));
        assert_eq!(svc.tcp_fast_open, Some(true));
        assert_eq!(svc.tcp_multi_path, Some(false));
        assert_eq!(svc.udp_fragment, Some(true));
        assert_eq!(svc.udp_timeout.as_deref(), Some("5m"));
        assert_eq!(svc.detour.as_deref(), Some("proxy-out"));
        assert_eq!(svc.sniff, Some(true));
        assert_eq!(svc.sniff_override_destination, Some(false));
        assert_eq!(svc.sniff_timeout.as_deref(), Some("300ms"));
        assert_eq!(svc.domain_strategy.as_deref(), Some("prefer_ipv4"));
        assert_eq!(svc.udp_disable_domain_unmapping, Some(true));
    }

    #[test]
    fn wp30w_tls_lowering() {
        let doc = json!({"services": [{
            "type": "ssmapi",
            "tls": {
                "enabled": true,
                "server_name": "example.com",
                "certificate_path": "/cert.pem",
                "key_path": "/key.pem"
            }
        }]});
        let ir = lower(&doc);
        let tls = ir.services[0].tls.as_ref().expect("tls should be Some");
        assert!(tls.enabled);
        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
        assert_eq!(tls.certificate_path.as_deref(), Some("/cert.pem"));
        assert_eq!(tls.key_path.as_deref(), Some("/key.pem"));
    }

    #[test]
    fn wp30w_ssmapi_legacy_tls_paths() {
        let doc = json!({"services": [{
            "type": "ssmapi",
            "ssmapi_tls_cert_path": "/legacy-cert.pem",
            "ssmapi_tls_key_path": "/legacy-key.pem"
        }]});
        let ir = lower(&doc);
        let tls = ir.services[0].tls.as_ref().expect("legacy tls should produce tls");
        assert!(tls.enabled);
        assert_eq!(tls.certificate_path.as_deref(), Some("/legacy-cert.pem"));
        assert_eq!(tls.key_path.as_deref(), Some("/legacy-key.pem"));
    }

    #[test]
    fn wp30w_ssmapi_explicit_tls_overrides_legacy() {
        let doc = json!({"services": [{
            "type": "ssmapi",
            "tls": {"enabled": true, "certificate_path": "/explicit.pem", "key_path": "/explicit-key.pem"},
            "ssmapi_tls_cert_path": "/legacy.pem"
        }]});
        let ir = lower(&doc);
        let tls = ir.services[0].tls.as_ref().unwrap();
        assert_eq!(tls.certificate_path.as_deref(), Some("/explicit.pem"),
            "explicit tls should override legacy tls paths");
    }

    #[test]
    fn wp30w_ssmapi_cache_path() {
        let doc = json!({"services": [{"type": "ssmapi", "cache_path": "/cache"}]});
        let ir = lower(&doc);
        assert_eq!(ir.services[0].cache_path.as_deref(), Some("/cache"));

        let doc2 = json!({"services": [{"type": "ssmapi", "ssmapi_cache_path": "/legacy-cache"}]});
        let ir2 = lower(&doc2);
        assert_eq!(ir2.services[0].cache_path.as_deref(), Some("/legacy-cache"));
    }

    #[test]
    fn wp30w_ssmapi_servers() {
        let doc = json!({"services": [{
            "type": "ssmapi",
            "servers": {"dns1": "my-dns", "dns2": "my-dns-2"}
        }]});
        let ir = lower(&doc);
        let servers = ir.services[0].servers.as_ref().expect("servers should be Some");
        assert_eq!(servers.get("dns1").map(|s| s.as_str()), Some("my-dns"));
        assert_eq!(servers.get("dns2").map(|s| s.as_str()), Some("my-dns-2"));
    }

    #[test]
    fn wp30w_derp_legacy_tls_paths() {
        let doc = json!({"services": [{
            "type": "derp",
            "derp_tls_cert_path": "/derp-cert.pem",
            "derp_tls_key_path": "/derp-key.pem"
        }]});
        let ir = lower(&doc);
        let tls = ir.services[0].tls.as_ref().expect("derp legacy tls should produce tls");
        assert!(tls.enabled);
        assert_eq!(tls.certificate_path.as_deref(), Some("/derp-cert.pem"));
    }

    #[test]
    fn wp30w_derp_config_path_and_legacy_aliases() {
        // config_path takes precedence
        let doc = json!({"services": [{"type": "derp", "config_path": "/c1"}]});
        assert_eq!(lower(&doc).services[0].config_path.as_deref(), Some("/c1"));

        // derp_config_path alias
        let doc2 = json!({"services": [{"type": "derp", "derp_config_path": "/c2"}]});
        assert_eq!(lower(&doc2).services[0].config_path.as_deref(), Some("/c2"));

        // derp_server_key_path alias
        let doc3 = json!({"services": [{"type": "derp", "derp_server_key_path": "/c3"}]});
        assert_eq!(lower(&doc3).services[0].config_path.as_deref(), Some("/c3"));
    }

    #[test]
    fn wp30w_derp_verify_client_endpoint() {
        let doc = json!({"services": [{
            "type": "derp",
            "derp_verify_client_endpoint": ["ep1", "ep2"]
        }]});
        let ir = lower(&doc);
        let vce = ir.services[0].verify_client_endpoint.as_ref().unwrap();
        assert_eq!(vce.items.len(), 2);
    }

    #[test]
    fn wp30w_derp_home_and_mesh_psk() {
        let doc = json!({"services": [{
            "type": "derp",
            "derp_home": "/home",
            "derp_mesh_psk": "secret",
            "derp_mesh_psk_file": "/psk-file"
        }]});
        let ir = lower(&doc);
        let svc = &ir.services[0];
        assert_eq!(svc.home.as_deref(), Some("/home"));
        assert_eq!(svc.mesh_psk.as_deref(), Some("secret"));
        assert_eq!(svc.mesh_psk_file.as_deref(), Some("/psk-file"));
    }

    #[test]
    fn wp30w_derp_mesh_with_legacy_strings() {
        let doc = json!({"services": [{
            "type": "derp",
            "derp_mesh_with": ["peer1:443", "peer2:8443"]
        }]});
        let ir = lower(&doc);
        let mw = ir.services[0].mesh_with.as_ref().expect("mesh_with should be Some");
        assert_eq!(mw.items.len(), 2);
    }

    #[test]
    fn wp30w_derp_stun_object() {
        let doc = json!({"services": [{
            "type": "derp",
            "stun": {"enabled": true, "listen_port": 3478}
        }]});
        let ir = lower(&doc);
        let stun = ir.services[0].stun.as_ref().expect("stun should be Some");
        assert!(stun.enabled);
        assert_eq!(stun.listen_port, Some(3478));
    }

    #[test]
    fn wp30w_derp_stun_legacy_fields() {
        let doc = json!({"services": [{
            "type": "derp",
            "derp_stun_enabled": true,
            "derp_stun_listen_port": 3479
        }]});
        let ir = lower(&doc);
        let stun = ir.services[0].stun.as_ref().expect("legacy stun should produce stun");
        assert!(stun.enabled);
        assert_eq!(stun.listen_port, Some(3479));
    }

    #[test]
    fn wp30w_no_services_no_ir() {
        let doc = json!({"outbounds": []});
        let ir = lower(&doc);
        assert!(ir.services.is_empty());
    }

    #[test]
    fn wp30w_multiple_services() {
        let doc = json!({"services": [
            {"type": "resolved", "tag": "r1"},
            {"type": "ssmapi", "tag": "s1"},
            {"type": "derp", "tag": "d1"}
        ]});
        let ir = lower(&doc);
        assert_eq!(ir.services.len(), 3);
        assert_eq!(ir.services[0].ty, crate::ir::ServiceType::Resolved);
        assert_eq!(ir.services[1].ty, crate::ir::ServiceType::Ssmapi);
        assert_eq!(ir.services[2].ty, crate::ir::ServiceType::Derp);
    }

    // -----------------------------------------------------------------------
    // Ownership pins (WP-30w)
    // -----------------------------------------------------------------------

    #[test]
    fn wp30w_pin_service_lowering_owner_is_service_rs() {
        // Pin: service lowering owner is in validator/v2/service.rs.
        // This test exists in service.rs itself, proving the owner is here.
        // lower_services is the entry point called by to_ir_v1().
        let doc = json!({"services": [{"type": "resolved", "tag": "pin-test"}]});
        let ir = lower(&doc);
        assert_eq!(ir.services.len(), 1, "lower_services must be callable from service.rs");
    }

    #[test]
    fn wp30w_pin_mod_rs_to_ir_v1_delegates_service() {
        // Pin: to_ir_v1() delegates service lowering to service::lower_services.
        // Verified by calling to_ir_v1() and confirming services are populated.
        let doc = json!({
            "schema_version": 2,
            "services": [{"type": "resolved", "tag": "via-delegate", "listen": "127.0.0.1", "listen_port": 53}]
        });
        let ir = super::super::to_ir_v1(&doc);
        assert_eq!(ir.services.len(), 1);
        assert_eq!(ir.services[0].tag.as_deref(), Some("via-delegate"));
        assert_eq!(ir.services[0].listen.as_deref(), Some("127.0.0.1"));
        assert_eq!(ir.services[0].listen_port, Some(53));
    }
}
