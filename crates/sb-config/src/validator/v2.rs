use crate::ir::{ConfigIR, Credentials};
use sb_types::IssueCode;
use serde_json::{json, Value};

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

/// 解析并归一化认证字段（ENV > 明文），避免下游重复判断
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

/// 将内部错误统一转换为固定结构
pub fn emit_issue(kind: &str, code: IssueCode, ptr: &str, msg: &str, hint: &str) -> Value {
    json!({"kind": kind, "code": code.as_str(), "ptr": ptr, "msg": msg, "hint": hint})
}

/// 轻量 schema 校验（占位实现）：解析内置 schema，对照字段集做 UnknownField/TypeMismatch/MissingRequired
/// 说明：为了不引入庞大依赖，这里实现最小必要逻辑；后续可切换 jsonschema crate，保持输出结构不变。
///
/// # Arguments
/// * `doc` - 待验证的 JSON 文档
/// * `allow_unknown` - 是否将未知字段视为警告（true）而非错误（false）
pub fn validate_v2(doc: &serde_json::Value, allow_unknown: bool) -> Vec<Value> {
    let schema_text = include_str!("v2_schema.json");
    let schema: Value = match serde_json::from_str(schema_text) {
        Ok(v) => v,
        Err(_) => {
            return vec![emit_issue(
                "error",
                IssueCode::Conflict,
                "/",
                "schema load failed",
                "internal",
            )]
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
    // 2) inbounds required/type checks（节选）
    if let Some(arr) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for (i, ib) in arr.iter().enumerate() {
            // required: type (always required)
            if ib.get("type").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/inbounds/{}/type", i),
                    "missing required field",
                    "add it",
                ));
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

            // additionalProperties=false (V2 允许的字段)
            if let Some(map) = ib.as_object() {
                for k in map.keys() {
                    match k.as_str() {
                        "name" | "type" | "listen" | "udp" | "sniff" | "auth"
                        | "interface_name" | "inet4_address" | "inet6_address" | "auto_route" => {}
                        _ => {
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
    }
    issues
}

/// 打包输出
pub fn pack_output(issues: Vec<Value>) -> Value {
    json!({ "issues": issues, "fingerprint": env!("CARGO_PKG_VERSION") })
}

/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    let mut ir = crate::ir::ConfigIR::default();
    if let Some(ins) = doc.get("inbounds").and_then(|v| v.as_array()) {
        for i in ins {
            let ty = match i.get("type").and_then(|v| v.as_str()).unwrap_or("socks") {
                "socks" => crate::ir::InboundType::Socks,
                "http" => crate::ir::InboundType::Http,
                "tun" => crate::ir::InboundType::Tun,
                "direct" => crate::ir::InboundType::Direct,
                _ => crate::ir::InboundType::Socks,
            };
            // Common fields
            let listen = i
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1")
                .to_string();
            let port = i.get("port").and_then(|v| v.as_u64()).unwrap_or(1080) as u16;
            let sniff = i.get("sniff").and_then(|v| v.as_bool()).unwrap_or(false);
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
            let (override_host, override_port) = if matches!(ty, crate::ir::InboundType::Direct) {
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
                ty,
                listen,
                port,
                sniff,
                udp,
                basic_auth,
                override_host,
                override_port,
            });
        }
    }
    if let Some(outs) = doc.get("outbounds").and_then(|v| v.as_array()) {
        for o in outs {
            let ty = match o.get("type").and_then(|v| v.as_str()).unwrap_or("direct") {
                "direct" => crate::ir::OutboundType::Direct,
                "http" => crate::ir::OutboundType::Http,
                "socks" => crate::ir::OutboundType::Socks,
                "block" => crate::ir::OutboundType::Block,
                "shadowtls" => crate::ir::OutboundType::Shadowtls,
                "hysteria2" => crate::ir::OutboundType::Hysteria2,
                "vless" => crate::ir::OutboundType::Vless,
                "vmess" => crate::ir::OutboundType::Vmess,
                "trojan" => crate::ir::OutboundType::Trojan,
                "ssh" => crate::ir::OutboundType::Ssh,
                _ => crate::ir::OutboundType::Direct,
            };
            let mut ob = crate::ir::OutboundIR {
                ty,
                server: o
                    .get("server")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                port: o.get("port").and_then(|v| v.as_u64()).map(|x| x as u16),
                udp: o.get("udp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                name: o
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                members: o.get("members").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                }),
                credentials: o.get("credentials").map(|c| Credentials {
                    username: c
                        .get("username")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    password: c
                        .get("password")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    username_env: c
                        .get("username_env")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    password_env: c
                        .get("password_env")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                }),
                uuid: o
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                flow: o
                    .get("flow")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                network: o
                    .get("network")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                packet_encoding: o
                    .get("packet_encoding")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                transport: o.get("transport").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                }),
                ws_path: o
                    .get("ws_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                ws_host: o
                    .get("ws_host")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                h2_path: o
                    .get("h2_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                h2_host: o
                    .get("h2_host")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tls_sni: o
                    .get("tls_sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                tls_alpn: o
                    .get("tls_alpn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                reality_enabled: None,
                reality_public_key: None,
                reality_short_id: None,
                reality_server_name: None,
                password: o
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                ssh_private_key: None,
                ssh_private_key_path: None,
                ssh_private_key_passphrase: None,
                ssh_host_key_verification: None,
                ssh_known_hosts_path: None,
                ssh_connection_pool_size: None,
                ssh_compression: None,
                ssh_keepalive_interval: None,
                connect_timeout_sec: None,
            };

            // Fallback: allow top-level username/password for ssh/http/socks
            if ob.credentials.is_none() {
                let top_user = o
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let top_pass = o
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if top_user.is_some() || top_pass.is_some() {
                    ob.credentials = Some(Credentials {
                        username: top_user,
                        password: top_pass,
                        username_env: None,
                        password_env: None,
                    });
                }
            }

            // SSH specific optional fields
            if matches!(ob.ty, crate::ir::OutboundType::Ssh) {
                ob.ssh_private_key = o
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_private_key_path = o
                    .get("private_key_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_private_key_passphrase = o
                    .get("private_key_passphrase")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_host_key_verification =
                    o.get("host_key_verification").and_then(|v| v.as_bool());
                ob.ssh_known_hosts_path = o
                    .get("known_hosts_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.ssh_connection_pool_size = o
                    .get("connection_pool_size")
                    .and_then(|v| v.as_u64())
                    .map(|x| x as usize);
                ob.ssh_compression = o.get("compression").and_then(|v| v.as_bool());
                ob.ssh_keepalive_interval = o.get("keepalive_interval").and_then(|v| v.as_u64());
            }

            // Parse connect_timeout for all outbound types
            ob.connect_timeout_sec = o
                .get("connect_timeout")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32);

            // Backward-compat: allow nested sections `ws`, `h2`, `tls` as objects
            if let Some(ws) = o.get("ws").and_then(|v| v.as_object()) {
                if ob.ws_path.is_none() {
                    ob.ws_path = ws
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.ws_host.is_none() {
                    ob.ws_host = ws
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
            if let Some(h2) = o.get("h2").and_then(|v| v.as_object()) {
                if ob.h2_path.is_none() {
                    ob.h2_path = h2
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.h2_host.is_none() {
                    ob.h2_host = h2
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
            if let Some(tls) = o.get("tls").and_then(|v| v.as_object()) {
                if ob.tls_sni.is_none() {
                    ob.tls_sni = tls
                        .get("sni")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.tls_alpn.is_none() {
                    ob.tls_alpn = tls
                        .get("alpn")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }

                // Parse REALITY configuration
                if let Some(reality) = tls.get("reality").and_then(|v| v.as_object()) {
                    ob.reality_enabled = reality.get("enabled").and_then(|v| v.as_bool());
                    ob.reality_public_key = reality
                        .get("public_key")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    ob.reality_short_id = reality
                        .get("short_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    ob.reality_server_name = reality
                        .get("server_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }

            ir.outbounds.push(ob);
        }
    }
    if let Some(route) = doc.get("route") {
        if let Some(rules) = route.get("rules").and_then(|v| v.as_array()) {
            for rr in rules {
                let mut r = crate::ir::RuleIR::default();
                macro_rules! arrs {
                    ($k:literal, $dst:expr) => {
                        if let Some(a) = rr.get($k).and_then(|v| v.as_array()) {
                            for x in a {
                                if let Some(s) = x.as_str() {
                                    $dst.push(s.to_string());
                                }
                            }
                        }
                    };
                }
                arrs!("domain", r.domain);
                arrs!("geosite", r.geosite);
                arrs!("geoip", r.geoip);
                arrs!("ipcidr", r.ipcidr);
                arrs!("port", r.port);
                arrs!("process", r.process);
                arrs!("network", r.network);
                arrs!("protocol", r.protocol);
                arrs!("source", r.source);
                arrs!("dest", r.dest);
                arrs!("user-agent", r.user_agent);
                arrs!("not_domain", r.not_domain);
                arrs!("not_geosite", r.not_geosite);
                arrs!("not_geoip", r.not_geoip);
                arrs!("not_ipcidr", r.not_ipcidr);
                arrs!("not_port", r.not_port);
                arrs!("not_process", r.not_process);
                arrs!("not_network", r.not_network);
                arrs!("not_protocol", r.not_protocol);
                r.outbound = route
                    .get("outbound")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ir.route.rules.push(r);
            }
        }
        ir.route.default = route
            .get("default")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    normalize_credentials(&mut ir);
    ir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_reality_config() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "reality-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "short_id": "01ab",
                        "server_name": "www.apple.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        assert_eq!(outbound.name, Some("reality-out".to_string()));
        assert_eq!(outbound.reality_enabled, Some(true));
        assert_eq!(
            outbound.reality_public_key,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        assert_eq!(outbound.reality_short_id, Some("01ab".to_string()));
        assert_eq!(
            outbound.reality_server_name,
            Some("www.apple.com".to_string())
        );

        // Validate the parsed config
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_parse_reality_config_nested_tls() {
        // Test backward compatibility with nested tls object
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "reality-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "sni": "www.apple.com",
                    "alpn": "h2,http/1.1",
                    "reality": {
                        "enabled": true,
                        "public_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                        "short_id": "cdef",
                        "server_name": "www.cloudflare.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        // Check TLS fields are parsed
        assert_eq!(outbound.tls_sni, Some("www.apple.com".to_string()));
        assert_eq!(outbound.tls_alpn, Some("h2,http/1.1".to_string()));

        // Check REALITY fields are parsed
        assert_eq!(outbound.reality_enabled, Some(true));
        assert_eq!(
            outbound.reality_public_key,
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string())
        );
        assert_eq!(outbound.reality_short_id, Some("cdef".to_string()));
        assert_eq!(
            outbound.reality_server_name,
            Some("www.cloudflare.com".to_string())
        );
    }

    #[test]
    fn test_parse_reality_config_disabled() {
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "normal-vless",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "example.com",
                    "reality": {
                        "enabled": false
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        assert_eq!(outbound.reality_enabled, Some(false));
        // When disabled, validation should pass even without other fields
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_parse_reality_config_without_reality() {
        // Test that outbounds without REALITY config work normally
        let json = serde_json::json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "normal-vless",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "example.com"
                }
            }]
        });

        let ir = to_ir_v1(&json);

        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];

        assert_eq!(outbound.reality_enabled, None);
        assert_eq!(outbound.reality_public_key, None);
        assert_eq!(outbound.reality_short_id, None);
        assert_eq!(outbound.reality_server_name, None);

        // Should pass validation when REALITY is not enabled
        assert!(outbound.validate_reality().is_ok());
    }
}
