//! Tests for parsing transport nesting (tls/ws/h2) from raw JSON into IR

use serde_json::json;

#[test]
fn parse_vmess_with_transport_ws_tls() {
    let doc = json!({
        "schema_version": 2,
        "outbounds": [
            {
                "type": "vmess",
                "name": "v",
                "server": "vmess.example.com",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": ["tls", "ws"],
                "ws": { "path": "/ws", "host": "cdn.example.com" },
                "tls": { "sni": "cdn.example.com", "alpn": "http/1.1" }
            }
        ]
    });

    let ir = sb_config::validator::v2::to_ir_v1(&doc);
    assert_eq!(ir.outbounds.len(), 1);
    let ob = &ir.outbounds[0];
    assert_eq!(ob.ty, sb_config::ir::OutboundType::Vmess);
    if let Some(tokens) = ob.transport.as_ref() {
        assert_eq!(tokens, &vec!["tls".to_string(), "ws".to_string()]);
    } else {
        panic!("expected transport tokens");
    }
    assert_eq!(ob.ws_path.as_deref(), Some("/ws"));
    assert_eq!(ob.ws_host.as_deref(), Some("cdn.example.com"));
    assert_eq!(ob.tls_sni.as_deref(), Some("cdn.example.com"));
    assert_eq!(ob.tls_alpn, Some(vec!["http/1.1".to_string()]));
}

#[test]
fn parse_vless_with_transport_h2_tls() {
    let doc = json!({
        "schema_version": 2,
        "outbounds": [
            {
                "type": "vless",
                "name": "vl",
                "server": "vless.example.com",
                "port": 8443,
                "uuid": "00000000-0000-0000-0000-000000000000",
                "transport": ["tls", "h2"],
                "h2": { "path": "/t", "host": "h2.example.com" },
                "tls": { "sni": "h2.example.com", "alpn": "h2" }
            }
        ]
    });

    let ir = sb_config::validator::v2::to_ir_v1(&doc);
    assert_eq!(ir.outbounds.len(), 1);
    let ob = &ir.outbounds[0];
    assert_eq!(ob.ty, sb_config::ir::OutboundType::Vless);
    if let Some(tokens) = ob.transport.as_ref() {
        assert_eq!(tokens, &vec!["tls".to_string(), "h2".to_string()]);
    } else {
        panic!("expected transport tokens");
    }
    assert_eq!(ob.h2_path.as_deref(), Some("/t"));
    assert_eq!(ob.h2_host.as_deref(), Some("h2.example.com"));
    assert_eq!(ob.tls_sni.as_deref(), Some("h2.example.com"));
    assert_eq!(ob.tls_alpn, Some(vec!["h2".to_string()]));
}

#[test]
fn parse_trojan_with_tls_only() {
    let doc = json!({
        "schema_version": 2,
        "outbounds": [
            {
                "type": "trojan",
                "name": "tr",
                "server": "trojan.example.com",
                "port": 443,
                "password": "secret",
                "transport": ["tls"],
                "tls": { "sni": "trojan.example.com", "alpn": "http/1.1" }
            }
        ]
    });

    let ir = sb_config::validator::v2::to_ir_v1(&doc);
    assert_eq!(ir.outbounds.len(), 1);
    let ob = &ir.outbounds[0];
    assert_eq!(ob.ty, sb_config::ir::OutboundType::Trojan);
    assert_eq!(ob.server.as_deref(), Some("trojan.example.com"));
    assert_eq!(ob.port, Some(443));
    assert_eq!(ob.password.as_deref(), Some("secret"));
    assert_eq!(ob.tls_sni.as_deref(), Some("trojan.example.com"));
    assert_eq!(ob.tls_alpn, Some(vec!["http/1.1".to_string()]));
}
