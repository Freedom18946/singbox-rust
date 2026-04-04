//! Tests for the Raw → Validated outbound configuration boundary.
//!
//! Verifies:
//! - Unknown fields are strictly rejected (`deny_unknown_fields`)
//! - Known/valid configs still parse correctly through the Raw bridge
//! - Round-trip (serialize → deserialize) works for domain types

use sb_config::outbound::{
    HttpProxyConfig, Outbound, Socks4Config, Socks5Config, TlsConfig, TransportConfig, VlessConfig,
};

// ─────────────────── Unknown field rejection ───────────────────

#[test]
fn unknown_field_in_vless_outbound_is_rejected() {
    let json = r#"{
        "type": "vless",
        "server": "example.com",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "bogus_field": true
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("bogus_field"),
        "error should mention unknown field, got: {err}"
    );
}

#[test]
fn unknown_field_in_http_outbound_is_rejected() {
    let json = r#"{
        "type": "http",
        "server": "proxy.example.com:8080",
        "extra_nonsense": 42
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field") || err.contains("extra_nonsense"),
        "error should mention unknown field, got: {err}"
    );
}

#[test]
fn unknown_field_in_socks5_outbound_is_rejected() {
    let json = r#"{
        "type": "socks5",
        "server": "socks.example.com:1080",
        "not_a_real_field": "value"
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
}

#[test]
fn unknown_field_in_vmess_outbound_is_rejected() {
    let json = r#"{
        "type": "vmess",
        "server": "example.com:443",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "phantom_option": false
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
}

#[test]
fn unknown_field_in_direct_outbound_is_rejected() {
    let json = r#"{
        "type": "direct",
        "surprise": "nope"
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
}

#[test]
fn unknown_field_in_tuic_outbound_is_rejected() {
    let json = r#"{
        "type": "tuic",
        "server": "tuic.example.com:443",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "password": "secret",
        "invented_key": 123
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
}

#[test]
fn unknown_field_in_selector_outbound_is_rejected() {
    let json = r#"{
        "type": "selector",
        "outbounds": ["a", "b"],
        "oops": true
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
}

#[test]
fn unknown_field_in_urltest_outbound_is_rejected() {
    let json = r#"{
        "type": "urltest",
        "outbounds": ["a", "b"],
        "mystery": 7
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(result.is_err(), "unknown field should be rejected");
}

#[test]
fn unknown_field_in_nested_tls_is_rejected() {
    let json = r#"{
        "type": "vless",
        "server": "example.com",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "tls": {
            "enabled": true,
            "bad_option": "oops"
        }
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(
        result.is_err(),
        "unknown field in nested TLS should be rejected"
    );
}

#[test]
fn unknown_field_in_nested_transport_ws_is_rejected() {
    let json = r#"{
        "type": "vless",
        "server": "example.com",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "transport": {
            "type": "ws",
            "path": "/ws",
            "nonexistent": true
        }
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(
        result.is_err(),
        "unknown field in nested transport should be rejected"
    );
}

#[test]
fn unknown_field_in_nested_multiplex_is_rejected() {
    let json = r#"{
        "type": "vmess",
        "server": "example.com:443",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "multiplex": {
            "enabled": true,
            "fake_knob": 99
        }
    }"#;
    let result = serde_json::from_str::<Outbound>(json);
    assert!(
        result.is_err(),
        "unknown field in nested multiplex should be rejected"
    );
}

// ─────────────────── Known configs still parse ─────────────────

#[test]
fn known_vless_outbound_still_parses() {
    let json = r#"{
        "type": "vless",
        "server": "example.com",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "flow": "xtls-rprx-vision",
        "network": "tcp",
        "packet_encoding": "xudp",
        "connect_timeout_sec": 30
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid VLESS should parse");
    match outbound {
        Outbound::Vless(cfg) => {
            assert_eq!(cfg.server, "example.com");
            assert_eq!(cfg.uuid, "550e8400-e29b-41d4-a716-446655440000");
            assert_eq!(cfg.flow, Some("xtls-rprx-vision".to_string()));
            assert_eq!(cfg.network, "tcp");
            assert_eq!(cfg.packet_encoding, Some("xudp".to_string()));
            assert_eq!(cfg.connect_timeout_sec, Some(30));
        }
        _ => panic!("Expected Vless variant"),
    }
}

#[test]
fn known_http_outbound_still_parses() {
    let json = r#"{
        "type": "http",
        "server": "proxy.example.com:8080",
        "tag": "my-proxy",
        "username": "user",
        "password": "pass",
        "connect_timeout_sec": 15,
        "tls": {
            "enabled": true,
            "sni": "proxy.example.com",
            "insecure": false
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid HTTP should parse");
    match outbound {
        Outbound::Http(cfg) => {
            assert_eq!(cfg.server, "proxy.example.com:8080");
            assert_eq!(cfg.tag, Some("my-proxy".to_string()));
            assert_eq!(cfg.username, Some("user".to_string()));
            assert_eq!(cfg.password, Some("pass".to_string()));
            assert_eq!(cfg.connect_timeout_sec, Some(15));
            let tls = cfg.tls.unwrap();
            assert!(tls.enabled);
            assert_eq!(tls.sni, Some("proxy.example.com".to_string()));
            assert!(!tls.insecure);
        }
        _ => panic!("Expected Http variant"),
    }
}

#[test]
fn known_vmess_with_transport_and_multiplex_parses() {
    let json = r#"{
        "type": "vmess",
        "server": "vmess.example.com:443",
        "uuid": "abcdef00-1234-5678-9abc-def012345678",
        "security": "aes-128-gcm",
        "alter_id": 0,
        "transport": {
            "type": "ws",
            "path": "/vmess-ws"
        },
        "multiplex": {
            "enabled": true,
            "protocol": "yamux",
            "max_connections": 8
        }
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid VMess should parse");
    match outbound {
        Outbound::Vmess(cfg) => {
            assert_eq!(cfg.server, "vmess.example.com:443");
            assert_eq!(cfg.security, "aes-128-gcm");
            assert_eq!(cfg.alter_id, 0);
            match cfg.transport.unwrap() {
                TransportConfig::WebSocket { path, .. } => assert_eq!(path, "/vmess-ws"),
                other => panic!("Expected WebSocket transport, got {other:?}"),
            }
            let mux = cfg.multiplex.unwrap();
            assert!(mux.enabled);
            assert_eq!(mux.protocol, "yamux");
            assert_eq!(mux.max_connections, 8);
        }
        _ => panic!("Expected Vmess variant"),
    }
}

#[test]
fn known_direct_outbound_parses() {
    let json = r#"{"type": "direct", "tag": "direct-out"}"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid direct should parse");
    match outbound {
        Outbound::Direct(cfg) => assert_eq!(cfg.tag, Some("direct-out".to_string())),
        _ => panic!("Expected Direct variant"),
    }
}

#[test]
fn known_socks5_outbound_parses() {
    let json = r#"{
        "type": "socks5",
        "server": "socks.example.com:1080",
        "username": "user",
        "password": "pass"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid SOCKS5 should parse");
    match outbound {
        Outbound::Socks5(cfg) => {
            assert_eq!(cfg.server, "socks.example.com:1080");
            assert_eq!(cfg.username, Some("user".to_string()));
        }
        _ => panic!("Expected Socks5 variant"),
    }
}

#[test]
fn known_socks4_outbound_parses() {
    let json = r#"{
        "type": "socks4",
        "server": "legacy.example.com:1080",
        "user_id": "legacy_user"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid SOCKS4 should parse");
    match outbound {
        Outbound::Socks4(cfg) => {
            assert_eq!(cfg.server, "legacy.example.com:1080");
            assert_eq!(cfg.user_id, Some("legacy_user".to_string()));
        }
        _ => panic!("Expected Socks4 variant"),
    }
}

#[test]
fn known_tuic_outbound_parses() {
    let json = r#"{
        "type": "tuic",
        "server": "tuic.example.com:443",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "password": "secret",
        "congestion_control": "bbr",
        "udp_relay_mode": "native",
        "zero_rtt_handshake": true
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid TUIC should parse");
    match outbound {
        Outbound::Tuic(cfg) => {
            assert_eq!(cfg.server, "tuic.example.com:443");
            assert_eq!(cfg.congestion_control, "bbr");
            assert_eq!(cfg.udp_relay_mode, Some("native".to_string()));
            assert!(cfg.zero_rtt_handshake);
        }
        _ => panic!("Expected Tuic variant"),
    }
}

#[test]
fn known_selector_outbound_parses() {
    let json = r#"{
        "type": "selector",
        "tag": "manual",
        "outbounds": ["proxy-a", "proxy-b"],
        "default": "proxy-a"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid selector should parse");
    match outbound {
        Outbound::Selector(cfg) => {
            assert_eq!(cfg.tag, Some("manual".to_string()));
            assert_eq!(cfg.outbounds, vec!["proxy-a", "proxy-b"]);
            assert_eq!(cfg.default, Some("proxy-a".to_string()));
        }
        _ => panic!("Expected Selector variant"),
    }
}

#[test]
fn known_urltest_outbound_parses() {
    let json = r#"{
        "type": "urltest",
        "outbounds": ["proxy-a", "proxy-b"],
        "url": "http://cp.cloudflare.com/generate_204",
        "interval": 120,
        "timeout": 10,
        "tolerance": 100
    }"#;
    let outbound: Outbound = serde_json::from_str(json).expect("valid urltest should parse");
    match outbound {
        Outbound::UrlTest(cfg) => {
            assert_eq!(cfg.url, "http://cp.cloudflare.com/generate_204");
            assert_eq!(cfg.interval, 120);
            assert_eq!(cfg.timeout, 10);
            assert_eq!(cfg.tolerance, 100);
        }
        _ => panic!("Expected UrlTest variant"),
    }
}

// ──────────────── Defaults are applied correctly ────────────────

#[test]
fn vless_defaults_applied_through_raw_bridge() {
    // Minimal VLESS — defaults should fill in network="tcp"
    let json = r#"{
        "type": "vless",
        "server": "example.com",
        "uuid": "550e8400-e29b-41d4-a716-446655440000"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::Vless(cfg) => {
            assert_eq!(cfg.network, "tcp", "default network should be tcp");
            assert_eq!(cfg.flow, None);
            assert_eq!(cfg.connect_timeout_sec, None);
        }
        _ => panic!("Expected Vless variant"),
    }
}

#[test]
fn vmess_defaults_applied_through_raw_bridge() {
    let json = r#"{
        "type": "vmess",
        "server": "example.com:443",
        "uuid": "abcdef00-1234-5678-9abc-def012345678"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::Vmess(cfg) => {
            assert_eq!(cfg.security, "auto", "default security should be auto");
            assert_eq!(cfg.alter_id, 0);
            assert!(!cfg.global_padding);
        }
        _ => panic!("Expected Vmess variant"),
    }
}

#[test]
fn tuic_defaults_applied_through_raw_bridge() {
    let json = r#"{
        "type": "tuic",
        "server": "tuic.example.com:443",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "password": "secret"
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::Tuic(cfg) => {
            assert_eq!(cfg.congestion_control, "bbr");
            assert_eq!(cfg.heartbeat, 10000);
            assert!(!cfg.udp_over_stream);
            assert!(!cfg.zero_rtt_handshake);
        }
        _ => panic!("Expected Tuic variant"),
    }
}

#[test]
fn urltest_defaults_applied_through_raw_bridge() {
    let json = r#"{
        "type": "urltest",
        "outbounds": ["a"]
    }"#;
    let outbound: Outbound = serde_json::from_str(json).unwrap();
    match outbound {
        Outbound::UrlTest(cfg) => {
            assert_eq!(cfg.url, "http://www.gstatic.com/generate_204");
            assert_eq!(cfg.interval, 60);
            assert_eq!(cfg.timeout, 5);
            assert_eq!(cfg.tolerance, 50);
        }
        _ => panic!("Expected UrlTest variant"),
    }
}

// ────────────────── Serialize → Deserialize roundtrip ──────────────────

#[test]
fn validated_outbound_serialize_deserialize_roundtrip() {
    // Build a domain-type Outbound directly (as adapters do),
    // serialize it, then deserialize back through the Raw bridge.
    let original = Outbound::Vless(VlessConfig {
        server: "example.com".to_string(),
        tag: Some("vless-rt".to_string()),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        network: "tcp".to_string(),
        packet_encoding: Some("xudp".to_string()),
        connect_timeout_sec: Some(15),
        tls: Some(TlsConfig {
            enabled: true,
            sni: Some("example.com".to_string()),
            alpn: None,
            insecure: false,
            reality: None,
            ech: None,
        }),
        transport: None,
        multiplex: None,
    });

    let json = serde_json::to_string(&original).expect("serialize should succeed");
    let deserialized: Outbound = serde_json::from_str(&json).expect("deserialize should succeed");

    match (&original, &deserialized) {
        (Outbound::Vless(a), Outbound::Vless(b)) => {
            assert_eq!(a.server, b.server);
            assert_eq!(a.tag, b.tag);
            assert_eq!(a.uuid, b.uuid);
            assert_eq!(a.flow, b.flow);
            assert_eq!(a.network, b.network);
            assert_eq!(a.packet_encoding, b.packet_encoding);
            assert_eq!(a.connect_timeout_sec, b.connect_timeout_sec);
            assert_eq!(
                a.tls.as_ref().unwrap().enabled,
                b.tls.as_ref().unwrap().enabled
            );
            assert_eq!(a.tls.as_ref().unwrap().sni, b.tls.as_ref().unwrap().sni);
        }
        _ => panic!("Expected both to be Vless"),
    }
}

#[test]
fn http_outbound_roundtrip() {
    let original = Outbound::Http(HttpProxyConfig {
        server: "proxy.example.com:8080".to_string(),
        tag: Some("http-rt".to_string()),
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        connect_timeout_sec: Some(30),
        tls: None,
    });

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Outbound = serde_json::from_str(&json).unwrap();

    match (&original, &deserialized) {
        (Outbound::Http(a), Outbound::Http(b)) => {
            assert_eq!(a.server, b.server);
            assert_eq!(a.tag, b.tag);
            assert_eq!(a.username, b.username);
            assert_eq!(a.password, b.password);
            assert_eq!(a.connect_timeout_sec, b.connect_timeout_sec);
        }
        _ => panic!("Expected both to be Http"),
    }
}

// ──────────── Adapter construction compatibility ────────────

#[test]
fn adapter_style_direct_construction_works() {
    // Adapters construct domain types directly by field, not via serde.
    // This test verifies that pattern still works after the refactor.
    let _cfg = HttpProxyConfig {
        server: "proxy:8080".to_string(),
        tag: Some("test".to_string()),
        username: None,
        password: None,
        connect_timeout_sec: Some(30),
        tls: Some(TlsConfig {
            enabled: true,
            sni: Some("proxy".to_string()),
            alpn: None,
            insecure: false,
            reality: None,
            ech: None,
        }),
    };

    let _cfg2 = Socks5Config {
        server: "socks:1080".to_string(),
        tag: None,
        username: None,
        password: None,
        connect_timeout_sec: None,
        tls: None,
    };

    let _cfg3 = Socks4Config {
        server: "socks4:1080".to_string(),
        tag: None,
        user_id: None,
        connect_timeout_sec: None,
    };

    // If this compiles and runs, adapter construction is intact.
}
