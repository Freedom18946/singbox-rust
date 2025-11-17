//! Hysteria v1 outbound adapter registration and instantiation tests

use sb_adapters::register_all;
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::{registry, OutboundParam};

/// Test that Hysteria v1 outbound can be instantiated with minimal config
#[test]
fn test_hysteria_outbound_registration() {
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Hysteria,
        name: Some("hysteria-out".to_string()),
        server: Some("example.com".to_string()),
        port: Some(443),
        hysteria_protocol: Some("udp".to_string()),
        up_mbps: Some(10),
        down_mbps: Some(50),
        hysteria_auth: Some("test-password".to_string()),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "hysteria".to_string(),
        name: Some("hysteria-out".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("hysteria");
    assert!(
        builder.is_some(),
        "Hysteria v1 builder should be registered"
    );

    let result = builder.unwrap()(&param, &ir);
    assert!(
        result.is_some(),
        "Hysteria v1 outbound should be registered and buildable"
    );
}

/// Test Hysteria v1 with obfuscation
#[test]
fn test_hysteria_with_obfuscation() {
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Hysteria,
        name: Some("hysteria-obfs".to_string()),
        server: Some("proxy.example.com".to_string()),
        port: Some(8443),
        hysteria_protocol: Some("wechat-video".to_string()),
        up_mbps: Some(20),
        down_mbps: Some(100),
        hysteria_auth: Some("secure-password".to_string()),
        obfs: Some("obfuscation-key".to_string()),
        skip_cert_verify: Some(true),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "hysteria".to_string(),
        name: Some("hysteria-obfs".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("hysteria");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir);
    assert!(
        result.is_some(),
        "Hysteria v1 with obfuscation should build"
    );
}

/// Test Hysteria v1 with custom QUIC windows
#[test]
fn test_hysteria_with_quic_windows() {
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Hysteria,
        name: Some("hysteria-quic".to_string()),
        server: Some("quic.example.com".to_string()),
        port: Some(443),
        hysteria_protocol: Some("udp".to_string()),
        up_mbps: Some(50),
        down_mbps: Some(200),
        hysteria_auth: Some("auth-token".to_string()),
        hysteria_recv_window_conn: Some(15728640), // 15 MB
        hysteria_recv_window: Some(67108864),      // 64 MB
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "hysteria".to_string(),
        name: Some("hysteria-quic".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("hysteria");
    let result = builder.unwrap()(&param, &ir);
    assert!(
        result.is_some(),
        "Hysteria v1 with QUIC windows should build"
    );
}

/// Test Hysteria v1 with ALPN and SNI
#[test]
fn test_hysteria_with_alpn_sni() {
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Hysteria,
        name: Some("hysteria-tls".to_string()),
        server: Some("tls.example.com".to_string()),
        port: Some(443),
        hysteria_protocol: Some("faketcp".to_string()),
        up_mbps: Some(30),
        down_mbps: Some(150),
        hysteria_auth: Some("password123".to_string()),
        tls_alpn: Some(vec!["hysteria".to_string(), "h3".to_string()]),
        tls_sni: Some("custom-sni.example.com".to_string()),
        skip_cert_verify: Some(false),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "hysteria".to_string(),
        name: Some("hysteria-tls".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("hysteria");
    let result = builder.unwrap()(&param, &ir);
    assert!(
        result.is_some(),
        "Hysteria v1 with ALPN and SNI should build"
    );
}

/// Test Hysteria v1 defaults when optional fields are missing
#[test]
fn test_hysteria_with_defaults() {
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Hysteria,
        name: Some("hysteria-defaults".to_string()),
        server: Some("default.example.com".to_string()),
        port: Some(443),
        // No protocol, auth, up/down_mbps - should use defaults
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "hysteria".to_string(),
        name: Some("hysteria-defaults".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("hysteria");
    let result = builder.unwrap()(&param, &ir);
    assert!(
        result.is_some(),
        "Hysteria v1 should build with default values"
    );
}

/// Test Hysteria v1 using password field as fallback for auth
#[test]
fn test_hysteria_with_password_fallback() {
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Hysteria,
        name: Some("hysteria-pwd".to_string()),
        server: Some("pwd.example.com".to_string()),
        port: Some(443),
        password: Some("fallback-password".to_string()), // Using password field
        up_mbps: Some(15),
        down_mbps: Some(75),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "hysteria".to_string(),
        name: Some("hysteria-pwd".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("hysteria");
    let result = builder.unwrap()(&param, &ir);
    assert!(
        result.is_some(),
        "Hysteria v1 should accept password as auth fallback"
    );
}
