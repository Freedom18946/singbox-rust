//! AnyTLS outbound adapter registration and instantiation tests

use sb_adapters::register_all;
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::{registry, Bridge, OutboundParam};
use sb_core::context::{Context, ContextRegistry};
use std::sync::Arc;

fn ctx() -> registry::AdapterOutboundContext {
    registry::AdapterOutboundContext {
        bridge: Arc::new(Bridge::new(Context::new())),
        context: ContextRegistry::from(&Context::new()),
    }
}

// Initialize rustls crypto provider
fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Test that AnyTLS outbound can be instantiated with minimal config
#[test]
fn test_anytls_outbound_registration() {
    init_crypto();
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-out".to_string()),
        server: Some("example.com".to_string()),
        port: Some(443),
        password: Some("test-password".to_string()),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "anytls".to_string(),
        name: Some("anytls-out".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("anytls");
    assert!(builder.is_some(), "AnyTLS builder should be registered");

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(
        result.is_some(),
        "AnyTLS outbound should be registered and buildable"
    );
}

/// Test AnyTLS with custom padding scheme
#[test]
fn test_anytls_with_padding() {
    init_crypto();
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-padded".to_string()),
        server: Some("proxy.example.com".to_string()),
        port: Some(8443),
        password: Some("secure-password".to_string()),
        anytls_padding: Some(vec!["100-200".to_string(), "200-300".to_string()]),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "anytls".to_string(),
        name: Some("anytls-padded".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("anytls");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some(), "AnyTLS with padding should build");
}

/// Test AnyTLS with custom TLS configuration
#[test]
fn test_anytls_with_tls_config() {
    init_crypto();
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-tls".to_string()),
        server: Some("secure.example.com".to_string()),
        port: Some(443),
        password: Some("password123".to_string()),
        tls_sni: Some("sni.example.com".to_string()),
        tls_alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
        skip_cert_verify: Some(false),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "anytls".to_string(),
        name: Some("anytls-tls".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("anytls");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some(), "AnyTLS with TLS config should build");
}

/// Test AnyTLS with skip cert verify
#[test]
fn test_anytls_skip_cert_verify() {
    init_crypto();
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-insecure".to_string()),
        server: Some("test.example.com".to_string()),
        port: Some(443),
        password: Some("test-pass".to_string()),
        skip_cert_verify: Some(true),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "anytls".to_string(),
        name: Some("anytls-insecure".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("anytls");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(
        result.is_some(),
        "AnyTLS with skip_cert_verify should build"
    );
}

/// Test that AnyTLS fails gracefully with missing required fields
#[test]
fn test_anytls_missing_required_fields() {
    init_crypto();
    register_all();

    // Missing server
    let ir_no_server = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-no-server".to_string()),
        port: Some(443),
        password: Some("password".to_string()),
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "anytls".to_string(),
        name: Some("anytls-no-server".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("anytls").unwrap();
    let result = builder(&param, &ir_no_server, &ctx());
    assert!(result.is_none(), "AnyTLS should fail without server");

    // Missing password
    let ir_no_password = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-no-password".to_string()),
        server: Some("example.com".to_string()),
        port: Some(443),
        ..Default::default()
    };

    let result = builder(&param, &ir_no_password, &ctx());
    assert!(result.is_none(), "AnyTLS should fail without password");
}

/// Test AnyTLS with custom CA certificate
#[test]
fn test_anytls_with_custom_ca() {
    init_crypto();
    register_all();

    let ir = OutboundIR {
        ty: OutboundType::Anytls,
        name: Some("anytls-custom-ca".to_string()),
        server: Some("private.example.com".to_string()),
        port: Some(443),
        password: Some("secure-pass".to_string()),
        tls_ca_pem: vec![
            "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU1F/MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\nc3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\nBnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDC8+7VjvAQi/2x0eiRqN5M\n7vKlKvP8WQQS9vLCT0j6nw3TFVEiF4gfXU0qKJBqrU2WvNmDpA3K7HLxzjYqfQ+Z\nAgMBAAEwDQYJKoZIhvcNAQELBQADQQAXGkT6WqKQKxHqGkHqN3F+RFuKKqC8L/oY\nZKHZMvP9o3hVEzF6H7LZ8GzWqT0XqHqHqHqHqHqHqHqHqHqH\n-----END CERTIFICATE-----\n".to_string(),
        ],
        ..Default::default()
    };

    let param = OutboundParam {
        kind: "anytls".to_string(),
        name: Some("anytls-custom-ca".to_string()),
        ..Default::default()
    };

    let builder = registry::get_outbound("anytls");
    assert!(builder.is_some());

    let result = builder.unwrap()(&param, &ir, &ctx());
    assert!(result.is_some(), "AnyTLS with custom CA should build");
}
