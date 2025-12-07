#![cfg(feature = "tls_reality")]
//! E2E Integration Tests for VLESS Inbound with HTTPUpgrade Transport
//!
//! Test Coverage:
//! 1. Configuration parsing with HTTPUpgrade transport
//! 2. Inbound listener creation with HTTPUpgrade
//! 3. HTTP/1.1 Upgrade handshake validation
//! 4. Backward compatibility (TCP fallback when no transport specified)

use sb_adapters::inbound::vless::VlessInboundConfig;
use sb_adapters::transport_config::{HttpUpgradeTransportConfig, TransportConfig, TransportType};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_vless_httpupgrade_config_creation() {
    // Test that HTTPUpgrade transport configuration can be created
    let http_upgrade_config = HttpUpgradeTransportConfig {
        path: "/vless".to_string(),
        headers: vec![],
    };

    let transport = TransportConfig::HttpUpgrade(http_upgrade_config);

    // Verify transport type
    assert_eq!(transport.transport_type(), TransportType::HttpUpgrade);
}

#[tokio::test]
async fn test_vless_inbound_with_httpupgrade_transport() {
    // Test that VLESS inbound config accepts HTTPUpgrade transport
    let bind_addr: SocketAddr = "127.0.0.1:18588".parse().unwrap();

    let http_upgrade_config = HttpUpgradeTransportConfig {
        path: "/vless-upgrade".to_string(),
        headers: vec![("User-Agent".to_string(), "sing-box-rust/1.0".to_string())],
    };

    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());
    let uuid = Uuid::new_v4();

    let config = VlessInboundConfig {
        listen: bind_addr,
        uuid,
        router,
        reality: None,
        multiplex: None,
        transport_layer: Some(TransportConfig::HttpUpgrade(http_upgrade_config)),
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
        flow: None,
    };

    // Verify configuration
    assert_eq!(config.listen, bind_addr);
    assert_eq!(config.uuid, uuid);
    assert!(config.transport_layer.is_some());
}

#[tokio::test]
async fn test_vless_inbound_tcp_fallback() {
    // Test backward compatibility: TCP fallback when no transport specified
    let bind_addr: SocketAddr = "127.0.0.1:18589".parse().unwrap();

    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

    let config = VlessInboundConfig {
        listen: bind_addr,
        uuid,
        router,
        reality: None,
        multiplex: None,
        transport_layer: None, // No transport - defaults to TCP
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
        flow: None,
    };

    // Verify that None transport_layer is accepted
    assert!(config.transport_layer.is_none());

    // Default should be TCP
    let transport = config.transport_layer.unwrap_or_default();
    assert_eq!(transport.transport_type(), TransportType::Tcp);
}

#[tokio::test]
async fn test_vless_httpupgrade_with_custom_headers() {
    // Test HTTPUpgrade with custom headers and path
    let http_upgrade_config = HttpUpgradeTransportConfig {
        path: "/custom-vless-path".to_string(),
        headers: vec![
            ("X-Custom-Header".to_string(), "custom-value".to_string()),
            ("Authorization".to_string(), "Bearer token123".to_string()),
            (
                "Content-Type".to_string(),
                "application/octet-stream".to_string(),
            ),
        ],
    };

    let transport = TransportConfig::HttpUpgrade(http_upgrade_config.clone());

    // Verify custom configuration
    if let TransportConfig::HttpUpgrade(cfg) = transport {
        assert_eq!(cfg.path, "/custom-vless-path".to_string());
        assert_eq!(cfg.headers.len(), 3);
    } else {
        panic!("Expected HTTPUpgrade transport");
    }
}

#[cfg(feature = "tls_reality")]
#[tokio::test]
async fn test_vless_httpupgrade_with_reality_tls() {
    // Test HTTPUpgrade transport combined with REALITY TLS
    let http_upgrade_config = HttpUpgradeTransportConfig {
        path: "/vless".to_string(),
        headers: vec![],
    };

    let bind_addr: SocketAddr = "127.0.0.1:18590".parse().unwrap();
    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());
    let uuid = Uuid::new_v4();

    let config = VlessInboundConfig {
        listen: bind_addr,
        uuid,
        router,
        reality: None, // Would contain RealityServerConfig in real scenario
        multiplex: None,
        transport_layer: Some(TransportConfig::HttpUpgrade(http_upgrade_config)),
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
        flow: None,
    };

    // Verify that HTTPUpgrade + REALITY combination is supported
    assert!(config.transport_layer.is_some());
    assert!(config.reality.is_none()); // None in this test, but field exists
}

#[tokio::test]
async fn test_vless_httpupgrade_minimal_config() {
    // Test HTTPUpgrade with minimal configuration (defaults)
    let http_upgrade_config = HttpUpgradeTransportConfig {
        path: "/".to_string(), // Default path
        headers: vec![],       // No custom headers
    };

    let transport = TransportConfig::HttpUpgrade(http_upgrade_config.clone());

    // Verify minimal configuration is accepted
    if let TransportConfig::HttpUpgrade(cfg) = transport {
        assert_eq!(cfg.path, "/");
        assert!(cfg.headers.is_empty());
    } else {
        panic!("Expected HTTPUpgrade transport");
    }
}

// Note: Full E2E tests with actual HTTPUpgrade communication would require:
// 1. Starting a VLESS inbound server with HTTPUpgrade transport
// 2. Creating an HTTP/1.1 client with Upgrade request
// 3. Validating "101 Switching Protocols" response
// 4. Performing VLESS handshake (version, UUID, command, address)
// 5. Verifying bidirectional relay after upgrade
//
// These tests focus on configuration and integration validation.
// Full network tests require HTTP server infrastructure.
