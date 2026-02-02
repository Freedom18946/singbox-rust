#![cfg(feature = "adapter-vless")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! VLESS protocol integration tests
//!
//! These tests verify VLESS outbound connector implementation including:
//! - Configuration validation
//! - Flow control and encryption modes
//! - Connector construction
//! - Trait implementations

use sb_adapters::outbound::prelude::*;
use sb_adapters::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
use sb_adapters::transport_config::TransportConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use uuid::Uuid;

// ============================================================================
// FlowControl Tests
// ============================================================================

#[test]
fn test_flow_control_variants() {
    // Verify all flow control variants exist
    let _none = FlowControl::None;
    let _vision = FlowControl::XtlsRprxVision;
    let _direct = FlowControl::XtlsRprxDirect;
}

#[test]
fn test_flow_control_equality() {
    assert_eq!(FlowControl::None, FlowControl::None);
    assert_ne!(FlowControl::None, FlowControl::XtlsRprxVision);
}

#[test]
fn test_flow_control_clone_debug() {
    let flow = FlowControl::XtlsRprxVision;
    let _cloned = flow.clone();
    let _debug = format!("{:?}", flow);
}

// ============================================================================
// Encryption Tests
// ============================================================================

#[test]
fn test_encryption_variants() {
    let _none = Encryption::None;
    let _aes = Encryption::Aes128Gcm;
    let _chacha = Encryption::ChaCha20Poly1305;
}

#[test]
fn test_encryption_equality() {
    assert_eq!(Encryption::None, Encryption::None);
    assert_ne!(Encryption::None, Encryption::Aes128Gcm);
}

// ============================================================================
// VlessConfig Tests
// ============================================================================

#[test]
fn test_vless_config_default() {
    let config = VlessConfig::default();

    // Verify default values
    assert_eq!(config.server_addr, SocketAddr::from(([127, 0, 0, 1], 443)));
    assert_eq!(config.flow, FlowControl::None);
    assert_eq!(config.encryption, Encryption::None);
    assert!(config.headers.is_empty());
    assert_eq!(config.timeout, Some(30));
    assert!(!config.tcp_fast_open);
}

#[test]
fn test_vless_config_custom() {
    let uuid = Uuid::new_v4();
    let config = VlessConfig {
        server_addr: SocketAddr::from(([10, 0, 0, 1], 8443)),
        uuid,
        flow: FlowControl::XtlsRprxVision,
        encryption: Encryption::Aes128Gcm,
        headers: HashMap::from([("Host".to_string(), "example.com".to_string())]),
        timeout: Some(60),
        tcp_fast_open: true,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "transport_mux")]
        multiplex: None,
        #[cfg(feature = "tls_reality")]
        reality: None,
        #[cfg(feature = "transport_ech")]
        ech: None,
    };

    assert_eq!(config.server_addr.port(), 8443);
    assert_eq!(config.uuid, uuid);
    assert_eq!(config.flow, FlowControl::XtlsRprxVision);
    assert_eq!(config.timeout, Some(60));
}

#[test]
fn test_vless_config_with_headers() {
    let config = VlessConfig {
        headers: HashMap::from([
            ("Host".to_string(), "proxy.example.com".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ]),
        ..VlessConfig::default()
    };

    assert_eq!(config.headers.len(), 2);
    assert_eq!(
        config.headers.get("Host"),
        Some(&"proxy.example.com".to_string())
    );
}

// ============================================================================
// VlessConnector Tests
// ============================================================================

#[test]
fn test_vless_connector_new() {
    let config = VlessConfig::default();
    let connector = VlessConnector::new(config);
    assert_eq!(connector.name(), "vless");
}

#[test]
fn test_vless_connector_default() {
    let connector = VlessConnector::default();
    assert_eq!(connector.name(), "vless");
}

#[test]
fn test_vless_connector_implements_outbound_connector() {
    fn assert_outbound_connector<T: OutboundConnector>() {}
    assert_outbound_connector::<VlessConnector>();
}

#[test]
fn test_vless_connector_implements_debug_clone() {
    let connector = VlessConnector::default();
    let _debug = format!("{:?}", connector);
    let _cloned = connector.clone();
}

// ============================================================================
// Async Tests
// ============================================================================

#[tokio::test]
async fn test_vless_connector_start_with_nil_uuid() {
    // Connector with nil UUID should fail start
    let config = VlessConfig {
        uuid: Uuid::nil(),
        ..VlessConfig::default()
    };
    let connector = VlessConnector::new(config);

    let result = connector.start().await;
    assert!(result.is_err(), "Start with nil UUID should fail");
}

#[tokio::test]
async fn test_vless_connector_start_valid() {
    let connector = VlessConnector::default();
    let result = connector.start().await;
    // May succeed or warn about connectivity, but shouldn't panic
    // The result depends on network availability
    let _ = result; // Accept either success or failure
}

#[tokio::test]
async fn test_vless_dial_unreachable() {
    // Configure with non-routable IP
    let config = VlessConfig {
        server_addr: SocketAddr::from(([10, 255, 255, 1], 443)),
        timeout: Some(1), // Short timeout
        ..VlessConfig::default()
    };

    let connector = VlessConnector::new(config);
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new();

    let start = std::time::Instant::now();
    let result = connector.dial(target, opts).await;
    let elapsed = start.elapsed();

    // Should fail
    assert!(result.is_err(), "Dial to unreachable should fail");

    // Should respect timeout
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "Should respect timeout, took {:?}",
        elapsed
    );
}

// ============================================================================
// UUID Tests
// ============================================================================

#[test]
fn test_vless_uuid_generation() {
    let config = VlessConfig::default();
    // Default should have a random non-nil UUID
    assert!(!config.uuid.is_nil());
}

#[test]
fn test_vless_uuid_custom() {
    let custom_uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let config = VlessConfig {
        uuid: custom_uuid,
        ..VlessConfig::default()
    };
    assert_eq!(config.uuid, custom_uuid);
}
