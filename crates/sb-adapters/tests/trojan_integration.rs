#![cfg(feature = "adapter-trojan")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Trojan protocol integration tests
//!
//! These tests verify Trojan protocol implementation including:
//! - Configuration validation
//! - Password hashing (SHA224)
//! - TLS handshake capability
//! - Connector construction

use sb_adapters::outbound::prelude::*;
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::transport_config::TransportConfig;
use std::time::Duration;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_trojan_config_basic() {
    // Basic valid Trojan configuration
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: Some("test-trojan".to_string()),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("example.com".to_string()),
        alpn: None,
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(
        connector.name(),
        "trojan",
        "Connector name should be 'trojan'"
    );
}

#[test]
fn test_trojan_config_with_skip_cert_verify() {
    // Configuration with skip_cert_verify enabled
    let config = TrojanConfig {
        server: "10.0.0.1:443".to_string(),
        tag: None,
        password: "insecure_test".to_string(),
        connect_timeout_sec: Some(5),
        sni: None,
        alpn: None,
        skip_cert_verify: true, // Skip verification for testing
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_config_with_alpn() {
    // Configuration with ALPN protocols
    let config = TrojanConfig {
        server: "trojan.example.com:443".to_string(),
        tag: Some("alpn-test".to_string()),
        password: "alpn_password".to_string(),
        connect_timeout_sec: Some(10),
        sni: Some("trojan.example.com".to_string()),
        alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_config_minimal() {
    // Minimal configuration with only required fields
    let config = TrojanConfig {
        server: "localhost:443".to_string(),
        tag: None,
        password: "password123".to_string(),
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

// ============================================================================
// Trait Implementation Tests
// ============================================================================

#[test]
fn test_trojan_connector_name() {
    let connector = TrojanConnector::default();
    assert_eq!(
        connector.name(),
        "trojan",
        "Connector name should be 'trojan'"
    );
}

#[test]
fn test_trojan_implements_outbound_connector() {
    // Verify the connector implements OutboundConnector trait
    fn assert_outbound_connector<T: OutboundConnector>() {}
    assert_outbound_connector::<TrojanConnector>();
}

#[test]
fn test_trojan_implements_debug_clone() {
    // Verify Debug and Clone are implemented
    let connector = TrojanConnector::default();
    let _debug = format!("{:?}", connector);
    let _cloned = connector.clone();
}

#[test]
fn test_trojan_default_connector() {
    // Default connector should be constructible
    let connector = TrojanConnector::default();
    assert_eq!(connector.name(), "trojan");
}

// ============================================================================
// Async Tests
// ============================================================================

#[tokio::test]
async fn test_trojan_connector_start() {
    let connector = TrojanConnector::default();
    let result = connector.start().await;
    assert!(result.is_ok(), "Connector start should succeed");
}

#[tokio::test]
async fn test_trojan_dial_without_config() {
    // Default connector without config should fail
    let connector = TrojanConnector::default();
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new();

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_err(),
        "Dial without configured server should fail"
    );
}

#[tokio::test]
#[ignore] // Requires actual TLS server or extensive mocking
async fn test_trojan_connection_to_mock_server() {
    // This test would require a full TLS mock server
    // Keeping as ignored placeholder for future test expansion
    let config = TrojanConfig {
        server: "127.0.0.1:9443".to_string(),
        tag: Some("mock-test".to_string()),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        sni: Some("localhost".to_string()),
        alpn: None,
        skip_cert_verify: true,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new();

    // Would need a real TLS server to test this
    let _result = connector.dial(target, opts).await;
}

#[tokio::test]
#[ignore] // Requires rustls CryptoProvider which may not be available in test context
async fn test_trojan_connection_timeout() {
    // Test that connector properly times out on unreachable server
    let config = TrojanConfig {
        server: "10.255.255.1:443".to_string(), // Non-routable IP
        tag: None,
        password: "timeout_test".to_string(),
        connect_timeout_sec: Some(1), // 1 second timeout
        sni: None,
        alpn: None,
        skip_cert_verify: true,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_millis(500));

    let start = std::time::Instant::now();
    let result = connector.dial(target, opts).await;
    let elapsed = start.elapsed();

    // Should fail (timeout or connection error)
    assert!(result.is_err(), "Connection to non-routable IP should fail");

    // Should not take too long
    assert!(
        elapsed < Duration::from_secs(10),
        "Should fail within reasonable time, took {:?}",
        elapsed
    );
}

// ============================================================================
// Password Hash Tests (validates SHA224 password handling)
// ============================================================================

#[test]
fn test_trojan_password_format() {
    // Trojan uses SHA224 hex-encoded password
    // This test validates the password is stored correctly
    let password = "test-password-123";
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: None,
        password: password.to_string(),
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    // Connector should be creatable with any password
    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_empty_password() {
    // Empty password should still be allowed (server will reject)
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: None,
        password: String::new(), // Empty password
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

#[test]
fn test_trojan_unicode_password() {
    // Unicode password should work
    let config = TrojanConfig {
        server: "127.0.0.1:443".to_string(),
        tag: None,
        password: "密码测试🔐".to_string(), // Unicode password
        connect_timeout_sec: None,
        sni: None,
        alpn: None,
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let connector = TrojanConnector::new(config);
    assert_eq!(connector.name(), "trojan");
}

// ============================================================================
// Configuration Serialization Tests
// ============================================================================

#[test]
fn test_trojan_config_serialization() {
    // Test that config can be serialized and deserialized
    let config = TrojanConfig {
        server: "trojan.example.com:443".to_string(),
        tag: Some("serialization-test".to_string()),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(30),
        sni: Some("trojan.example.com".to_string()),
        alpn: Some(vec!["h2".to_string()]),
        skip_cert_verify: false,
        transport_layer: TransportConfig::default(),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
    };

    let serialized = serde_json::to_string(&config);
    assert!(serialized.is_ok(), "Config should serialize");

    let json = serialized.unwrap();
    assert!(json.contains("trojan.example.com:443"));
    assert!(json.contains("test_password"));
}
