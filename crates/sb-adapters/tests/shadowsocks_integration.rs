#![cfg(feature = "adapter-shadowsocks")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Shadowsocks protocol integration tests
//!
//! These tests verify Shadowsocks protocol implementation including:
//! - Configuration validation
//! - AEAD encryption (AES-256-GCM, ChaCha20-Poly1305)
//! - Connector construction
//! - Outbound dial mechanics

use async_trait::async_trait;
use sb_adapters::outbound::prelude::*;
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_core::adapter::OutboundConnector as CoreOutboundConnector;
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug)]
struct MockIoConnector;

#[async_trait]
impl CoreOutboundConnector for MockIoConnector {
    async fn connect(&self, _host: &str, _port: u16) -> std::io::Result<tokio::net::TcpStream> {
        Err(std::io::Error::other(
            "connect() should not be used in detour test",
        ))
    }

    async fn connect_io(&self, host: &str, port: u16) -> std::io::Result<sb_transport::IoStream> {
        let stream = tokio::net::TcpStream::connect((host, port)).await?;
        Ok(Box::new(stream))
    }
}

fn install_mock_runtime_outbounds() {
    let mut reg = OutboundRegistry::default();
    reg.insert(
        "mock-detour".to_string(),
        OutboundImpl::Connector(Arc::new(MockIoConnector)),
    );
    sb_core::adapter::registry::install_runtime_outbounds(Arc::new(OutboundRegistryHandle::new(
        reg,
    )));
}

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_shadowsocks_config_aes256gcm() {
    // Valid AES-256-GCM configuration
    let config = ShadowsocksConfig {
        server: "127.0.0.1:8388".to_string(),
        tag: Some("test-ss".to_string()),
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(30),
        detour: None,
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(config);
    assert!(connector.is_ok(), "AES-256-GCM config should be valid");
}

#[test]
fn test_shadowsocks_config_chacha20() {
    // Valid ChaCha20-Poly1305 configuration
    let config = ShadowsocksConfig {
        server: "127.0.0.1:8388".to_string(),
        tag: None,
        method: "chacha20-ietf-poly1305".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(30),
        detour: None,
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(config);
    assert!(
        connector.is_ok(),
        "ChaCha20-Poly1305 config should be valid"
    );
}

#[test]
fn test_shadowsocks_config_chacha20_alternative() {
    // Test alternative chacha20 method name
    let config = ShadowsocksConfig {
        server: "127.0.0.1:8388".to_string(),
        tag: None,
        method: "chacha20-poly1305".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: None,
        detour: None,
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(config);
    assert!(
        connector.is_ok(),
        "chacha20-poly1305 alternative name should be valid"
    );
}

#[test]
fn test_shadowsocks_config_invalid_method() {
    // Invalid cipher method should fail
    let config = ShadowsocksConfig {
        server: "127.0.0.1:8388".to_string(),
        tag: None,
        method: "invalid-cipher".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: None,
        detour: None,
        multiplex: None,
    };

    let connector = ShadowsocksConnector::new(config);
    assert!(connector.is_err(), "Invalid cipher method should fail");
}

#[test]
fn test_shadowsocks_with_config() {
    // Test the convenience constructor
    let connector =
        ShadowsocksConnector::with_config("127.0.0.1:8388", "aes-256-gcm", "test_password");
    assert!(connector.is_ok(), "with_config should succeed");
}

#[test]
fn test_shadowsocks_with_config_invalid_method() {
    // Test with invalid method
    let connector =
        ShadowsocksConnector::with_config("127.0.0.1:8388", "invalid-method", "test_password");
    assert!(connector.is_err(), "Invalid method should fail");
}

#[test]
fn test_shadowsocks_default_connector() {
    // Default connector should be constructible
    let connector = ShadowsocksConnector::default();
    assert_eq!(connector.name(), "shadowsocks");
}

// ============================================================================
// Trait Implementation Tests
// ============================================================================

#[test]
fn test_shadowsocks_connector_name() {
    let connector = ShadowsocksConnector::default();
    assert_eq!(
        connector.name(),
        "shadowsocks",
        "Connector name should be 'shadowsocks'"
    );
}

#[test]
fn test_shadowsocks_implements_outbound_connector() {
    // Verify the connector implements OutboundConnector trait
    fn assert_outbound_connector<T: OutboundConnector>() {}
    assert_outbound_connector::<ShadowsocksConnector>();
}

#[test]
fn test_shadowsocks_implements_debug_clone() {
    // Verify Debug and Clone are implemented
    let connector = ShadowsocksConnector::default();
    let _debug = format!("{:?}", connector);
    let _cloned = connector.clone();
}

// ============================================================================
// Async Tests
// ============================================================================

#[tokio::test]
async fn test_shadowsocks_connector_start() {
    let connector = ShadowsocksConnector::default();
    let result = connector.start().await;
    assert!(result.is_ok(), "Connector start should succeed");
}

#[tokio::test]
#[ignore] // Network behavior varies - may succeed immediately on some systems
async fn test_shadowsocks_connection_timeout() {
    // Use a non-routable IP to trigger timeout
    let config = ShadowsocksConfig {
        server: "10.255.255.1:8388".to_string(), // Non-routable IP
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(1), // 1 second timeout
        detour: None,
        multiplex: None,
    };
    let connector = ShadowsocksConnector::new(config).unwrap();

    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_millis(100));

    let start = std::time::Instant::now();
    let result = connector.dial(target, opts).await;
    let elapsed = start.elapsed();

    // Should fail due to timeout
    assert!(result.is_err(), "Connection to non-routable IP should fail");

    // Should respect timeout (with some margin for processing)
    assert!(
        elapsed < Duration::from_secs(5),
        "Should respect timeout, took {:?}",
        elapsed
    );
}

// ============================================================================
// Mock Server Connection Test
// ============================================================================

/// Test that Shadowsocks connector can connect to a mock server
/// The mock server doesn't implement full SS protocol, but verifies:
/// 1. TCP connection is established
/// 2. Connector sends some data (salt + encrypted payload)
#[tokio::test]
async fn test_shadowsocks_connector_dial_mock() {
    // Start mock server
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!("skipping shadowsocks dial mock test: PermissionDenied binding listener");
            return;
        }
        Err(err) => panic!("failed to bind mock listener: {err}"),
    };
    let server_addr = listener.local_addr().unwrap();

    // Spawn mock server that performs a minimal SS handshake:
    // 1) read client salt + first encrypted chunk
    // 2) send server salt back (aes-256-gcm => 32 bytes)
    // 3) read one more encrypted chunk (target address payload)
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut buf = [0u8; 256];
        let n1 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n1 == 0 {
            return false;
        }

        let server_salt = [7u8; 32];
        if stream.write_all(&server_salt).await.is_err() {
            return false;
        }

        let n2 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        n2 > 0
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Create connector
    let config = ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: None,
        multiplex: None,
    };
    let connector = ShadowsocksConnector::new(config).unwrap();

    // Dial
    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));

    let dial_result = connector.dial(target, opts).await;

    // Dial should succeed (connection established + handshake sent)
    assert!(
        dial_result.is_ok(),
        "Dial should succeed: {:?}",
        dial_result.err()
    );

    // Server should have received data
    let server_received_data = server_handle.await.unwrap();
    assert!(
        server_received_data,
        "Server should have received SS handshake data"
    );
}

#[tokio::test]
async fn test_shadowsocks_connector_dial_via_detour_mock() {
    install_mock_runtime_outbounds();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut buf = [0u8; 256];
        let n1 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n1 == 0 {
            return false;
        }

        let server_salt = [7u8; 32];
        if stream.write_all(&server_salt).await.is_err() {
            return false;
        }

        let n2 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        n2 > 0
    });

    let config = ShadowsocksConfig {
        server: server_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: Some("mock-detour".to_string()),
        multiplex: None,
    };
    let connector = ShadowsocksConnector::new(config).unwrap();

    let target = Target::tcp("example.com", 80);
    let opts = DialOpts::new().with_connect_timeout(Duration::from_secs(5));
    let dial_result = connector.dial(target, opts).await;

    assert!(
        dial_result.is_ok(),
        "Dial through detour should succeed: {:?}",
        dial_result.err()
    );

    let server_received_data = server_handle.await.unwrap();
    assert!(
        server_received_data,
        "Server should have received SS handshake data through detour"
    );
}

#[tokio::test]
async fn test_shadowsocks_detour_rejects_multiplex() {
    let config = ShadowsocksConfig {
        server: "127.0.0.1:8388".to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: Some("mock-detour".to_string()),
        multiplex: Some(sb_transport::multiplex::MultiplexConfig::default()),
    };
    let connector = ShadowsocksConnector::new(config).unwrap();

    let err = match connector
        .dial(Target::tcp("example.com", 80), DialOpts::new())
        .await
    {
        Ok(_) => panic!("detour + multiplex should fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("does not support multiplex"));
}

#[tokio::test]
async fn test_shadowsocks_dial_tcp_only() {
    let connector = ShadowsocksConnector::default();

    // Attempt UDP dial should fail (Shadowsocks outbound only supports TCP via dial)
    let target = Target::udp("example.com", 53);
    let opts = DialOpts::new();

    let result = connector.dial(target, opts).await;
    assert!(result.is_err(), "UDP target should fail for TCP-only dial");
}
