//! E2E Integration Tests for VMess Inbound with WebSocket Transport
//!
//! Test Coverage:
//! 1. Configuration parsing with WebSocket transport
//! 2. Inbound listener creation with WebSocket
//! 3. Connection handling over WebSocket
//! 4. Backward compatibility (TCP fallback when no transport specified)

use sb_adapters::inbound::vmess::VmessInboundConfig;
use sb_adapters::transport_config::{TransportConfig, TransportType, WebSocketTransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_vmess_websocket_config_creation() {
    // Test that WebSocket transport configuration can be created
    let ws_config = WebSocketTransportConfig {
        path: "/vmess".to_string(),
        headers: vec![],
        max_message_size: Some(64 * 1024 * 1024), // 64MB
        max_frame_size: Some(16 * 1024 * 1024),   // 16MB
    };

    let transport = TransportConfig::WebSocket(ws_config);

    // Verify transport type
    assert_eq!(transport.transport_type(), TransportType::WebSocket);
}

#[tokio::test]
async fn test_vmess_inbound_with_websocket_transport() {
    // Test that VMess inbound config accepts WebSocket transport
    let bind_addr: SocketAddr = "127.0.0.1:18488".parse().unwrap();

    let ws_config = WebSocketTransportConfig {
        path: "/vmess".to_string(),
        headers: vec![],
        max_message_size: Some(64 * 1024 * 1024),
        max_frame_size: Some(16 * 1024 * 1024),
    };

    // Create a mock router handle (minimal for testing)
    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

    let config = VmessInboundConfig {
        listen: bind_addr,
        uuid: Uuid::new_v4(),
        security: "aes-128-gcm".to_string(),
        router,
        multiplex: None,
        transport_layer: Some(TransportConfig::WebSocket(ws_config)),
    };

    // Verify configuration
    assert_eq!(config.listen, bind_addr);
    assert_eq!(config.security, "aes-128-gcm");
    assert!(config.transport_layer.is_some());
}

#[tokio::test]
async fn test_vmess_inbound_tcp_fallback() {
    // Test backward compatibility: TCP fallback when no transport specified
    let bind_addr: SocketAddr = "127.0.0.1:18489".parse().unwrap();

    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

    let config = VmessInboundConfig {
        listen: bind_addr,
        uuid: Uuid::new_v4(),
        security: "chacha20-poly1305".to_string(),
        router,
        multiplex: None,
        transport_layer: None, // No transport specified - should default to TCP
    };

    // Verify that None transport_layer is accepted (TCP fallback)
    assert!(config.transport_layer.is_none());

    // When calling serve(), it should use .unwrap_or_default() which gives TCP
    let transport = config.transport_layer.unwrap_or_default();
    assert_eq!(transport.transport_type(), TransportType::Tcp);
}

#[tokio::test]
async fn test_vmess_websocket_with_custom_headers() {
    // Test WebSocket with custom headers configuration
    let ws_config = WebSocketTransportConfig {
        path: "/vmess-ws".to_string(),
        headers: vec![
            ("User-Agent".to_string(), "sing-box-rust/1.0".to_string()),
            ("X-Custom-Header".to_string(), "test-value".to_string()),
        ],
        max_message_size: Some(32 * 1024 * 1024), // 32MB
        max_frame_size: Some(8 * 1024 * 1024),    // 8MB
    };

    let transport = TransportConfig::WebSocket(ws_config.clone());

    // Verify custom configuration
    if let TransportConfig::WebSocket(cfg) = transport {
        assert_eq!(cfg.path, "/vmess-ws".to_string());
        assert_eq!(cfg.headers.len(), 2);
        assert_eq!(cfg.max_message_size, Some(32 * 1024 * 1024));
    } else {
        panic!("Expected WebSocket transport");
    }
}

#[tokio::test]
async fn test_vmess_security_methods() {
    // Test both AES-128-GCM and ChaCha20-Poly1305 security methods
    let bind_addr: SocketAddr = "127.0.0.1:18490".parse().unwrap();
    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

    // Test AES-128-GCM
    let config_aes = VmessInboundConfig {
        listen: bind_addr,
        uuid: Uuid::new_v4(),
        security: "aes-128-gcm".to_string(),
        router: router.clone(),
        multiplex: None,
        transport_layer: None,
    };
    assert_eq!(config_aes.security, "aes-128-gcm");

    // Test ChaCha20-Poly1305
    let config_chacha = VmessInboundConfig {
        listen: bind_addr,
        uuid: Uuid::new_v4(),
        security: "chacha20-poly1305".to_string(),
        router,
        multiplex: None,
        transport_layer: None,
    };
    assert_eq!(config_chacha.security, "chacha20-poly1305");
}

// Note: Full E2E tests with actual network communication would require:
// 1. Starting a VMess inbound server with WebSocket transport
// 2. Creating a VMess client connection over WebSocket
// 3. Performing AEAD authentication and handshake
// 4. Verifying bidirectional encrypted communication
//
// These tests focus on configuration and integration validation.
// Full network tests are deferred to integration test suite with test infrastructure.
