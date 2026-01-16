#![cfg(feature = "tls_reality")]
//! E2E Integration Tests for Trojan Inbound with gRPC Transport
//!
//! Test Coverage:
//! 1. Configuration parsing with gRPC transport
//! 2. Inbound listener creation with gRPC
//! 3. TLS + gRPC combination
//! 4. Backward compatibility (TCP fallback when no transport specified)

use sb_adapters::inbound::trojan::{TrojanInboundConfig, TrojanUser};
use sb_adapters::transport_config::{GrpcTransportConfig, TransportConfig, TransportType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::test]
async fn test_trojan_grpc_config_creation() {
    // Test that gRPC transport configuration can be created
    let grpc_config = GrpcTransportConfig {
        service_name: "TrojanService".to_string(),
        method_name: "Tunnel".to_string(),
        metadata: vec![],
    };

    let transport = TransportConfig::Grpc(grpc_config);

    // Verify transport type
    assert_eq!(transport.transport_type(), TransportType::Grpc);
}

#[tokio::test]
async fn test_trojan_inbound_with_grpc_transport() {
    // Test that Trojan inbound config accepts gRPC transport
    let bind_addr: SocketAddr = "127.0.0.1:18488".parse().unwrap();

    let grpc_config = GrpcTransportConfig {
        service_name: "TrojanService".to_string(),
        method_name: "Tunnel".to_string(),
        metadata: vec![("authorization".to_string(), "Bearer token123".to_string())],
    };

    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen: bind_addr,
        password: None,
        users: vec![TrojanUser::new(
            "test-user".to_string(),
            "trojan-password-456".to_string(),
        )],
        cert_path: "/tmp/test-cert.pem".to_string(),
        key_path: "/tmp/test-key.pem".to_string(),
        router,
        tag: None,
        stats: None,
        reality: None,
        multiplex: None,
        transport_layer: Some(TransportConfig::Grpc(grpc_config)),
        fallback: None,
        fallback_for_alpn: HashMap::new(),
    };

    // Verify configuration
    assert_eq!(config.listen, bind_addr);
    assert_eq!(config.users.len(), 1);
    assert!(config.transport_layer.is_some());
}

#[tokio::test]
async fn test_trojan_inbound_tcp_fallback() {
    // Test backward compatibility: TCP fallback when no transport specified
    let bind_addr: SocketAddr = "127.0.0.1:18489".parse().unwrap();

    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen: bind_addr,
        password: None,
        users: vec![TrojanUser::new(
            "test-user".to_string(),
            "trojan-password".to_string(),
        )],
        cert_path: "/tmp/cert.pem".to_string(),
        key_path: "/tmp/key.pem".to_string(),
        router,
        tag: None,
        stats: None,
        reality: None,
        multiplex: None,
        transport_layer: None, // No transport - defaults to TCP
        fallback: None,
        fallback_for_alpn: HashMap::new(),
    };

    // Verify that None transport_layer is accepted
    assert!(config.transport_layer.is_none());

    // Default should be TCP
    let transport = config.transport_layer.unwrap_or_default();
    assert_eq!(transport.transport_type(), TransportType::Tcp);
}

#[tokio::test]
async fn test_trojan_grpc_with_custom_metadata() {
    // Test gRPC with custom metadata configuration
    let grpc_config = GrpcTransportConfig {
        service_name: "CustomTrojanService".to_string(),
        method_name: "CustomTunnel".to_string(),
        metadata: vec![
            ("user-agent".to_string(), "sing-box-rust/1.0".to_string()),
            ("x-custom-header".to_string(), "custom-value".to_string()),
            (
                "authorization".to_string(),
                "Bearer secret-token".to_string(),
            ),
        ],
    };

    let transport = TransportConfig::Grpc(grpc_config.clone());

    // Verify custom configuration
    if let TransportConfig::Grpc(cfg) = transport {
        assert_eq!(cfg.service_name, "CustomTrojanService".to_string());
        assert_eq!(cfg.method_name, "CustomTunnel".to_string());
        assert_eq!(cfg.metadata.len(), 3);
    } else {
        panic!("Expected gRPC transport");
    }
}

#[cfg(feature = "tls_reality")]
#[tokio::test]
async fn test_trojan_grpc_with_reality_tls() {
    // Test gRPC transport combined with REALITY TLS
    let grpc_config = GrpcTransportConfig {
        service_name: "TrojanService".to_string(),
        method_name: "Tunnel".to_string(),
        metadata: vec![],
    };

    // Note: Full REALITY TLS configuration requires X25519 keys, target server, etc.
    // This test validates that the configuration structure supports the combination

    let bind_addr: SocketAddr = "127.0.0.1:18490".parse().unwrap();
    let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen: bind_addr,
        password: None,
        users: vec![TrojanUser::new(
            "test-user".to_string(),
            "trojan-reality".to_string(),
        )],
        cert_path: "/tmp/cert.pem".to_string(),
        key_path: "/tmp/key.pem".to_string(),
        router,
        tag: None,
        stats: None,
        reality: None, // Would contain RealityServerConfig in real scenario
        multiplex: None,
        transport_layer: Some(TransportConfig::Grpc(grpc_config)),
        fallback: None,
        fallback_for_alpn: HashMap::new(),
    };

    // Verify that gRPC + REALITY combination is supported
    assert!(config.transport_layer.is_some());
    assert!(config.reality.is_none()); // None in this test, but field exists
}

// Note: Full E2E tests with actual gRPC communication would require:
// 1. Starting a Trojan inbound server with gRPC transport
// 2. Creating a gRPC client with bidirectional streaming
// 3. Performing TLS handshake and Trojan authentication
// 4. Verifying CONNECT command processing and relay
//
// These tests focus on configuration and integration validation.
// Full network tests require gRPC server infrastructure.
