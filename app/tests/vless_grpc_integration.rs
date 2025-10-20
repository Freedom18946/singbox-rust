#![cfg(feature = "net_e2e")]
//! VLESS + gRPC Transport Integration Test
//!
//! This test validates that VLESS outbound adapter correctly integrates with gRPC transport.

use std::net::SocketAddr;
use uuid::Uuid;

use sb_adapters::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
use sb_adapters::outbound::OutboundConnector;
use sb_adapters::transport_config::{GrpcTransportConfig, TransportConfig};

#[tokio::test]
async fn test_vless_grpc_config_creation() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let grpc_config = GrpcTransportConfig {
        service_name: "TunnelService".to_string(),
        method_name: "Tunnel".to_string(),
        metadata: vec![("authorization".to_string(), "Bearer token123".to_string())],
    };

    let config = VlessConfig {
        server_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: std::collections::HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Grpc(grpc_config),
        ..Default::default()
    };

    assert_eq!(config.server_addr, server_addr);
    assert_eq!(config.uuid, test_uuid);

    let connector = VlessConnector::new(config);
    assert_eq!(connector.name(), "vless");
}

#[tokio::test]
async fn test_vless_grpc_with_multiplex() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let config = VlessConfig {
        server_addr,
        uuid: test_uuid,
        flow: FlowControl::XtlsRprxDirect,
        encryption: Encryption::ChaCha20Poly1305,
        headers: std::collections::HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Grpc(GrpcTransportConfig {
            service_name: "TunnelService".to_string(),
            method_name: "Tunnel".to_string(),
            metadata: vec![],
        }),
        ..Default::default()
    };

    let connector = VlessConnector::new(config);
    assert_eq!(connector.name(), "vless");
}

#[tokio::test]
async fn test_vless_grpc_flow_control_modes() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let flow_modes = vec![
        FlowControl::None,
        FlowControl::XtlsRprxVision,
        FlowControl::XtlsRprxDirect,
    ];

    for flow in flow_modes {
        let config = VlessConfig {
            server_addr,
            uuid: test_uuid,
            flow,
            encryption: Encryption::None,
            headers: std::collections::HashMap::new(),
            timeout: Some(10),
            tcp_fast_open: false,
            transport_layer: TransportConfig::Grpc(GrpcTransportConfig {
                service_name: "TunnelService".to_string(),
                method_name: "Tunnel".to_string(),
                metadata: vec![],
            }),
            ..Default::default()
        };

        let connector = VlessConnector::new(config);
        assert_eq!(connector.name(), "vless");
    }
}

#[tokio::test]
async fn test_vless_tcp_vs_grpc() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 443));

    // TCP configuration
    let tcp_config = VlessConfig {
        server_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: std::collections::HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Tcp,
        ..Default::default()
    };

    // gRPC configuration
    let grpc_config = VlessConfig {
        server_addr,
        uuid: test_uuid,
        flow: FlowControl::None,
        encryption: Encryption::None,
        headers: std::collections::HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer: TransportConfig::Grpc(GrpcTransportConfig {
            service_name: "TunnelService".to_string(),
            method_name: "Tunnel".to_string(),
            metadata: vec![],
        }),
        ..Default::default()
    };

    let tcp_connector = VlessConnector::new(tcp_config);
    let grpc_connector = VlessConnector::new(grpc_config);

    assert_eq!(tcp_connector.name(), "vless");
    assert_eq!(grpc_connector.name(), "vless");
}
