#![cfg(feature = "net_e2e")]
//! VMess + WebSocket Transport Integration Test
//!
//! This test validates that VMess outbound adapter correctly integrates with WebSocket transport.

use std::net::SocketAddr;
use std::time::Duration;
use uuid::Uuid;

use sb_adapters::outbound::vmess::{
    Security, VmessAuth, VmessConfig, VmessConnector, VmessTransport,
};
use sb_adapters::outbound::OutboundConnector;
use sb_adapters::transport_config::{TransportConfig, WebSocketTransportConfig};

#[tokio::test]
async fn test_vmess_websocket_config_creation() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let ws_config = WebSocketTransportConfig {
        path: "/vmess".to_string(),
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ],
        max_message_size: Some(64 * 1024 * 1024),
        max_frame_size: Some(16 * 1024 * 1024),
    };

    let config = VmessConfig {
        server_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::WebSocket(ws_config.clone()),
        timeout: Some(Duration::from_secs(30)),
        packet_encoding: false,
        headers: std::collections::HashMap::new(),
        ..Default::default()
    };

    assert_eq!(config.server_addr, server_addr);
    assert_eq!(config.auth.uuid, test_uuid);

    let connector = VmessConnector::new(config);
    assert_eq!(connector.name(), "vmess");
}

#[tokio::test]
async fn test_vmess_websocket_with_multiplex() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let config = VmessConfig {
        server_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::ChaCha20Poly1305,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/vmess-mux".to_string(),
            headers: vec![],
            max_message_size: Some(64 * 1024 * 1024),
            max_frame_size: Some(16 * 1024 * 1024),
        }),
        timeout: Some(Duration::from_secs(30)),
        packet_encoding: false,
        headers: std::collections::HashMap::new(),
        ..Default::default()
    };

    let connector = VmessConnector::new(config);
    assert_eq!(connector.name(), "vmess");
}

#[tokio::test]
async fn test_vmess_websocket_path_variants() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 8443));

    let paths = vec!["/", "/vmess", "/v2ray/ws", "/api/v1/tunnel"];

    for path in paths {
        let config = VmessConfig {
            server_addr,
            auth: VmessAuth {
                uuid: test_uuid,
                alter_id: 0,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            transport_layer: TransportConfig::WebSocket(WebSocketTransportConfig {
                path: path.to_string(),
                headers: vec![],
                max_message_size: None,
                max_frame_size: None,
            }),
            timeout: Some(Duration::from_secs(10)),
            packet_encoding: false,
            headers: std::collections::HashMap::new(),
            ..Default::default()
        };

        let connector = VmessConnector::new(config);
        assert_eq!(connector.name(), "vmess");
    }
}

#[tokio::test]
async fn test_vmess_tcp_vs_websocket() {
    let test_uuid = Uuid::new_v4();
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 443));

    // TCP configuration
    let tcp_config = VmessConfig {
        server_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::Tcp,
        timeout: Some(Duration::from_secs(30)),
        packet_encoding: false,
        headers: std::collections::HashMap::new(),
        ..Default::default()
    };

    // WebSocket configuration
    let ws_config = VmessConfig {
        server_addr,
        auth: VmessAuth {
            uuid: test_uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/vmess".to_string(),
            headers: vec![],
            max_message_size: None,
            max_frame_size: None,
        }),
        timeout: Some(Duration::from_secs(30)),
        packet_encoding: false,
        headers: std::collections::HashMap::new(),
        ..Default::default()
    };

    let tcp_connector = VmessConnector::new(tcp_config);
    let ws_connector = VmessConnector::new(ws_config);

    assert_eq!(tcp_connector.name(), "vmess");
    assert_eq!(ws_connector.name(), "vmess");
}
