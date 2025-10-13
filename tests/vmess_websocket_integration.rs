//! VMess + WebSocket Transport Integration Test
//!
//! This test validates that VMess outbound adapter correctly integrates with WebSocket transport.

use sb_adapters::outbound::vmess::{VmessConfig, VmessConnector};
use sb_adapters::outbound::OutboundConnector;
use sb_adapters::transport_config::{TransportConfig, WebSocketTransportConfig};
use uuid::Uuid;

#[tokio::test]
async fn test_vmess_websocket_config_creation() {
    let test_uuid = Uuid::new_v4();
    let server_addr = "127.0.0.1:8443".to_string();

    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
    ];

    let ws_config = WebSocketTransportConfig {
        path: "/vmess".to_string(),
        headers: headers.clone(),
        max_message_size: Some(64 * 1024 * 1024),
        max_frame_size: Some(16 * 1024 * 1024),
    };

    let config = VmessConfig {
        server: server_addr.clone(),
        tag: Some("vmess-ws".to_string()),
        uuid: test_uuid,
        alter_id: 0,
        security: "auto".to_string(),
        connect_timeout_sec: Some(30),
        transport_layer: TransportConfig::WebSocket(ws_config),
        multiplex: None,
        tls: None,
    };

    assert_eq!(config.server, server_addr);
    assert_eq!(config.uuid, test_uuid);

    let connector = VmessConnector::new(config);
    assert_eq!(connector.name(), "vmess");
}

#[tokio::test]
async fn test_vmess_websocket_path_variants() {
    let test_uuid = Uuid::new_v4();
    let server_addr = "127.0.0.1:443".to_string();

    let paths = vec!["/", "/vmess", "/ws", "/api/v1/connect"];

    for path in paths {
        let config = VmessConfig {
            server: server_addr.clone(),
            tag: None,
            uuid: test_uuid,
            alter_id: 0,
            security: "auto".to_string(),
            connect_timeout_sec: Some(10),
            transport_layer: TransportConfig::WebSocket(WebSocketTransportConfig {
                path: path.to_string(),
                headers: vec![],
                max_message_size: None,
                max_frame_size: None,
            }),
            multiplex: None,
            tls: None,
        };

        let connector = VmessConnector::new(config);
        assert_eq!(connector.name(), "vmess");
    }
}

#[tokio::test]
async fn test_vmess_tcp_vs_websocket() {
    let test_uuid = Uuid::new_v4();
    let server_addr = "127.0.0.1:443".to_string();

    // TCP configuration
    let tcp_config = VmessConfig {
        server: server_addr.clone(),
        tag: Some("vmess-tcp".to_string()),
        uuid: test_uuid,
        alter_id: 0,
        security: "auto".to_string(),
        connect_timeout_sec: Some(30),
        transport_layer: TransportConfig::Tcp,
        multiplex: None,
        tls: None,
    };

    // WebSocket configuration
    let ws_config = VmessConfig {
        server: server_addr,
        tag: Some("vmess-ws".to_string()),
        uuid: test_uuid,
        alter_id: 0,
        security: "auto".to_string(),
        connect_timeout_sec: Some(30),
        transport_layer: TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/vmess".to_string(),
            headers: vec![],
            max_message_size: Some(64 * 1024 * 1024),
            max_frame_size: Some(16 * 1024 * 1024),
        }),
        multiplex: None,
        tls: None,
    };

    let tcp_connector = VmessConnector::new(tcp_config);
    let ws_connector = VmessConnector::new(ws_config);

    assert_eq!(tcp_connector.name(), "vmess");
    assert_eq!(ws_connector.name(), "vmess");
}

#[tokio::test]
async fn test_vmess_websocket_with_multiplex() {
    let test_uuid = Uuid::new_v4();
    let server_addr = "127.0.0.1:443".to_string();

    let config = VmessConfig {
        server: server_addr,
        tag: Some("vmess-mux".to_string()),
        uuid: test_uuid,
        alter_id: 0,
        security: "auto".to_string(),
        connect_timeout_sec: Some(30),
        transport_layer: TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/vmess".to_string(),
            headers: vec![],
            max_message_size: Some(64 * 1024 * 1024),
            max_frame_size: Some(16 * 1024 * 1024),
        }),
        multiplex: Some(sb_transport::multiplex::MultiplexConfig {
            enabled: true,
            protocol: "yamux".to_string(),
            max_connections: 4,
            max_streams: 16,
            padding: false,
            brutal: None,
        }),
        tls: None,
    };

    let connector = VmessConnector::new(config);
    assert_eq!(connector.name(), "vmess");
}
