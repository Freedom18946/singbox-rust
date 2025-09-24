//! VMess protocol integration tests

use sb_adapters::outbound::vmess::{VmessConfig, VmessConnector};
use sb_core::{
    outbound::traits::OutboundConnector,
    types::{Endpoint, Host},
};
use std::net::{IpAddr, Ipv4Addr};

/// Test VMess connector creation and configuration validation
#[tokio::test]
async fn test_vmess_connector_creation() {
    let config = VmessConfig {
        server: "127.0.0.1:8080".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        security: "aes-128-gcm".to_string(),
        alter_id: 0,
        connect_timeout_sec: Some(10),
    };

    let connector = VmessConnector::new(config);
    assert!(connector.is_ok(), "VMess connector creation should succeed");
}

/// Test VMess connector with invalid UUID
#[tokio::test]
async fn test_vmess_connector_invalid_uuid() {
    let config = VmessConfig {
        server: "127.0.0.1:8080".to_string(),
        uuid: "invalid-uuid-format".to_string(),
        security: "auto".to_string(),
        alter_id: 0,
        connect_timeout_sec: None,
    };

    let connector = VmessConnector::new(config);
    assert!(
        connector.is_err(),
        "VMess connector with invalid UUID should fail"
    );
}

/// Test VMess configuration serialization/deserialization
#[tokio::test]
async fn test_vmess_config_serde() {
    let config = VmessConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        security: "auto".to_string(),
        alter_id: 0,
        connect_timeout_sec: Some(30),
    };

    // Test serialization
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("example.com:443"));
    assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(json.contains("auto"));

    // Test deserialization
    let deserialized: VmessConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.server, config.server);
    assert_eq!(deserialized.uuid, config.uuid);
    assert_eq!(deserialized.security, config.security);
}

/// Test VMess header generation
#[tokio::test]
async fn test_vmess_header_generation() {
    let config = VmessConfig {
        server: "127.0.0.1:8080".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        security: "aes-128-gcm".to_string(),
        alter_id: 0,
        connect_timeout_sec: None,
    };

    let connector = VmessConnector::new(config).unwrap();
    let endpoint = Endpoint::new(Host::domain("example.com"), 443);

    // Generate multiple headers to test consistency
    for _ in 0..10 {
        let header = connector
            .generate_request_header(sb_adapters::outbound::vmess::VmessCommand::Tcp, &endpoint)
            .unwrap();

        assert!(!header.is_empty());
        assert_eq!(header[0], 1); // Version should be 1
    }
}

/// Test VMess with different address types
#[tokio::test]
async fn test_vmess_address_types() {
    let config = VmessConfig {
        server: "127.0.0.1:8080".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        security: "auto".to_string(),
        alter_id: 0,
        connect_timeout_sec: None,
    };

    let connector = VmessConnector::new(config).unwrap();

    // Test IPv4 address
    let ipv4_endpoint = Endpoint::new(Host::ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), 80);
    let header = connector
        .generate_request_header(
            sb_adapters::outbound::vmess::VmessCommand::Tcp,
            &ipv4_endpoint,
        )
        .unwrap();
    assert!(!header.is_empty());

    // Test IPv6 address
    let ipv6_endpoint = Endpoint::new(Host::ip(IpAddr::V6("::1".parse().unwrap())), 80);
    let header = connector
        .generate_request_header(
            sb_adapters::outbound::vmess::VmessCommand::Tcp,
            &ipv6_endpoint,
        )
        .unwrap();
    assert!(!header.is_empty());

    // Test domain name
    let domain_endpoint = Endpoint::new(Host::domain("example.com"), 443);
    let header = connector
        .generate_request_header(
            sb_adapters::outbound::vmess::VmessCommand::Tcp,
            &domain_endpoint,
        )
        .unwrap();
    assert!(!header.is_empty());
}

/// Test VMess connector implements OutboundConnector trait
#[tokio::test]
async fn test_vmess_connector_trait() {
    let config = VmessConfig {
        server: "127.0.0.1:8080".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        security: "auto".to_string(),
        alter_id: 0,
        connect_timeout_sec: Some(5),
    };

    let connector = VmessConnector::new(config).unwrap();

    // Test that it implements the OutboundConnector trait
    let _: Box<dyn OutboundConnector> = Box::new(connector);
}
