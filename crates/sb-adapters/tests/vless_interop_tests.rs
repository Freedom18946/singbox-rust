//! VLESS protocol interoperability tests with Go version
//!
//! These tests verify that our VLESS implementation is compatible with
//! the Go version of sing-box and other VLESS implementations.

use sb_adapters::outbound::vless::{
    VlessCommand, VlessConfig, VlessConnector, VlessFlow, VlessPacketEncoding, VlessRequestHeader,
};
use sb_core::types::Endpoint;
use serde_json;
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

#[test]
fn test_vless_config_parsing_compatibility() {
    // Test parsing configuration that matches Go version format
    let json_config = r#"
    {
        "type": "vless",
        "tag": "vless-out",
        "server": "example.com",
        "server_port": 443,
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "flow": "xtls-rprx-vision",
        "network": "tcp",
        "packet_encoding": "xudp"
    }
    "#;

    let parsed: serde_json::Value = serde_json::from_str(json_config).unwrap();

    // Extract VLESS-specific fields
    assert_eq!(parsed["type"], "vless");
    assert_eq!(parsed["server"], "example.com");
    assert_eq!(parsed["server_port"], 443);
    assert_eq!(parsed["uuid"], "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(parsed["flow"], "xtls-rprx-vision");
    assert_eq!(parsed["network"], "tcp");
    assert_eq!(parsed["packet_encoding"], "xudp");

    // Test creating VlessConfig from parsed values
    let config = VlessConfig {
        server: format!("{}:{}", parsed["server"], parsed["server_port"]),
        uuid: parsed["uuid"].as_str().unwrap().to_string(),
        flow: Some(parsed["flow"].as_str().unwrap().to_string()),
        network: parsed["network"].as_str().unwrap().to_string(),
        packet_encoding: Some(parsed["packet_encoding"].as_str().unwrap().to_string()),
        connect_timeout_sec: None,
    };

    let connector = VlessConnector::new(config).unwrap();
    assert!(connector.connect_timeout().as_secs() > 0);
}

#[test]
fn test_vless_header_go_compatibility() {
    // Test header format compatibility with Go implementation
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

    // Test cases that should match Go version behavior
    let test_cases = vec![
        // TCP to IPv4
        (
            VlessCommand::Tcp,
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        ),
        // UDP to IPv6
        (
            VlessCommand::Udp,
            Endpoint::new(IpAddr::V6("2001:4860:4860::8888".parse().unwrap()), 53),
        ),
        // TCP to domain
        (VlessCommand::Tcp, Endpoint::new("www.google.com", 443)),
        // MUX command
        (VlessCommand::Mux, Endpoint::new("example.com", 80)),
    ];

    for (command, endpoint) in test_cases {
        let header = VlessRequestHeader::new(uuid, command, &endpoint);
        let encoded = header.encode();

        // Verify header structure matches expected format
        assert_eq!(encoded[0], 0x00); // Version
        assert_eq!(&encoded[1..17], uuid.as_bytes()); // UUID
        assert_eq!(encoded[17], 0x00); // Addons length
        assert_eq!(encoded[18], command.to_byte()); // Command

        // Verify we can decode our own headers
        let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.command, command);
    }
}

#[test]
fn test_vless_flow_control_compatibility() {
    // Test flow control modes that should be compatible with Go version
    let flow_modes = vec![
        ("", VlessFlow::None),
        ("xtls-rprx-vision", VlessFlow::XtlsRprxVision),
    ];

    for (flow_str, expected_flow) in flow_modes {
        let parsed_flow = VlessFlow::from_str(flow_str);
        assert_eq!(parsed_flow, expected_flow);
        assert_eq!(parsed_flow.to_str(), flow_str);
    }
}

#[test]
fn test_vless_packet_encoding_compatibility() {
    // Test packet encoding modes compatible with Go version
    let encoding_modes = vec![
        ("", VlessPacketEncoding::None),
        ("packetaddr", VlessPacketEncoding::PacketAddr),
        ("xudp", VlessPacketEncoding::Xudp),
    ];

    for (encoding_str, expected_encoding) in encoding_modes {
        let parsed_encoding = VlessPacketEncoding::from_str(encoding_str);
        assert_eq!(parsed_encoding, expected_encoding);
    }
}

#[test]
fn test_vless_uuid_formats() {
    // Test various UUID formats that should be accepted
    let valid_uuids = vec![
        "550e8400-e29b-41d4-a716-446655440000", // Standard format
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8", // Another valid UUID
        "00000000-0000-0000-0000-000000000000", // Nil UUID
        "ffffffff-ffff-ffff-ffff-ffffffffffff", // Max UUID
    ];

    for uuid_str in valid_uuids {
        let config = VlessConfig {
            server: "example.com:443".to_string(),
            uuid: uuid_str.to_string(),
            flow: None,
            network: "tcp".to_string(),
            packet_encoding: None,
            connect_timeout_sec: None,
        };

        let connector = VlessConnector::new(config);
        assert!(
            connector.is_ok(),
            "Failed to create connector with UUID: {}",
            uuid_str
        );
    }

    // Test invalid UUIDs
    let invalid_uuids = vec![
        "not-a-uuid",
        "550e8400-e29b-41d4-a716",                    // Too short
        "550e8400-e29b-41d4-a716-446655440000-extra", // Too long
        "gggggggg-gggg-gggg-gggg-gggggggggggg",       // Invalid characters
    ];

    for uuid_str in invalid_uuids {
        let config = VlessConfig {
            server: "example.com:443".to_string(),
            uuid: uuid_str.to_string(),
            flow: None,
            network: "tcp".to_string(),
            packet_encoding: None,
            connect_timeout_sec: None,
        };

        let connector = VlessConnector::new(config);
        assert!(
            connector.is_err(),
            "Should fail with invalid UUID: {}",
            uuid_str
        );
    }
}

#[test]
fn test_vless_header_size_limits() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

    // Test maximum domain name length (255 bytes as per DNS spec)
    let max_domain = "a".repeat(253) + ".com"; // 253 + 4 = 257, but we limit to 255
    let long_domain = "a".repeat(250) + ".test"; // 255 chars total

    let endpoint = Endpoint::new(long_domain.as_str(), 443);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    // Verify the domain was encoded correctly
    assert_eq!(decoded.address[0] as usize, long_domain.len());
    assert_eq!(&decoded.address[1..], long_domain.as_bytes());
}

#[test]
fn test_vless_network_types() {
    // Test network type configurations
    let network_types = vec!["tcp", "udp"];

    for network in network_types {
        let config = VlessConfig {
            server: "example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            flow: None,
            network: network.to_string(),
            packet_encoding: None,
            connect_timeout_sec: None,
        };

        let connector = VlessConnector::new(config);
        assert!(connector.is_ok(), "Failed with network type: {}", network);
    }
}

#[test]
fn test_vless_config_serialization() {
    // Test that our config can be serialized/deserialized like Go version
    let config = VlessConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        network: "tcp".to_string(),
        packet_encoding: Some("xudp".to_string()),
        connect_timeout_sec: Some(30),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&config).unwrap();

    // Deserialize back
    let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();

    // Verify all fields match
    assert_eq!(deserialized.server, config.server);
    assert_eq!(deserialized.uuid, config.uuid);
    assert_eq!(deserialized.flow, config.flow);
    assert_eq!(deserialized.network, config.network);
    assert_eq!(deserialized.packet_encoding, config.packet_encoding);
    assert_eq!(deserialized.connect_timeout_sec, config.connect_timeout_sec);
}

#[test]
fn test_vless_header_edge_cases() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

    // Test edge cases that might occur in real usage
    let edge_cases = vec![
        // Minimum port
        Endpoint::new("example.com", 1),
        // Maximum port
        Endpoint::new("example.com", 65535),
        // Localhost IPv4
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        // Localhost IPv6
        Endpoint::new(IpAddr::V6("::1".parse().unwrap()), 8080),
        // Single character domain
        Endpoint::new("a", 80),
        // Numeric domain (should be treated as domain, not IP)
        Endpoint::new("123", 80),
    ];

    for endpoint in edge_cases {
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);
        let encoded = header.encode();
        let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

        // Verify roundtrip works
        assert_eq!(decoded.uuid, header.uuid);
        assert_eq!(decoded.command, header.command);
        assert_eq!(decoded.port, header.port);
        assert_eq!(decoded.address_type, header.address_type);
        assert_eq!(decoded.address, header.address);
    }
}

// Mock server tests (would require actual VLESS server for full integration)
#[cfg(feature = "integration-tests")]
mod integration_tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_vless_connection_timeout() {
        // Test connection timeout behavior
        let config = VlessConfig {
            server: "192.0.2.1:443".to_string(), // TEST-NET-1 (should not be routable)
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            flow: None,
            network: "tcp".to_string(),
            packet_encoding: None,
            connect_timeout_sec: Some(1), // Very short timeout
        };

        let connector = VlessConnector::new(config).unwrap();

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let dst = Endpoint::new("httpbin.org", 80);
        let ctx = ConnCtx::new(1, Network::Tcp, src, dst);

        let start = std::time::Instant::now();
        let result = connector.connect_tcp(&ctx).await;
        let elapsed = start.elapsed();

        // Should timeout within reasonable time
        assert!(elapsed < Duration::from_secs(5));
        assert!(result.is_err()); // Should fail due to timeout or connection error
    }

    #[tokio::test]
    async fn test_vless_udp_transport_interface() {
        // Test UDP transport interface (mock)
        let config = VlessConfig {
            server: "127.0.0.1:1080".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            flow: None,
            network: "udp".to_string(),
            packet_encoding: Some("xudp".to_string()),
            connect_timeout_sec: Some(5),
        };

        let connector = VlessConnector::new(config).unwrap();

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let dst = Endpoint::new("8.8.8.8", 53);
        let ctx = ConnCtx::new(2, Network::Udp, src, dst);

        // This will fail without a real server, but tests the interface
        let result = timeout(Duration::from_secs(1), connector.connect_udp(&ctx)).await;

        // We expect failure, but it should be a proper error, not a panic
        match result {
            Ok(Ok(_transport)) => {
                // If somehow successful, that's fine too
            }
            Ok(Err(_)) | Err(_) => {
                // Expected - no real server available
            }
        }
    }
}

#[test]
fn test_vless_protocol_constants() {
    // Verify protocol constants match expected values
    assert_eq!(VlessCommand::Tcp as u8, 0x01);
    assert_eq!(VlessCommand::Udp as u8, 0x02);
    assert_eq!(VlessCommand::Mux as u8, 0x03);

    // Verify version constant
    let uuid = Uuid::new_v4();
    let endpoint = Endpoint::new("example.com", 443);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);
    assert_eq!(header.version, 0x00); // VLESS version should be 0
}
