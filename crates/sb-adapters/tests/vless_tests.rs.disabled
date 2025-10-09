#![cfg(feature = "adapter-vless")]
//! Comprehensive tests for VLESS protocol implementation

use sb_adapters::outbound::vless::{
    VlessAddressType, VlessCommand, VlessConfig, VlessConnector, VlessFlow, VlessPacketEncoding,
    VlessRequestHeader,
};
use sb_core::types::Endpoint;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::time::Duration;
use uuid::Uuid;

#[test]
fn test_vless_config_defaults() {
    let config = VlessConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        flow: None,
        network: "tcp".to_string(),
        packet_encoding: None,
        connect_timeout_sec: None,
    };

    let connector = VlessConnector::new(config).unwrap();
    assert_eq!(connector.connect_timeout(), Duration::from_secs(10));
}

#[test]
fn test_vless_config_with_flow() {
    let config = VlessConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        network: "tcp".to_string(),
        packet_encoding: Some("xudp".to_string()),
        connect_timeout_sec: Some(30),
    };

    let connector = VlessConnector::new(config).unwrap();
    assert_eq!(connector.connect_timeout(), Duration::from_secs(30));
}

#[test]
fn test_vless_flow_modes() {
    assert_eq!(
        VlessFlow::from_str("xtls-rprx-vision"),
        VlessFlow::XtlsRprxVision
    );
    assert_eq!(VlessFlow::from_str(""), VlessFlow::None);
    assert_eq!(VlessFlow::from_str("unknown"), VlessFlow::None);

    assert_eq!(VlessFlow::XtlsRprxVision.to_str(), "xtls-rprx-vision");
    assert_eq!(VlessFlow::None.to_str(), "");
}

#[test]
fn test_vless_packet_encoding_modes() {
    assert_eq!(
        VlessPacketEncoding::from_str("packetaddr"),
        VlessPacketEncoding::PacketAddr
    );
    assert_eq!(
        VlessPacketEncoding::from_str("xudp"),
        VlessPacketEncoding::Xudp
    );
    assert_eq!(VlessPacketEncoding::from_str(""), VlessPacketEncoding::None);
    assert_eq!(
        VlessPacketEncoding::from_str("unknown"),
        VlessPacketEncoding::None
    );
}

#[test]
fn test_vless_command_serialization() {
    // Test all command types
    let commands = [
        (VlessCommand::Tcp, 0x01),
        (VlessCommand::Udp, 0x02),
        (VlessCommand::Mux, 0x03),
    ];

    for (cmd, byte) in commands {
        assert_eq!(cmd.to_byte(), byte);
        assert_eq!(VlessCommand::from_byte(byte), Some(cmd));
    }

    // Test invalid command
    assert_eq!(VlessCommand::from_byte(0xFF), None);
}

#[test]
fn test_vless_address_type_serialization() {
    let address_types = [
        (VlessAddressType::Ipv4, 0x01),
        (VlessAddressType::Domain, 0x02),
        (VlessAddressType::Ipv6, 0x03),
    ];

    for (addr_type, byte) in address_types {
        assert_eq!(addr_type.to_byte(), byte);
        assert_eq!(VlessAddressType::from_byte(byte), Some(addr_type));
    }

    // Test invalid address type
    assert_eq!(VlessAddressType::from_byte(0xFF), None);
}

#[test]
fn test_vless_header_ipv4_encoding() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    assert_eq!(header.version, 0x00);
    assert_eq!(header.uuid, uuid);
    assert_eq!(header.command, VlessCommand::Tcp);
    assert_eq!(header.port, 8080);
    assert_eq!(header.address_type, VlessAddressType::Ipv4);
    assert_eq!(header.address, vec![192, 168, 1, 1]);

    // Test encoding and decoding
    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.version, header.version);
    assert_eq!(decoded.uuid, header.uuid);
    assert_eq!(decoded.command, header.command);
    assert_eq!(decoded.port, header.port);
    assert_eq!(decoded.address_type, header.address_type);
    assert_eq!(decoded.address, header.address);
}

#[test]
fn test_vless_header_ipv6_encoding() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let ipv6 = Ipv6Addr::new(
        0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
    );
    let endpoint = Endpoint::new(IpAddr::V6(ipv6), 443);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    assert_eq!(header.address_type, VlessAddressType::Ipv6);
    assert_eq!(header.address, ipv6.octets().to_vec());
    assert_eq!(header.port, 443);

    // Test encoding and decoding
    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.address_type, VlessAddressType::Ipv6);
    assert_eq!(decoded.address, ipv6.octets().to_vec());
    assert_eq!(decoded.port, 443);
}

#[test]
fn test_vless_header_domain_encoding() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let endpoint = Endpoint::new("www.example.com", 443);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    assert_eq!(header.address_type, VlessAddressType::Domain);
    assert_eq!(header.address[0], 15); // "www.example.com".len()
    assert_eq!(&header.address[1..], b"www.example.com");
    assert_eq!(header.port, 443);

    // Test encoding and decoding
    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.address_type, VlessAddressType::Domain);
    assert_eq!(decoded.address[0], 15);
    assert_eq!(&decoded.address[1..], b"www.example.com");
    assert_eq!(decoded.port, 443);
}

#[test]
fn test_vless_header_udp_command() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let endpoint = Endpoint::new("example.com", 53);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Udp, &endpoint);

    assert_eq!(header.command, VlessCommand::Udp);

    // Test encoding and decoding
    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.command, VlessCommand::Udp);
}

#[test]
fn test_vless_header_mux_command() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let endpoint = Endpoint::new("example.com", 443);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Mux, &endpoint);

    assert_eq!(header.command, VlessCommand::Mux);

    // Test encoding and decoding
    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.command, VlessCommand::Mux);
}

#[test]
fn test_vless_header_decode_errors() {
    // Test data too short
    let short_data = vec![0x00]; // Only version byte
    let result = VlessRequestHeader::decode(&short_data);
    assert!(result.is_err());

    // Test invalid version
    let mut invalid_version = vec![0x01]; // Invalid version
    invalid_version.extend_from_slice(&[0u8; 16]); // UUID
    invalid_version.push(0x00); // Addons length
    let result = VlessRequestHeader::decode(&invalid_version);
    assert!(result.is_err());

    // Test invalid command
    let mut invalid_cmd = vec![0x00]; // Version
    invalid_cmd.extend_from_slice(&[0u8; 16]); // UUID
    invalid_cmd.push(0x00); // Addons length
    invalid_cmd.push(0xFF); // Invalid command
    let result = VlessRequestHeader::decode(&invalid_cmd);
    assert!(result.is_err());
}

#[test]
fn test_vless_header_with_addons() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let endpoint = Endpoint::new("example.com", 443);
    let mut header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    // Add some addon data
    header.addons = vec![0x01, 0x02, 0x03];
    header.addons_length = 3;

    let encoded = header.encode();
    let (decoded, _) = VlessRequestHeader::decode(&encoded).unwrap();

    assert_eq!(decoded.addons_length, 3);
    assert_eq!(decoded.addons, vec![0x01, 0x02, 0x03]);
}

#[test]
fn test_vless_connector_invalid_configs() {
    // Test invalid UUID
    let invalid_uuid_config = VlessConfig {
        server: "example.com:443".to_string(),
        uuid: "not-a-valid-uuid".to_string(),
        flow: None,
        network: "tcp".to_string(),
        packet_encoding: None,
        connect_timeout_sec: None,
    };

    let result = VlessConnector::new(invalid_uuid_config);
    assert!(result.is_err());

    // Test valid config
    let valid_config = VlessConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        network: "tcp".to_string(),
        packet_encoding: Some("xudp".to_string()),
        connect_timeout_sec: Some(15),
    };

    let result = VlessConnector::new(valid_config);
    assert!(result.is_ok());
}

#[test]
fn test_vless_header_encoding_roundtrip() {
    let test_cases = vec![
        // IPv4 case
        (
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            VlessCommand::Tcp,
            Endpoint::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        ),
        // IPv6 case
        (
            Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            VlessCommand::Udp,
            Endpoint::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
                53,
            ),
        ),
        // Domain case
        (
            Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap(),
            VlessCommand::Mux,
            Endpoint::new("google.com", 443),
        ),
    ];

    for (uuid, command, endpoint) in test_cases {
        let original_header = VlessRequestHeader::new(uuid, command, &endpoint);
        let encoded = original_header.encode();
        let (decoded_header, bytes_consumed) = VlessRequestHeader::decode(&encoded).unwrap();

        // Verify all fields match
        assert_eq!(decoded_header.version, original_header.version);
        assert_eq!(decoded_header.uuid, original_header.uuid);
        assert_eq!(decoded_header.addons_length, original_header.addons_length);
        assert_eq!(decoded_header.addons, original_header.addons);
        assert_eq!(decoded_header.command, original_header.command);
        assert_eq!(decoded_header.port, original_header.port);
        assert_eq!(decoded_header.address_type, original_header.address_type);
        assert_eq!(decoded_header.address, original_header.address);

        // Verify we consumed all bytes
        assert_eq!(bytes_consumed, encoded.len());
    }
}

#[test]
fn test_vless_header_minimum_size() {
    // Minimum VLESS header: version(1) + uuid(16) + addons_len(0) + cmd(1) + port(2) + addr_type(1) + addr(4 for IPv4) = 25 bytes
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    let encoded = header.encode();
    // version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + addr_type(1) + addr(4) = 26 bytes
    assert_eq!(encoded.len(), 26); // Minimum size for IPv4
}

#[test]
fn test_vless_header_domain_size() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let domain = "example.com";
    let endpoint = Endpoint::new(domain, 443);
    let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

    let encoded = header.encode();
    // version(1) + uuid(16) + addons_len(1) + cmd(1) + port(2) + addr_type(1) + domain_len(1) + domain(11) = 34 bytes
    assert_eq!(encoded.len(), 34);
}

// Integration test structure (would require actual server for full testing)
#[cfg(feature = "integration-tests")]
mod integration_tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_vless_tcp_connection_mock() {
        // This would be a mock test since we don't have a real VLESS server
        let config = VlessConfig {
            server: "127.0.0.1:1080".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            flow: None,
            network: "tcp".to_string(),
            packet_encoding: None,
            connect_timeout_sec: Some(5),
        };

        let connector = VlessConnector::new(config).unwrap();

        // Create connection context
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let dst = Endpoint::new("httpbin.org", 80);
        let ctx = ConnCtx::new(1, Network::Tcp, src, dst);

        // This would fail without a real server, but tests the interface
        let result = timeout(Duration::from_secs(1), connector.connect_tcp(&ctx)).await;
        // We expect this to fail since there's no server, but it should be a connection error, not a panic
        assert!(result.is_err() || result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_vless_udp_connection_mock() {
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

        let result = timeout(Duration::from_secs(1), connector.connect_udp(&ctx)).await;
        // We expect this to fail since there's no server
        assert!(result.is_err() || result.unwrap().is_err());
    }
}
