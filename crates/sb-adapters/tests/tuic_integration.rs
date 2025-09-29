#![cfg(feature = "tuic_DISABLED")]
//! TUIC protocol integration tests
//!
//! These tests verify TUIC protocol implementation including:
//! - Configuration parsing and validation
//! - Protocol packet encoding/decoding
//! - Authentication mechanisms
//! - UDP relay and multiplexing features
//! - Session management
//! - Interoperability with TUIC servers

use sb_adapters::outbound::tuic::{
    TuicAddressType, TuicAuthPacket, TuicCommand, TuicConfig, TuicCongestionControl,
    TuicConnectPacket, TuicConnector, TuicMultiplexer, TuicPacket, TuicUdpRelayMode,
};
use sb_core::{
    outbound::traits::OutboundConnector,
    types::{ConnCtx, Endpoint, Host, Network},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use uuid::Uuid;

#[test]
fn test_tuic_config_validation() {
    // Valid configuration
    let valid_config = TuicConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: Some("native".to_string()),
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 10000,
        connect_timeout_sec: Some(5),
        auth_timeout_sec: Some(3),
    };

    let connector = TuicConnector::new(valid_config);
    assert!(connector.is_ok());

    // Invalid UUID
    let invalid_config = TuicConfig {
        server: "example.com:443".to_string(),
        uuid: "invalid-uuid".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: None,
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 10000,
        connect_timeout_sec: None,
        auth_timeout_sec: None,
    };

    let connector = TuicConnector::new(invalid_config);
    assert!(connector.is_err());
}

#[test]
fn test_tuic_protocol_enums() {
    // Test command conversion
    assert_eq!(TuicCommand::Connect.to_byte(), 0x01);
    assert_eq!(TuicCommand::from_byte(0x01), Some(TuicCommand::Connect));
    assert_eq!(TuicCommand::Packet.to_byte(), 0x02);
    assert_eq!(TuicCommand::from_byte(0x02), Some(TuicCommand::Packet));
    assert_eq!(TuicCommand::Authenticate.to_byte(), 0x05);
    assert_eq!(
        TuicCommand::from_byte(0x05),
        Some(TuicCommand::Authenticate)
    );
    assert_eq!(TuicCommand::from_byte(0xFF), None);

    // Test address type conversion
    assert_eq!(TuicAddressType::Ipv4.to_byte(), 0x01);
    assert_eq!(
        TuicAddressType::from_byte(0x01),
        Some(TuicAddressType::Ipv4)
    );
    assert_eq!(TuicAddressType::Domain.to_byte(), 0x02);
    assert_eq!(
        TuicAddressType::from_byte(0x02),
        Some(TuicAddressType::Domain)
    );
    assert_eq!(TuicAddressType::Ipv6.to_byte(), 0x03);
    assert_eq!(
        TuicAddressType::from_byte(0x03),
        Some(TuicAddressType::Ipv6)
    );
    assert_eq!(TuicAddressType::from_byte(0xFF), None);

    // Test congestion control
    assert_eq!(
        TuicCongestionControl::from_str("bbr"),
        TuicCongestionControl::Bbr
    );
    assert_eq!(
        TuicCongestionControl::from_str("cubic"),
        TuicCongestionControl::Cubic
    );
    assert_eq!(
        TuicCongestionControl::from_str("new_reno"),
        TuicCongestionControl::NewReno
    );
    assert_eq!(
        TuicCongestionControl::from_str("unknown"),
        TuicCongestionControl::Bbr
    );

    // Test UDP relay mode
    assert_eq!(
        TuicUdpRelayMode::from_str("native"),
        TuicUdpRelayMode::Native
    );
    assert_eq!(TuicUdpRelayMode::from_str("quic"), TuicUdpRelayMode::Quic);
    assert_eq!(
        TuicUdpRelayMode::from_str("unknown"),
        TuicUdpRelayMode::Native
    );
}

#[test]
fn test_tuic_auth_packet_encoding() {
    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let password = "test_password".to_string();
    let auth_packet = TuicAuthPacket::new(uuid, password.clone());

    let encoded = auth_packet.encode();
    assert!(!encoded.is_empty());

    // Check command byte
    assert_eq!(encoded[0], TuicCommand::Authenticate.to_byte());

    // Check UUID (16 bytes)
    let uuid_bytes = &encoded[1..17];
    assert_eq!(uuid_bytes, uuid.as_bytes());

    // Check password length and password
    let password_len = encoded[17] as usize;
    assert_eq!(password_len, password.len());
    let password_bytes = &encoded[18..18 + password_len];
    assert_eq!(password_bytes, password.as_bytes());

    // Check timestamp (8 bytes)
    let timestamp_bytes = &encoded[18 + password_len..18 + password_len + 8];
    assert_eq!(timestamp_bytes.len(), 8);

    // Verify total length
    let expected_len = 1 + 16 + 1 + password.len() + 8;
    assert_eq!(encoded.len(), expected_len);
}

#[test]
fn test_tuic_connect_packet_encoding() {
    // Test with domain
    let domain_endpoint = Endpoint::new("example.com", 443);
    let connect_packet = TuicConnectPacket::new(&domain_endpoint);

    let encoded = connect_packet.encode();
    assert!(!encoded.is_empty());
    assert_eq!(encoded[0], TuicCommand::Connect.to_byte());
    assert_eq!(encoded[1], TuicAddressType::Domain.to_byte());

    let domain_len = encoded[2] as usize;
    assert_eq!(domain_len, 11); // "example.com".len()
    let domain_bytes = &encoded[3..3 + domain_len];
    assert_eq!(domain_bytes, b"example.com");

    let port_bytes = &encoded[3 + domain_len..3 + domain_len + 2];
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    assert_eq!(port, 443);

    // Test with IPv4
    let ipv4_endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let connect_packet = TuicConnectPacket::new(&ipv4_endpoint);

    let encoded = connect_packet.encode();
    assert_eq!(encoded[0], TuicCommand::Connect.to_byte());
    assert_eq!(encoded[1], TuicAddressType::Ipv4.to_byte());

    let ip_bytes = &encoded[2..6];
    assert_eq!(ip_bytes, &[127, 0, 0, 1]);

    let port_bytes = &encoded[6..8];
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    assert_eq!(port, 8080);
}

#[test]
fn test_tuic_packet_encoding() {
    let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
    let data = b"DNS query data".to_vec();
    let packet = TuicPacket::new(1, 2, &endpoint, data.clone());

    let encoded = packet.encode();
    assert!(!encoded.is_empty());

    // Check command
    assert_eq!(encoded[0], TuicCommand::Packet.to_byte());

    // Check session ID
    let session_id = u16::from_be_bytes([encoded[1], encoded[2]]);
    assert_eq!(session_id, 1);

    // Check packet ID
    let packet_id = u16::from_be_bytes([encoded[3], encoded[4]]);
    assert_eq!(packet_id, 2);

    // Check fragment info
    assert_eq!(encoded[5], 1); // fragment_total
    assert_eq!(encoded[6], 0); // fragment_id

    // Check address type
    assert_eq!(encoded[7], TuicAddressType::Ipv4.to_byte());

    // Check IP address
    let ip_bytes = &encoded[8..12];
    assert_eq!(ip_bytes, &[192, 168, 1, 1]);

    // Check port
    let port_bytes = &encoded[12..14];
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    assert_eq!(port, 53);

    // Check data length
    let data_len_bytes = &encoded[14..16];
    let data_len = u16::from_be_bytes([data_len_bytes[0], data_len_bytes[1]]);
    assert_eq!(data_len, data.len() as u16);

    // Check data
    let data_bytes = &encoded[16..16 + data.len()];
    assert_eq!(data_bytes, data.as_slice());
}

#[test]
fn test_tuic_multiplexer() {
    let mut multiplexer = TuicMultiplexer::new();

    // Test session creation
    let session_id1 = multiplexer.create_session();
    let session_id2 = multiplexer.create_session();

    assert_ne!(session_id1, session_id2);
    assert!(multiplexer.get_session_mut(session_id1).is_some());
    assert!(multiplexer.get_session_mut(session_id2).is_some());

    // Test packet ID generation
    let packet_id1 = multiplexer.next_packet_id();
    let packet_id2 = multiplexer.next_packet_id();

    assert_ne!(packet_id1, packet_id2);

    // Test session activity update
    if let Some(session) = multiplexer.get_session_mut(session_id1) {
        let old_activity = session.last_activity;
        std::thread::sleep(std::time::Duration::from_millis(1));
        session.update_activity();
        assert!(session.last_activity > old_activity);
    }

    // Test session cleanup (no sessions should be expired immediately)
    let initial_count = multiplexer.sessions.len();
    multiplexer.cleanup_expired_sessions(std::time::Duration::from_secs(1));
    assert_eq!(multiplexer.sessions.len(), initial_count);
}

#[test]
fn test_tuic_connector_properties() {
    let config = TuicConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "cubic".to_string(),
        udp_relay_mode: Some("quic".to_string()),
        udp_over_stream: true,
        zero_rtt_handshake: true,
        heartbeat: 5000,
        connect_timeout_sec: Some(15),
        auth_timeout_sec: Some(5),
    };

    let connector = TuicConnector::new(config).unwrap();

    assert_eq!(
        connector.connect_timeout(),
        std::time::Duration::from_secs(15)
    );
    assert_eq!(
        connector.congestion_control(),
        &TuicCongestionControl::Cubic
    );
    assert_eq!(connector.udp_relay_mode(), &TuicUdpRelayMode::Quic);
}

#[tokio::test]
async fn test_tuic_connector_without_quic_feature() {
    let config = TuicConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: None,
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 10000,
        connect_timeout_sec: None,
        auth_timeout_sec: None,
    };

    let connector = TuicConnector::new(config).unwrap();

    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
    let dst = Endpoint::new("example.com", 443);
    let ctx = ConnCtx::new(1, Network::Tcp, src, dst);

    // Without QUIC feature enabled, connections should fail with configuration error
    #[cfg(not(feature = "tuic"))]
    {
        let tcp_result = connector.connect_tcp(&ctx).await;
        assert!(tcp_result.is_err());

        let udp_result = connector.connect_udp(&ctx).await;
        assert!(udp_result.is_err());
    }
}

#[test]
fn test_tuic_packet_fragmentation() {
    // Test single fragment packet
    let endpoint = Endpoint::new("test.com", 80);
    let data = b"small data".to_vec();
    let packet = TuicPacket::new(10, 20, &endpoint, data);

    assert_eq!(packet.fragment_total, 1);
    assert_eq!(packet.fragment_id, 0);

    let encoded = packet.encode();
    assert_eq!(encoded[5], 1); // fragment_total
    assert_eq!(encoded[6], 0); // fragment_id
}

#[test]
fn test_tuic_address_encoding_edge_cases() {
    // Test empty domain (should not happen in practice, but test robustness)
    let endpoint = Endpoint::new("", 80);
    let connect_packet = TuicConnectPacket::new(&endpoint);
    let encoded = connect_packet.encode();

    assert_eq!(encoded[1], TuicAddressType::Domain.to_byte());
    assert_eq!(encoded[2], 0); // domain length should be 0

    // Test IPv6 address
    let ipv6_addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let ipv6_endpoint = Endpoint::new(IpAddr::V6(ipv6_addr), 443);
    let connect_packet = TuicConnectPacket::new(&ipv6_endpoint);
    let encoded = connect_packet.encode();

    assert_eq!(encoded[1], TuicAddressType::Ipv6.to_byte());
    let ipv6_bytes = &encoded[2..18];
    assert_eq!(ipv6_bytes, ipv6_addr.octets());
}

#[test]
fn test_tuic_session_metrics() {
    let mut multiplexer = TuicMultiplexer::new();
    let session_id = multiplexer.create_session();

    if let Some(session) = multiplexer.get_session_mut(session_id) {
        assert_eq!(session.tx_packets, 0);
        assert_eq!(session.rx_packets, 0);

        // Simulate packet transmission
        session.tx_packets += 1;
        session.rx_packets += 2;

        assert_eq!(session.tx_packets, 1);
        assert_eq!(session.rx_packets, 2);
    }
}

// Mock test for QUIC functionality (when feature is enabled)
#[cfg(feature = "tuic")]
mod quic_tests {
    use super::*;

    #[tokio::test]
    async fn test_tuic_quic_config_creation() {
        let config = TuicConfig {
            server: "example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            password: "test_password".to_string(),
            congestion_control: "bbr".to_string(),
            udp_relay_mode: Some("native".to_string()),
            udp_over_stream: false,
            zero_rtt_handshake: false,
            heartbeat: 10000,
            connect_timeout_sec: Some(10),
            auth_timeout_sec: Some(3),
        };

        let connector = TuicConnector::new(config).unwrap();

        // Test QUIC config creation (this will test the internal method)
        let quic_config_result = connector.create_quic_config();
        assert!(quic_config_result.is_ok());

        let quic_config = quic_config_result.unwrap();
        assert!(!quic_config.alpn_protocols.is_empty());
        assert_eq!(quic_config.alpn_protocols[0], b"tuic");
    }
}
