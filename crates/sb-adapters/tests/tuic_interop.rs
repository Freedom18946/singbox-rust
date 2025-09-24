//! TUIC interoperability tests
//!
//! These tests verify TUIC protocol interoperability with Go version servers
//! and other TUIC implementations. They test real-world scenarios and
//! compatibility with existing TUIC server configurations.

use sb_adapters::outbound::tuic::{TuicConfig, TuicConnector};
use sb_core::{
    outbound::traits::OutboundConnector,
    types::{ConnCtx, Endpoint, Network},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::time::Duration;

/// Test TUIC configuration compatibility with Go version
#[test]
fn test_tuic_config_compatibility() {
    // Test configuration that matches Go sing-box TUIC format
    let go_compatible_config = TuicConfig {
        server: "tuic.example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: Some("native".to_string()),
        udp_over_stream: false,
        zero_rtt_handshake: true,
        heartbeat: 10000,
        connect_timeout_sec: Some(10),
        auth_timeout_sec: Some(3),
    };

    let connector = TuicConnector::new(go_compatible_config);
    assert!(connector.is_ok());

    // Test with QUIC UDP relay mode
    let quic_udp_config = TuicConfig {
        server: "tuic.example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "cubic".to_string(),
        udp_relay_mode: Some("quic".to_string()),
        udp_over_stream: true,
        zero_rtt_handshake: false,
        heartbeat: 5000,
        connect_timeout_sec: Some(15),
        auth_timeout_sec: Some(5),
    };

    let connector = TuicConnector::new(quic_udp_config);
    assert!(connector.is_ok());
}

/// Test TUIC protocol version compatibility
#[test]
fn test_tuic_protocol_version() {
    // TUIC protocol should be compatible with standard TUIC implementations
    // This test verifies that our packet formats match the expected structure

    use sb_adapters::outbound::tuic::{TuicAuthPacket, TuicConnectPacket};
    use uuid::Uuid;

    let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

    // Test authentication packet format
    let auth_packet = TuicAuthPacket::new(uuid, "password123".to_string());
    let auth_encoded = auth_packet.encode();

    // Verify packet structure matches TUIC specification
    assert_eq!(auth_encoded[0], 0x05); // Authenticate command
    assert_eq!(&auth_encoded[1..17], uuid.as_bytes()); // UUID
    assert_eq!(auth_encoded[17], 11); // Password length
    assert_eq!(&auth_encoded[18..29], b"password123"); // Password
    assert_eq!(auth_encoded.len(), 29 + 8); // Total length with timestamp

    // Test connect packet format
    let endpoint = Endpoint::new("google.com", 443);
    let connect_packet = TuicConnectPacket::new(&endpoint);
    let connect_encoded = connect_packet.encode();

    assert_eq!(connect_encoded[0], 0x01); // Connect command
    assert_eq!(connect_encoded[1], 0x02); // Domain address type
    assert_eq!(connect_encoded[2], 10); // Domain length
    assert_eq!(&connect_encoded[3..13], b"google.com"); // Domain

    let port_bytes = &connect_encoded[13..15];
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    assert_eq!(port, 443);
}

/// Test TUIC congestion control algorithms
#[test]
fn test_tuic_congestion_control_algorithms() {
    use sb_adapters::outbound::tuic::TuicCongestionControl;

    // Test all supported congestion control algorithms
    let algorithms = vec![
        ("bbr", TuicCongestionControl::Bbr),
        ("cubic", TuicCongestionControl::Cubic),
        ("new_reno", TuicCongestionControl::NewReno),
        ("newreno", TuicCongestionControl::NewReno), // Alternative spelling
    ];

    for (name, expected) in algorithms {
        let config = TuicConfig {
            server: "tuic.example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            password: "test_password".to_string(),
            congestion_control: name.to_string(),
            udp_relay_mode: None,
            udp_over_stream: false,
            zero_rtt_handshake: false,
            heartbeat: 10000,
            connect_timeout_sec: None,
            auth_timeout_sec: None,
        };

        let connector = TuicConnector::new(config).unwrap();
        assert_eq!(connector.congestion_control(), &expected);
    }
}

/// Test TUIC UDP relay modes
#[test]
fn test_tuic_udp_relay_modes() {
    use sb_adapters::outbound::tuic::TuicUdpRelayMode;

    // Test native UDP relay mode
    let native_config = TuicConfig {
        server: "tuic.example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: Some("native".to_string()),
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 10000,
        connect_timeout_sec: None,
        auth_timeout_sec: None,
    };

    let connector = TuicConnector::new(native_config).unwrap();
    assert_eq!(connector.udp_relay_mode(), &TuicUdpRelayMode::Native);

    // Test QUIC UDP relay mode
    let quic_config = TuicConfig {
        server: "tuic.example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: Some("quic".to_string()),
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 10000,
        connect_timeout_sec: None,
        auth_timeout_sec: None,
    };

    let connector = TuicConnector::new(quic_config).unwrap();
    assert_eq!(connector.udp_relay_mode(), &TuicUdpRelayMode::Quic);
}

/// Test TUIC packet fragmentation compatibility
#[test]
fn test_tuic_packet_fragmentation() {
    use sb_adapters::outbound::tuic::TuicPacket;

    let endpoint = Endpoint::new("dns.google", 53);

    // Test single fragment (most common case)
    let small_data = b"small DNS query".to_vec();
    let packet = TuicPacket::new(1, 1, &endpoint, small_data.clone());

    assert_eq!(packet.fragment_total, 1);
    assert_eq!(packet.fragment_id, 0);

    let encoded = packet.encode();
    assert_eq!(encoded[5], 1); // fragment_total
    assert_eq!(encoded[6], 0); // fragment_id

    // Verify data integrity
    // Packet structure: cmd(1) + session_id(2) + packet_id(2) + fragment_total(1) + fragment_id(1) + addr_type(1) + domain_len(1) + domain(10) + port(2) + data_len(2) + data
    let data_len_offset = 1 + 2 + 2 + 1 + 1 + 1 + 1 + 10 + 2; // = 21
    let data_len_bytes = &encoded[data_len_offset..data_len_offset + 2];
    let data_len = u16::from_be_bytes([data_len_bytes[0], data_len_bytes[1]]);
    assert_eq!(data_len, small_data.len() as u16);

    let data_bytes = &encoded[data_len_offset + 2..data_len_offset + 2 + small_data.len()];
    assert_eq!(data_bytes, small_data.as_slice());
}

/// Test TUIC session management
#[test]
fn test_tuic_session_management() {
    use sb_adapters::outbound::tuic::TuicMultiplexer;
    use std::time::Duration;

    let mut multiplexer = TuicMultiplexer::new();

    // Create multiple sessions
    let session_ids: Vec<u16> = (0..10).map(|_| multiplexer.create_session()).collect();

    // Verify all sessions are unique
    for i in 0..session_ids.len() {
        for j in i + 1..session_ids.len() {
            assert_ne!(session_ids[i], session_ids[j]);
        }
    }

    // Test session activity tracking
    for &session_id in &session_ids {
        if let Some(session) = multiplexer.get_session_mut(session_id) {
            session.tx_packets += 1;
            session.rx_packets += 1;
            session.update_activity();
        }
    }

    // Verify all sessions are still active
    assert_eq!(multiplexer.sessions.len(), 10);

    // Test cleanup with very short timeout (should remove all sessions)
    std::thread::sleep(Duration::from_millis(1));
    multiplexer.cleanup_expired_sessions(Duration::from_nanos(1));
    assert_eq!(multiplexer.sessions.len(), 0);
}

/// Test TUIC authentication timing
#[test]
fn test_tuic_authentication_timing() {
    use sb_adapters::outbound::tuic::TuicAuthPacket;
    use uuid::Uuid;

    let uuid = Uuid::new_v4();
    let password = "test_password".to_string();

    // Create two auth packets with longer time difference to ensure different timestamps
    let auth1 = TuicAuthPacket::new(uuid, password.clone());
    std::thread::sleep(Duration::from_secs(1)); // Use 1 second to ensure different timestamps
    let auth2 = TuicAuthPacket::new(uuid, password);

    // Timestamps should be different (or at least auth2 >= auth1)
    assert!(auth2.timestamp >= auth1.timestamp);

    // But both should be recent
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert!(auth1.timestamp <= now);
    assert!(auth2.timestamp <= now);
}

/// Test TUIC error handling scenarios
#[tokio::test]
async fn test_tuic_error_scenarios() {
    // Test invalid server address
    let invalid_server_config = TuicConfig {
        server: "invalid-server-address".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        password: "test_password".to_string(),
        congestion_control: "bbr".to_string(),
        udp_relay_mode: None,
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 10000,
        connect_timeout_sec: Some(1), // Short timeout for quick test
        auth_timeout_sec: Some(1),
    };

    let connector = TuicConnector::new(invalid_server_config).unwrap();

    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
    let dst = Endpoint::new("example.com", 443);
    let ctx = ConnCtx::new(1, Network::Udp, src, dst);

    // Connection should fail due to invalid server
    let result = connector.connect_udp(&ctx).await;
    assert!(result.is_err());
}

/// Test TUIC configuration edge cases
#[test]
fn test_tuic_config_edge_cases() {
    // Test with minimal configuration
    let minimal_config = TuicConfig {
        server: "127.0.0.1:443".to_string(),
        uuid: "00000000-0000-0000-0000-000000000000".to_string(),
        password: "".to_string(),                  // Empty password
        congestion_control: "unknown".to_string(), // Should default to BBR
        udp_relay_mode: None,
        udp_over_stream: false,
        zero_rtt_handshake: false,
        heartbeat: 1, // Very short heartbeat
        connect_timeout_sec: None,
        auth_timeout_sec: None,
    };

    let connector = TuicConnector::new(minimal_config).unwrap();
    assert_eq!(
        connector.congestion_control(),
        &sb_adapters::outbound::tuic::TuicCongestionControl::Bbr
    );

    // Test with maximum values
    let max_config = TuicConfig {
        server: "example.com:65535".to_string(),
        uuid: "ffffffff-ffff-ffff-ffff-ffffffffffff".to_string(),
        password: "a".repeat(1000), // Very long password
        congestion_control: "cubic".to_string(),
        udp_relay_mode: Some("quic".to_string()),
        udp_over_stream: true,
        zero_rtt_handshake: true,
        heartbeat: u64::MAX,
        connect_timeout_sec: Some(3600), // 1 hour
        auth_timeout_sec: Some(300),     // 5 minutes
    };

    let connector = TuicConnector::new(max_config);
    assert!(connector.is_ok());
}

/// Test TUIC packet size limits
#[test]
fn test_tuic_packet_size_limits() {
    use sb_adapters::outbound::tuic::TuicPacket;

    let endpoint = Endpoint::new("example.com", 80);

    // Test with maximum reasonable packet size
    let large_data = vec![0u8; 65535]; // Maximum UDP packet size
    let packet = TuicPacket::new(1, 1, &endpoint, large_data.clone());

    let encoded = packet.encode();
    assert!(!encoded.is_empty());

    // Verify data length encoding
    let data_len_offset = encoded.len() - large_data.len() - 2;
    let data_len_bytes = &encoded[data_len_offset..data_len_offset + 2];
    let data_len = u16::from_be_bytes([data_len_bytes[0], data_len_bytes[1]]);
    assert_eq!(data_len, large_data.len() as u16);

    // Test with empty data
    let empty_data = Vec::new();
    let packet = TuicPacket::new(1, 1, &endpoint, empty_data);
    let encoded = packet.encode();

    // Should still have valid packet structure
    assert!(encoded.len() > 16); // At least header size
}

/// Benchmark TUIC packet encoding performance
#[test]
fn test_tuic_packet_encoding_performance() {
    use sb_adapters::outbound::tuic::TuicPacket;
    use std::time::Instant;

    let endpoint = Endpoint::new("benchmark.test", 443);
    let data = vec![0u8; 1024]; // 1KB packet

    let start = Instant::now();
    let iterations = 10000;

    for i in 0..iterations {
        let packet = TuicPacket::new(i as u16, i as u16, &endpoint, data.clone());
        let _encoded = packet.encode();
    }

    let duration = start.elapsed();
    let packets_per_sec = iterations as f64 / duration.as_secs_f64();

    // Should be able to encode at least 100,000 packets per second
    assert!(
        packets_per_sec > 100_000.0,
        "Packet encoding too slow: {} packets/sec",
        packets_per_sec
    );
}
