#![cfg(feature = "adapter-tuic")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! TUIC outbound integration tests for the current adapter API.

use sb_adapters::outbound::tuic::{TuicAdapterConfig, TuicConnector, TuicUdpRelayMode};
use uuid::Uuid;

#[test]
fn tuic_adapter_config_uses_current_fields() {
    let cfg = TuicAdapterConfig {
        tag: None,
        server: "example.com".to_string(),
        port: 443,
        uuid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        token: "test-token".to_string(),
        password: Some("test-password".to_string()),
        congestion_control: Some("bbr".to_string()),
        alpn: Some("tuic,h3".to_string()),
        skip_cert_verify: false,
        udp_relay_mode: TuicUdpRelayMode::Quic,
        udp_over_stream: true,
    };

    let connector = TuicConnector::new(cfg.clone());
    assert_eq!(connector.name(), "tuic");
    assert_eq!(cfg.server, "example.com");
    assert_eq!(cfg.port, 443);
    assert_eq!(cfg.token, "test-token");
    assert!(matches!(cfg.udp_relay_mode, TuicUdpRelayMode::Quic));
    assert!(cfg.udp_over_stream);
}

#[test]
fn tuic_udp_packet_roundtrip_domain() {
    let payload = b"dns query data";
    let encoded = TuicConnector::encode_udp_packet("example.com", 53, payload);
    let (host, port, decoded_payload) = TuicConnector::decode_udp_packet(&encoded).unwrap();

    assert_eq!(host, "example.com");
    assert_eq!(port, 53);
    assert_eq!(decoded_payload, payload);
}

#[test]
fn tuic_udp_packet_roundtrip_ipv4() {
    let payload = b"hello";
    let encoded = TuicConnector::encode_udp_packet("127.0.0.1", 443, payload);
    let (host, port, decoded_payload) = TuicConnector::decode_udp_packet(&encoded).unwrap();

    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 443);
    assert_eq!(decoded_payload, payload);
}

#[test]
fn tuic_udp_packet_rejects_truncated_length() {
    let err = TuicConnector::decode_udp_packet(&[0x00]).expect_err("short packet must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}
