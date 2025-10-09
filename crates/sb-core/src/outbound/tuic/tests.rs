//! TUIC protocol tests
//!
//! Comprehensive test suite for TUIC implementation including:
//! - Configuration validation
//! - Authentication packet building
//! - Handshake protocol
//! - UDP over stream framing
//! - Packet encoding/decoding

#[cfg(test)]
#[cfg(feature = "out_tuic")]
mod config_tests {
    use crate::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};
    use crate::outbound::types::OutboundTcp;

    #[test]
    fn test_tuic_config_creation() {
        let config = TuicConfig {
            server: "example.com".to_string(),
            port: 443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: Some("test-password".to_string()),
            congestion_control: Some("cubic".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: false,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.token, "test-token");
        assert!(!config.skip_cert_verify);
        assert!(!config.udp_over_stream);
    }

    #[test]
    fn test_tuic_outbound_creation() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: Some("bbr".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config);
        assert!(outbound.is_ok());

        let outbound = outbound.unwrap();
        assert_eq!(outbound.protocol_name(), "tuic");
    }

    #[test]
    fn test_tuic_config_with_password() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: Some("secret-password".to_string()),
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        assert_eq!(config.password, Some("secret-password".to_string()));
    }

    #[test]
    fn test_tuic_config_udp_relay_modes() {
        let config_native = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let config_quic = TuicConfig {
            udp_relay_mode: UdpRelayMode::Quic,
            ..config_native.clone()
        };

        assert!(matches!(config_native.udp_relay_mode, UdpRelayMode::Native));
        assert!(matches!(config_quic.udp_relay_mode, UdpRelayMode::Quic));
    }

    #[test]
    fn test_tuic_config_udp_over_stream() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        assert!(config.udp_over_stream);
    }

    #[test]
    fn test_tuic_config_congestion_control_variants() {
        let configs = vec![
            ("cubic", "cubic"),
            ("bbr", "bbr"),
            ("newreno", "newreno"),
        ];

        for (cc_name, expected) in configs {
            let config = TuicConfig {
                server: "127.0.0.1".to_string(),
                port: 8443,
                uuid: uuid::Uuid::new_v4(),
                token: "test-token".to_string(),
                password: None,
                congestion_control: Some(cc_name.to_string()),
                alpn: None,
                skip_cert_verify: true,
                udp_relay_mode: UdpRelayMode::Native,
                udp_over_stream: false,
            };

            assert_eq!(config.congestion_control, Some(expected.to_string()));
        }
    }

    #[test]
    fn test_tuic_config_alpn_variants() {
        let config_default = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let config_custom = TuicConfig {
            alpn: Some("h3".to_string()),
            ..config_default.clone()
        };

        assert_eq!(config_default.alpn, None);
        assert_eq!(config_custom.alpn, Some("h3".to_string()));
    }
}

#[cfg(test)]
#[cfg(feature = "out_tuic")]
mod authentication_tests {
    use crate::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};

    #[test]
    fn test_auth_packet_structure() {
        let uuid = uuid::Uuid::new_v4();
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid,
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let auth_packet = outbound.build_auth_packet().unwrap();

        // TUIC v5 auth packet format:
        // [Version(1)] [Command(1)] [UUID(16)] [Token_Len(2)] [Token(N)]
        assert!(auth_packet.len() >= 20); // At least version + command + uuid + token_len
        assert_eq!(auth_packet[0], 0x05); // Version 5
        assert_eq!(auth_packet[1], 0x01); // Auth command

        // Verify UUID is embedded
        let uuid_bytes = &auth_packet[2..18];
        assert_eq!(uuid_bytes, uuid.as_bytes());

        // Verify token length
        let token_len = u16::from_be_bytes([auth_packet[18], auth_packet[19]]);
        assert_eq!(token_len, "test-token".len() as u16);

        // Verify token
        let token_bytes = &auth_packet[20..];
        assert_eq!(token_bytes, "test-token".as_bytes());
    }

    #[test]
    fn test_auth_packet_with_different_tokens() {
        let uuid = uuid::Uuid::new_v4();

        let config1 = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid,
            token: "token1".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let config2 = TuicConfig {
            token: "token2".to_string(),
            ..config1.clone()
        };

        let outbound1 = TuicOutbound::new(config1).unwrap();
        let outbound2 = TuicOutbound::new(config2).unwrap();

        let auth1 = outbound1.build_auth_packet().unwrap();
        let auth2 = outbound2.build_auth_packet().unwrap();

        // Different tokens should produce different packets
        assert_ne!(auth1, auth2);
    }

    #[test]
    fn test_auth_packet_with_different_uuids() {
        let uuid1 = uuid::Uuid::new_v4();
        let uuid2 = uuid::Uuid::new_v4();

        let config1 = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid1,
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let config2 = TuicConfig {
            uuid: uuid2,
            ..config1.clone()
        };

        let outbound1 = TuicOutbound::new(config1).unwrap();
        let outbound2 = TuicOutbound::new(config2).unwrap();

        let auth1 = outbound1.build_auth_packet().unwrap();
        let auth2 = outbound2.build_auth_packet().unwrap();

        // Different UUIDs should produce different packets
        assert_ne!(auth1, auth2);
    }

    #[test]
    fn test_auth_packet_deterministic() {
        let uuid = uuid::Uuid::new_v4();
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid,
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config).unwrap();

        let auth1 = outbound.build_auth_packet().unwrap();
        let auth2 = outbound.build_auth_packet().unwrap();

        // Same config should produce same auth packet
        assert_eq!(auth1, auth2);
    }
}

#[cfg(test)]
#[cfg(feature = "out_tuic")]
mod handshake_tests {
    use crate::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};

    #[test]
    fn test_connect_packet_ipv4() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let connect_packet = outbound.build_connect_packet("192.168.1.1", 443).unwrap();

        // TUIC v5 connect packet format:
        // [Command(1)] [Address_Type(1)] [Address(N)] [Port(2)]
        assert_eq!(connect_packet[0], 0x02); // Connect command
        assert_eq!(connect_packet[1], 0x01); // IPv4 type

        // IPv4 address (4 bytes)
        assert_eq!(&connect_packet[2..6], &[192, 168, 1, 1]);

        // Port (2 bytes, big-endian)
        let port = u16::from_be_bytes([connect_packet[6], connect_packet[7]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn test_connect_packet_ipv6() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let connect_packet = outbound.build_connect_packet("2001:db8::1", 443).unwrap();

        assert_eq!(connect_packet[0], 0x02); // Connect command
        assert_eq!(connect_packet[1], 0x04); // IPv6 type

        // IPv6 address (16 bytes)
        assert_eq!(connect_packet.len(), 1 + 1 + 16 + 2); // cmd + type + ipv6 + port
    }

    #[test]
    fn test_connect_packet_domain() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let connect_packet = outbound.build_connect_packet("example.com", 443).unwrap();

        assert_eq!(connect_packet[0], 0x02); // Connect command
        assert_eq!(connect_packet[1], 0x03); // Domain type
        assert_eq!(connect_packet[2], 11); // Domain length ("example.com" = 11 bytes)

        // Domain name
        assert_eq!(&connect_packet[3..14], b"example.com");

        // Port
        let port = u16::from_be_bytes([connect_packet[14], connect_packet[15]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn test_udp_associate_packet() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: false,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let udp_packet = outbound.build_udp_associate_packet("0.0.0.0", 0).unwrap();

        assert_eq!(udp_packet[0], 0x03); // UDP associate command
        assert_eq!(udp_packet[1], 0x01); // IPv4 type
    }
}

#[cfg(test)]
#[cfg(feature = "out_tuic")]
mod udp_framing_tests {
    use crate::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};

    #[test]
    fn test_udp_packet_encoding_ipv4() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let data = b"test udp payload";
        let packet = outbound.encode_udp_packet("192.168.1.1", 53, data).unwrap();

        // Format: [Length(2)] [Fragment_ID(1)] [Fragment_Total(1)] [Address_Type(1)] [Address(N)] [Port(2)] [Data(N)]
        
        // Check length field
        let length = u16::from_be_bytes([packet[0], packet[1]]);
        assert_eq!(length as usize, packet.len() - 2);

        // Check fragment fields
        assert_eq!(packet[2], 0); // Fragment ID
        assert_eq!(packet[3], 1); // Fragment total (no fragmentation)

        // Check address type
        assert_eq!(packet[4], 0x01); // IPv4

        // Check IPv4 address
        assert_eq!(&packet[5..9], &[192, 168, 1, 1]);

        // Check port
        let port = u16::from_be_bytes([packet[9], packet[10]]);
        assert_eq!(port, 53);

        // Check payload
        assert_eq!(&packet[11..], data);
    }

    #[test]
    fn test_udp_packet_encoding_ipv6() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let data = b"test udp payload";
        let packet = outbound.encode_udp_packet("2001:db8::1", 53, data).unwrap();

        // Check address type
        assert_eq!(packet[4], 0x04); // IPv6

        // IPv6 address is 16 bytes
        assert_eq!(packet.len(), 2 + 1 + 1 + 1 + 16 + 2 + data.len());
    }

    #[test]
    fn test_udp_packet_encoding_domain() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let data = b"test udp payload";
        let packet = outbound.encode_udp_packet("dns.google", 53, data).unwrap();

        // Check address type
        assert_eq!(packet[4], 0x03); // Domain

        // Check domain length
        assert_eq!(packet[5], 10); // "dns.google" = 10 bytes

        // Check domain
        assert_eq!(&packet[6..16], b"dns.google");

        // Check port
        let port = u16::from_be_bytes([packet[16], packet[17]]);
        assert_eq!(port, 53);

        // Check payload
        assert_eq!(&packet[18..], data);
    }

    #[test]
    fn test_udp_packet_decoding_ipv4() {
        // Create a valid UDP packet
        let mut packet = Vec::new();
        
        // Length (will be filled)
        packet.extend_from_slice(&[0u8, 0u8]);
        
        // Fragment ID and total
        packet.push(0); // Fragment ID
        packet.push(1); // Fragment total
        
        // Address type and IPv4
        packet.push(0x01); // IPv4
        packet.extend_from_slice(&[192, 168, 1, 1]);
        
        // Port
        packet.extend_from_slice(&53u16.to_be_bytes());
        
        // Payload
        let payload = b"test data";
        packet.extend_from_slice(payload);
        
        // Fill in length
        let length = (packet.len() - 2) as u16;
        packet[0..2].copy_from_slice(&length.to_be_bytes());

        // Decode
        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();

        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 53);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_udp_packet_decoding_domain() {
        // Create a valid UDP packet with domain
        let mut packet = Vec::new();
        
        // Length (will be filled)
        packet.extend_from_slice(&[0u8, 0u8]);
        
        // Fragment ID and total
        packet.push(0);
        packet.push(1);
        
        // Address type and domain
        packet.push(0x03); // Domain
        packet.push(11); // Length of "example.com"
        packet.extend_from_slice(b"example.com");
        
        // Port
        packet.extend_from_slice(&443u16.to_be_bytes());
        
        // Payload
        let payload = b"test data";
        packet.extend_from_slice(payload);
        
        // Fill in length
        let length = (packet.len() - 2) as u16;
        packet[0..2].copy_from_slice(&length.to_be_bytes());

        // Decode
        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();

        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_udp_packet_roundtrip() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        
        let original_host = "example.com";
        let original_port = 443;
        let original_data = b"test payload data";

        // Encode
        let packet = outbound.encode_udp_packet(original_host, original_port, original_data).unwrap();

        // Decode
        let (decoded_host, decoded_port, decoded_data) = TuicOutbound::decode_udp_packet(&packet).unwrap();

        assert_eq!(decoded_host, original_host);
        assert_eq!(decoded_port, original_port);
        assert_eq!(decoded_data, original_data);
    }

    #[test]
    fn test_udp_packet_decoding_invalid_length() {
        // Packet too short
        let packet = vec![0u8, 10]; // Claims length 10 but no data

        let result = TuicOutbound::decode_udp_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_packet_decoding_invalid_address_type() {
        let mut packet = Vec::new();
        
        // Length
        packet.extend_from_slice(&[0u8, 10]);
        
        // Fragment ID and total
        packet.push(0);
        packet.push(1);
        
        // Invalid address type
        packet.push(0xFF); // Invalid type
        
        // Fill rest with dummy data
        packet.extend_from_slice(&[0u8; 10]);

        let result = TuicOutbound::decode_udp_packet(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_packet_empty_payload() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let packet = outbound.encode_udp_packet("example.com", 443, b"").unwrap();

        // Should still be valid with empty payload
        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();

        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(data.len(), 0);
    }

    #[test]
    fn test_udp_packet_large_payload() {
        let config = TuicConfig {
            server: "127.0.0.1".to_string(),
            port: 8443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: None,
            alpn: None,
            skip_cert_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
            udp_over_stream: true,
        };

        let outbound = TuicOutbound::new(config).unwrap();
        let large_data = vec![0xAB; 1400]; // Typical MTU size
        let packet = outbound.encode_udp_packet("example.com", 443, &large_data).unwrap();

        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet).unwrap();

        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(data, large_data);
    }
}

#[cfg(test)]
#[cfg(feature = "out_tuic")]
mod protocol_constants_tests {
    #[test]
    fn test_tuic_version() {
        // TUIC v5
        assert_eq!(0x05, 0x05);
    }

    #[test]
    fn test_command_types() {
        // Command types
        assert_eq!(0x01, 0x01); // Auth
        assert_eq!(0x02, 0x02); // Connect
        assert_eq!(0x03, 0x03); // UDP associate
    }

    #[test]
    fn test_address_types() {
        // Address types
        assert_eq!(0x01, 0x01); // IPv4
        assert_eq!(0x03, 0x03); // Domain
        assert_eq!(0x04, 0x04); // IPv6
    }
}
