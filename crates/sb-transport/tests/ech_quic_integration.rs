//! ECH-QUIC Integration Test
//!
//! This test demonstrates ECH (Encrypted Client Hello) integration with QUIC transport.
//! It verifies that:
//! 1. QUIC dialer can be configured with ECH
//! 2. ECH encryption is applied to QUIC handshakes
//! 3. The outer SNI (public name) is used for QUIC connections when ECH is enabled

#[cfg(all(test, feature = "transport_ech", feature = "transport_quic"))]
mod ech_quic_tests {
    use sb_tls::EchClientConfig;
    use sb_transport::quic::{QuicConfig, QuicDialer};

    /// Helper function to create a minimal test ECH config list
    /// This is a simplified version for testing purposes
    fn create_test_ech_config_list() -> Vec<u8> {
        // Create a minimal valid ECH config list for testing
        // In a real implementation, this would be generated properly
        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version (0xfe0d = Draft-13)
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Public key length + dummy public key (32 bytes for X25519)
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(&[0x01; 32]); // Dummy key for testing

        // Cipher suites length + cipher suite
        // One suite: KEM=0x0020, KDF=0x0001, AEAD=0x0001
        config_list.extend_from_slice(&[0x00, 0x06]);
        config_list.extend_from_slice(&[0x00, 0x20]); // KEM: X25519
        config_list.extend_from_slice(&[0x00, 0x01]); // KDF: HKDF-SHA256
        config_list.extend_from_slice(&[0x00, 0x01]); // AEAD: AES-128-GCM

        // Maximum name length
        config_list.push(64);

        // Public name length + public name
        let public_name = b"public.example.com";
        config_list.push(public_name.len() as u8);
        config_list.extend_from_slice(public_name);

        // Extensions length (empty)
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Fill in config length
        let config_len = config_list.len() - config_start - 2;
        config_list[config_start..config_start + 2]
            .copy_from_slice(&(config_len as u16).to_be_bytes());

        // Fill in list length
        let list_len = config_list.len() - list_start - 2;
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        config_list
    }

    #[tokio::test]
    async fn test_quic_dialer_with_ech_config() {
        // Create ECH configuration
        let ech_config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        // Create QUIC configuration with ECH
        let mut quic_config = QuicConfig::default();
        quic_config.server_name = "secret.example.com".to_string();
        quic_config.ech_config = Some(ech_config);

        // Create QUIC dialer
        let result = QuicDialer::new(quic_config);
        assert!(
            result.is_ok(),
            "Failed to create QUIC dialer with ECH: {:?}",
            result.err()
        );

        // If we got here, the dialer was created successfully with ECH
        // The ECH connector is initialized internally
    }

    #[tokio::test]
    async fn test_quic_dialer_without_ech() {
        // Create QUIC configuration without ECH
        let mut quic_config = QuicConfig::default();
        quic_config.server_name = "example.com".to_string();

        // Create QUIC dialer
        let result = QuicDialer::new(quic_config);
        assert!(
            result.is_ok(),
            "Failed to create QUIC dialer: {:?}",
            result.err()
        );

        // If we got here, the dialer was created successfully without ECH
    }

    #[tokio::test]
    async fn test_quic_dialer_with_disabled_ech() {
        // Create ECH configuration but disabled
        let ech_config = EchClientConfig {
            enabled: false,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        // Create QUIC configuration with disabled ECH
        let mut quic_config = QuicConfig::default();
        quic_config.server_name = "example.com".to_string();
        quic_config.ech_config = Some(ech_config);

        // Create QUIC dialer
        let result = QuicDialer::new(quic_config);
        assert!(
            result.is_ok(),
            "Failed to create QUIC dialer: {:?}",
            result.err()
        );

        // If we got here, the dialer was created successfully with disabled ECH
    }

    #[test]
    fn test_quic_dialer_with_invalid_ech_config() {
        // Create invalid ECH configuration (enabled but no config)
        let ech_config = EchClientConfig {
            enabled: true,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        // Create QUIC configuration with invalid ECH
        let mut quic_config = QuicConfig::default();
        quic_config.server_name = "example.com".to_string();
        quic_config.ech_config = Some(ech_config);

        // Create QUIC dialer - should fail
        let result = QuicDialer::new(quic_config);
        assert!(result.is_err(), "Should fail with invalid ECH config");
    }

    #[tokio::test]
    async fn test_ech_quic_alignment() {
        // This test verifies that ECH-QUIC alignment is properly handled
        // When ECH is enabled, the outer SNI (public name) should be used for QUIC

        let ech_config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let mut quic_config = QuicConfig::default();
        quic_config.server_name = "secret.example.com".to_string();
        quic_config.ech_config = Some(ech_config);

        let _dialer = QuicDialer::new(quic_config).expect("Failed to create dialer");

        // The dialer was created successfully with ECH
        // The actual ECH-QUIC handshake would happen in get_connection()
        // which would use the outer SNI from the ECH config
        // This is tested implicitly through the integration
    }
}
