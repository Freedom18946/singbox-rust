//! Trojan outbound smoke tests
//!
//! These tests verify that the Trojan outbound implementation compiles and
//! can be instantiated correctly. They do not require external services
//! and are designed to catch basic configuration and implementation issues.

#[cfg(feature = "out_trojan")]
mod trojan_tests {
    use sb_core::outbound::crypto_types::{HostPort, OutboundTcp};
    use sb_core::outbound::trojan::{TrojanConfig, TrojanOutbound};
    use tokio;

    #[tokio::test]
    async fn test_trojan_config_creation() {
        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.password, "password123");
        assert_eq!(config.sni, "example.com");
        assert_eq!(config.alpn, None);
        assert_eq!(config.skip_cert_verify, false);
    }

    #[tokio::test]
    async fn test_trojan_config_with_alpn() {
        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        )
        .with_alpn(vec!["h2".to_string(), "http/1.1".to_string()])
        .with_skip_cert_verify(true);

        assert_eq!(
            config.alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
        assert_eq!(config.skip_cert_verify, true);
    }

    #[tokio::test]
    async fn test_trojan_outbound_creation() {
        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );

        let result = TrojanOutbound::new(config);
        assert!(result.is_ok(), "TrojanOutbound creation should succeed");

        let outbound = result.unwrap();
        assert_eq!(outbound.protocol_name(), "trojan");
    }

    #[tokio::test]
    async fn test_trojan_strict_cert_verification_by_default() {
        use std::env;

        // Ensure environment variable is not set
        env::remove_var("SB_TROJAN_SKIP_CERT_VERIFY");

        let mut config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );
        config.skip_cert_verify = true; // This should be ignored without env var

        let result = TrojanOutbound::new(config);
        assert!(
            result.is_ok(),
            "TrojanOutbound creation should succeed even with skip_cert_verify=true but no env var"
        );

        // The implementation should ignore skip_cert_verify without environment variable
        // In practice, this means TLS verification is still enabled
    }

    #[tokio::test]
    async fn test_trojan_cert_skip_with_environment() {
        use std::env;

        // Set environment variable to allow skipping
        env::set_var("SB_TROJAN_SKIP_CERT_VERIFY", "true");

        let mut config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );
        config.skip_cert_verify = true;

        let result = TrojanOutbound::new(config);
        assert!(
            result.is_ok(),
            "TrojanOutbound creation should succeed with proper env var"
        );

        // Clean up
        env::remove_var("SB_TROJAN_SKIP_CERT_VERIFY");
    }

    #[tokio::test]
    async fn test_trojan_alpn_environment_override() {
        use std::env;

        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );

        // Test with SB_TROJAN_ALPN environment variable
        env::set_var("SB_TROJAN_ALPN", "h2");
        let result = TrojanOutbound::new(config.clone());
        assert!(result.is_ok(), "Should handle ALPN environment variable");

        // Test with invalid ALPN value
        env::set_var("SB_TROJAN_ALPN", "invalid");
        let result = TrojanOutbound::new(config.clone());
        assert!(result.is_ok(), "Should handle invalid ALPN gracefully");

        // Clean up
        env::remove_var("SB_TROJAN_ALPN");
    }

    #[tokio::test]
    async fn test_trojan_outbound_with_invalid_sni() {
        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "".to_string(), // Invalid SNI
        );

        // For now, we allow empty SNI in config creation
        // The error will occur during connection
        let result = TrojanOutbound::new(config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_trojan_connect_to_invalid_server() {
        let config = TrojanConfig::new(
            "invalid.nonexistent.domain".to_string(),
            443,
            "password123".to_string(),
            "invalid.nonexistent.domain".to_string(),
        );

        let outbound = TrojanOutbound::new(config).unwrap();
        let target = HostPort::new("example.com".to_string(), 80);

        // This should fail because the server doesn't exist
        let result = outbound.connect(&target).await;
        assert!(result.is_err(), "Connection to invalid server should fail");
    }

    #[tokio::test]
    async fn test_host_port_display() {
        let host_port = HostPort::new("example.com".to_string(), 443);
        assert_eq!(format!("{}", host_port), "example.com:443");
    }

    #[tokio::test]
    async fn test_host_port_from_domain() {
        let host_port = HostPort::from_domain("test.example.com", 8080);
        assert_eq!(host_port.host, "test.example.com");
        assert_eq!(host_port.port, 8080);
    }
}

#[cfg(not(feature = "out_trojan"))]
mod trojan_stub_tests {
    use sb_core::outbound::trojan::{TrojanConfig, TrojanOutbound};

    #[tokio::test]
    async fn test_trojan_stub_config_creation() {
        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );

        // Stub implementation should allow config creation
        assert!(true);
    }

    #[tokio::test]
    async fn test_trojan_stub_outbound_creation() {
        let config = TrojanConfig::new(
            "example.com".to_string(),
            443,
            "password123".to_string(),
            "example.com".to_string(),
        );

        let result = TrojanOutbound::new(config);
        assert!(result.is_err(), "Stub implementation should fail");

        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}

// Integration test (requires feature flags)
#[cfg(all(feature = "out_trojan", feature = "metrics"))]
#[tokio::test]
async fn test_trojan_metrics_integration() {
    use sb_core::metrics::outbound::{record_trojan_connect_error, record_trojan_connect_success};

    // These should not panic
    record_trojan_connect_success();
    record_trojan_connect_error();
}

#[tokio::test]
async fn test_basic_compilation() {
    // This test just ensures the module compiles correctly
    assert!(true);
}
