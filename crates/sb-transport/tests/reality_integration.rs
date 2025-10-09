//! Integration tests for REALITY TLS transport

#[cfg(feature = "transport_reality")]
mod reality_tests {
    use sb_transport::{RealityDialer, TcpDialer};
    use sb_tls::RealityClientConfig;

    #[test]
    fn test_reality_dialer_creation() {
        // Create a valid REALITY configuration
        let config = RealityClientConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        // Create REALITY dialer
        let dialer = RealityDialer::new(TcpDialer, config);
        assert!(dialer.is_ok(), "Failed to create REALITY dialer");
    }

    #[test]
    fn test_reality_dialer_invalid_config() {
        // Create an invalid REALITY configuration (empty target)
        let config = RealityClientConfig {
            target: "".to_string(), // Invalid: empty target
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        // Should fail to create dialer
        let dialer = RealityDialer::new(TcpDialer, config);
        assert!(dialer.is_err(), "Should fail with invalid config");
    }

    #[test]
    fn test_reality_dialer_from_env_missing_vars() {
        // Save current environment state
        let saved_target = std::env::var("SB_REALITY_TARGET").ok();
        let saved_key = std::env::var("SB_REALITY_PUBLIC_KEY").ok();

        // Clear environment variables
        std::env::remove_var("SB_REALITY_TARGET");
        std::env::remove_var("SB_REALITY_PUBLIC_KEY");

        // Should fail without required environment variables
        let dialer = RealityDialer::from_env(TcpDialer);
        assert!(dialer.is_err(), "Should fail without environment variables");

        // Restore environment state
        if let Some(target) = saved_target {
            std::env::set_var("SB_REALITY_TARGET", target);
        }
        if let Some(key) = saved_key {
            std::env::set_var("SB_REALITY_PUBLIC_KEY", key);
        }
    }

    #[test]
    fn test_reality_dialer_from_env_with_vars() {
        // Set required environment variables
        std::env::set_var("SB_REALITY_TARGET", "www.apple.com");
        std::env::set_var(
            "SB_REALITY_PUBLIC_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        std::env::set_var("SB_REALITY_SHORT_ID", "01ab");
        std::env::set_var("SB_REALITY_FINGERPRINT", "firefox");

        // Should succeed with environment variables
        let dialer = RealityDialer::from_env(TcpDialer);
        assert!(dialer.is_ok(), "Should succeed with environment variables");

        // Clean up
        std::env::remove_var("SB_REALITY_TARGET");
        std::env::remove_var("SB_REALITY_PUBLIC_KEY");
        std::env::remove_var("SB_REALITY_SHORT_ID");
        std::env::remove_var("SB_REALITY_FINGERPRINT");
    }

    #[test]
    fn test_reality_dialer_from_env_defaults() {
        // Set only required environment variables
        std::env::set_var("SB_REALITY_TARGET", "www.example.com");
        std::env::set_var(
            "SB_REALITY_PUBLIC_KEY",
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        );

        // Should succeed and use defaults for optional vars
        let dialer = RealityDialer::from_env(TcpDialer);
        assert!(dialer.is_ok(), "Should succeed with defaults");

        if let Ok(dialer) = dialer {
            // Verify defaults are applied
            assert_eq!(
                dialer.connector.config().server_name,
                "www.example.com",
                "server_name should default to target"
            );
            assert_eq!(
                dialer.connector.config().fingerprint,
                "chrome",
                "fingerprint should default to chrome"
            );
        }

        // Clean up
        std::env::remove_var("SB_REALITY_TARGET");
        std::env::remove_var("SB_REALITY_PUBLIC_KEY");
    }
}
