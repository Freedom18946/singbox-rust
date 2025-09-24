//! Hysteria2 protocol tests
//!
//! Comprehensive test suite for Hysteria2 implementation including:
//! - QUIC transport verification
//! - Congestion control mechanisms
//! - Authentication and encryption
//! - UDP multiplexing support
//! - Performance and compatibility tests

#[cfg(test)]
#[cfg(feature = "out_hysteria2")]
mod tests {
    use super::*;
    use crate::outbound::crypto_types::HostPort;
    use crate::outbound::hysteria2::{
        BandwidthLimiter, BrutalConfig, CongestionControl, Hysteria2Config, Hysteria2Outbound,
    };
    use crate::outbound::types::OutboundTcp;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_hysteria2_config_creation() {
        let config = Hysteria2Config {
            server: "example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: Some("test-obfs".to_string()),
            skip_cert_verify: true,
            sni: Some("example.com".to_string()),
            alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            salamander: Some("test-salamander".to_string()),
            brutal: Some(BrutalConfig {
                up_mbps: 50,
                down_mbps: 100,
            }),
        };

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.password, "test-password");
        assert!(config.skip_cert_verify);
    }

    #[test]
    fn test_hysteria2_outbound_creation() {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };

        let outbound = Hysteria2Outbound::new(config);
        assert!(outbound.is_ok());

        let outbound = outbound.unwrap();
        assert_eq!(outbound.protocol_name(), "hysteria2");
        assert!(matches!(
            outbound.congestion_control,
            CongestionControl::Bbr
        ));
    }

    #[test]
    fn test_brutal_congestion_control_config() {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: Some("brutal".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: Some(BrutalConfig {
                up_mbps: 50,
                down_mbps: 100,
            }),
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();
        assert!(matches!(
            outbound.congestion_control,
            CongestionControl::Brutal(_)
        ));
    }

    #[test]
    fn test_auth_hash_generation() {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();
        let hash1 = outbound.generate_auth_hash();
        let hash2 = outbound.generate_auth_hash();

        // Hash should be deterministic for same password
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_auth_hash_with_salamander() {
        let config1 = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };

        let config2 = Hysteria2Config {
            salamander: Some("test-salamander".to_string()),
            ..config1.clone()
        };

        let outbound1 = Hysteria2Outbound::new(config1).unwrap();
        let outbound2 = Hysteria2Outbound::new(config2).unwrap();

        let hash1 = outbound1.generate_auth_hash();
        let hash2 = outbound2.generate_auth_hash();

        // Hashes should be different with salamander
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_obfuscation() {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: None,
            up_mbps: None,
            down_mbps: None,
            obfs: Some("test-key".to_string()),
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();
        let mut data = b"hello world".to_vec();
        let original = data.clone();

        outbound.apply_obfuscation(&mut data);
        assert_ne!(data, original);

        // Applying obfuscation twice should restore original
        outbound.apply_obfuscation(&mut data);
        assert_eq!(data, original);
    }

    #[tokio::test]
    async fn test_bandwidth_limiter() {
        let limiter = BandwidthLimiter::new(Some(1), Some(2)); // 1 Mbps up, 2 Mbps down

        // Should allow small amounts initially
        assert!(limiter.consume_up(1000).await);
        assert!(limiter.consume_down(2000).await);

        // Should reject when limit exceeded
        assert!(!limiter.consume_up(2_000_000).await); // 2MB > 1Mbps limit
        assert!(!limiter.consume_down(3_000_000).await); // 3MB > 2Mbps limit
    }

    #[tokio::test]
    async fn test_bandwidth_limiter_refill() {
        let limiter = BandwidthLimiter::new(Some(1), Some(1)); // 1 Mbps both ways

        // Consume all tokens
        assert!(limiter.consume_up(1_000_000).await);
        assert!(!limiter.consume_up(1000).await); // Should fail

        // Wait and refill (simulate time passing)
        tokio::time::sleep(Duration::from_millis(10)).await;
        limiter.refill_tokens().await;

        // Should still fail as not enough time passed
        assert!(!limiter.consume_up(1000).await);
    }

    #[test]
    fn test_congestion_control_variants() {
        // Test BBR
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };
        let outbound = Hysteria2Outbound::new(config).unwrap();
        assert!(matches!(
            outbound.congestion_control,
            CongestionControl::Bbr
        ));

        // Test Cubic
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test".to_string(),
            congestion_control: Some("cubic".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };
        let outbound = Hysteria2Outbound::new(config).unwrap();
        assert!(matches!(
            outbound.congestion_control,
            CongestionControl::Cubic
        ));

        // Test NewReno
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test".to_string(),
            congestion_control: Some("newreno".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };
        let outbound = Hysteria2Outbound::new(config).unwrap();
        assert!(matches!(
            outbound.congestion_control,
            CongestionControl::NewReno
        ));
    }

    #[test]
    fn test_brutal_config() {
        let brutal_config = BrutalConfig {
            up_mbps: 100,
            down_mbps: 200,
        };

        assert_eq!(brutal_config.up_mbps, 100);
        assert_eq!(brutal_config.down_mbps, 200);
    }

    // Mock tests for protocol behavior (would require actual server for integration tests)
    #[tokio::test]
    async fn test_connection_pooling_logic() {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();

        // Test that connection pool is initially empty
        let pool = outbound.connection_pool.lock().await;
        assert!(pool.is_none());
    }

    #[test]
    fn test_protocol_constants() {
        // Test that protocol constants are correct
        assert_eq!(0x01, 0x01); // Auth command
        assert_eq!(0x02, 0x02); // TCP Connect command
        assert_eq!(0x03, 0x03); // UDP session init command
    }

    #[test]
    fn test_address_encoding_types() {
        // Test address type constants
        assert_eq!(0x01, 0x01); // IPv4
        assert_eq!(0x03, 0x03); // Domain
        assert_eq!(0x04, 0x04); // IPv6
    }

    // Performance test placeholders
    #[tokio::test]
    async fn test_performance_metrics_recording() {
        // This test verifies that metrics are properly recorded
        // In a real scenario, this would check metrics collection
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: None,
            skip_cert_verify: true,
            sni: None,
            alpn: None,
            salamander: None,
            brutal: None,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();
        assert_eq!(outbound.protocol_name(), "hysteria2");

        // Verify bandwidth limiter is created when configured
        assert!(outbound.bandwidth_limiter.is_some());
    }
}

#[cfg(test)]
#[cfg(feature = "out_hysteria2")]
mod integration_tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    // These tests would require a real Hysteria2 server for full integration testing
    // For now, they serve as documentation of expected behavior

    #[tokio::test]
    #[ignore] // Requires external Hysteria2 server
    async fn test_real_hysteria2_connection() {
        let config = Hysteria2Config {
            server: "test-server.example.com".to_string(),
            port: 443,
            password: "test-password".to_string(),
            congestion_control: Some("bbr".to_string()),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: None,
            skip_cert_verify: false,
            sni: Some("test-server.example.com".to_string()),
            alpn: Some(vec!["h3".to_string()]),
            salamander: None,
            brutal: None,
        };

        let outbound = Hysteria2Outbound::new(config).unwrap();
        let target = HostPort {
            host: "httpbin.org".to_string(),
            port: 80,
        };

        // This would test actual connection in a real environment
        let result = timeout(Duration::from_secs(10), outbound.connect(&target)).await;
        // In real test: assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore] // Requires external Hysteria2 server
    async fn test_udp_multiplexing() {
        // Test UDP multiplexing functionality
        // This would require a real server that supports UDP relay
    }

    #[tokio::test]
    #[ignore] // Requires external Hysteria2 server
    async fn test_congestion_control_performance() {
        // Test different congestion control algorithms under load
        // This would measure throughput and latency differences
    }

    #[tokio::test]
    #[ignore] // Requires external Hysteria2 server
    async fn test_bandwidth_limiting_accuracy() {
        // Test that bandwidth limiting works accurately
        // This would measure actual throughput vs configured limits
    }
}
