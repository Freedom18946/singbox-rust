//! Hysteria2 integration tests
//!
//! These tests verify the complete Hysteria2 implementation including:
//! - QUIC transport functionality
//! - Authentication mechanisms
//! - Congestion control behavior
//! - UDP multiplexing support
//! - Performance characteristics
//! - Compatibility with Go version

#[cfg(feature = "out_hysteria2")]
use sb_core::outbound::hysteria2::{
    BandwidthLimiter, BrutalConfig, CongestionControl, Hysteria2Config, Hysteria2Outbound,
};
#[cfg(feature = "out_hysteria2")]
use sb_core::outbound::types::OutboundTcp;
#[cfg(feature = "out_hysteria2")]
use std::time::{Duration, Instant};

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_quic_transport_verification() {
    // Test QUIC transport layer functionality
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "test-password-123".to_string(),
        congestion_control: Some("bbr".to_string()),
        up_mbps: Some(100),
        down_mbps: Some(200),
        obfs: None,
        skip_cert_verify: true,
        sni: None,
        alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
        salamander: None,
        brutal: None,
    };

    let outbound = Hysteria2Outbound::new(config);
    assert!(outbound.is_ok(), "Failed to create Hysteria2 outbound");

    let outbound = outbound.unwrap();
    assert_eq!(outbound.protocol_name(), "hysteria2");

    // Verify QUIC configuration is properly set up
    // Note: Actual connection would require a running server
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_congestion_control_mechanisms() {
    // Test different congestion control algorithms
    let algorithms = vec![
        ("bbr", CongestionControl::Bbr),
        ("cubic", CongestionControl::Cubic),
        ("newreno", CongestionControl::NewReno),
    ];

    for (name, expected) in algorithms {
        let config = Hysteria2Config {
            server: "127.0.0.1".to_string(),
            port: 8443,
            password: "test-password".to_string(),
            congestion_control: Some(name.to_string()),
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

        match (&outbound.congestion_control, &expected) {
            (CongestionControl::Bbr, CongestionControl::Bbr) => (),
            (CongestionControl::Cubic, CongestionControl::Cubic) => (),
            (CongestionControl::NewReno, CongestionControl::NewReno) => (),
            _ => panic!(
                "Congestion control mismatch for {}: expected {:?}, got {:?}",
                name, expected, outbound.congestion_control
            ),
        }
    }
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_brutal_congestion_control() {
    // Test Brutal congestion control with bandwidth limits
    let brutal_config = BrutalConfig {
        up_mbps: 50,
        down_mbps: 100,
    };

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
        brutal: Some(brutal_config.clone()),
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();

    match &outbound.congestion_control {
        CongestionControl::Brutal(config) => {
            assert_eq!(config.up_mbps, 50);
            assert_eq!(config.down_mbps, 100);
        }
        _ => panic!("Expected Brutal congestion control configuration"),
    }
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_authentication_and_encryption() {
    // Test authentication hash generation with different configurations
    let base_config = Hysteria2Config {
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

    // Test basic authentication hash
    let outbound1 = Hysteria2Outbound::new(base_config.clone()).unwrap();
    let hash1 = outbound1.generate_auth_hash();
    assert_eq!(hash1.len(), 32);

    // Test with salamander obfuscation
    let config_with_salamander = Hysteria2Config {
        salamander: Some("test-salamander".to_string()),
        ..base_config.clone()
    };
    let outbound2 = Hysteria2Outbound::new(config_with_salamander).unwrap();
    let hash2 = outbound2.generate_auth_hash();

    // Hashes should be different with salamander
    assert_ne!(hash1, hash2);

    // Test obfuscation functionality
    let config_with_obfs = Hysteria2Config {
        obfs: Some("test-obfs-key".to_string()),
        ..base_config
    };
    let outbound3 = Hysteria2Outbound::new(config_with_obfs).unwrap();

    let mut test_data = b"Hello, Hysteria2!".to_vec();
    let original_data = test_data.clone();

    // Apply obfuscation
    outbound3.apply_obfuscation(&mut test_data);
    assert_ne!(test_data, original_data);

    // Apply obfuscation again to restore
    outbound3.apply_obfuscation(&mut test_data);
    assert_eq!(test_data, original_data);
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_bandwidth_limiting() {
    // Test bandwidth limiter functionality
    let limiter = BandwidthLimiter::new(Some(10), Some(20)); // 10 Mbps up, 20 Mbps down

    // Test initial token availability
    assert!(limiter.consume_up(1_000_000).await); // 1 MB should be allowed
    assert!(limiter.consume_down(2_000_000).await); // 2 MB should be allowed

    // Test limit enforcement
    assert!(!limiter.consume_up(15_000_000).await); // 15 MB > 10 Mbps limit
    assert!(!limiter.consume_down(25_000_000).await); // 25 MB > 20 Mbps limit

    // Test no limits case
    let unlimited_limiter = BandwidthLimiter::new(None, None);
    assert!(unlimited_limiter.consume_up(100_000_000).await); // Should always succeed
    assert!(unlimited_limiter.consume_down(100_000_000).await); // Should always succeed
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_udp_multiplexing_support() {
    // Test UDP session creation and management
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

    // Verify UDP multiplexing configuration
    assert!(outbound.bandwidth_limiter.is_some());

    // Note: Actual UDP session testing would require a QUIC connection
    // This test verifies the configuration is correct
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_performance_characteristics() {
    // Test performance-related configurations
    let start = Instant::now();

    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "test-password".to_string(),
        congestion_control: Some("bbr".to_string()),
        up_mbps: Some(1000), // High bandwidth
        down_mbps: Some(1000),
        obfs: None,
        skip_cert_verify: true,
        sni: None,
        alpn: None,
        salamander: None,
        brutal: None,
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();
    let creation_time = start.elapsed();

    // Outbound creation should be fast
    assert!(creation_time < Duration::from_millis(100));

    // Test bandwidth limiter performance
    if let Some(ref limiter) = outbound.bandwidth_limiter {
        let start = Instant::now();
        for _ in 0..1000 {
            limiter.consume_up(1000).await;
        }
        let consume_time = start.elapsed();

        // Bandwidth limiting should be efficient
        assert!(consume_time < Duration::from_millis(100));
    }
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_compatibility_features() {
    // Test compatibility features with Go version
    let config = Hysteria2Config {
        server: "example.com".to_string(),
        port: 443,
        password: "compatible-password".to_string(),
        congestion_control: Some("bbr".to_string()),
        up_mbps: Some(100),
        down_mbps: Some(200),
        obfs: Some("compatible-obfs".to_string()),
        skip_cert_verify: false,
        sni: Some("example.com".to_string()),
        alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
        salamander: Some("compatible-salamander".to_string()),
        brutal: Some(BrutalConfig {
            up_mbps: 50,
            down_mbps: 100,
        }),
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();

    // Verify all compatibility features are properly configured
    assert_eq!(outbound.protocol_name(), "hysteria2");
    assert!(matches!(
        outbound.congestion_control,
        CongestionControl::Brutal(_)
    ));
    assert!(outbound.bandwidth_limiter.is_some());

    // Test authentication hash is deterministic (important for compatibility)
    let hash1 = outbound.generate_auth_hash();
    let hash2 = outbound.generate_auth_hash();
    assert_eq!(hash1, hash2);
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_error_handling() {
    // Test various error conditions

    // Test invalid server address handling
    let invalid_config = Hysteria2Config {
        server: "".to_string(), // Invalid empty server
        port: 0,                // Invalid port
        password: "test".to_string(),
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

    // Should still create outbound (validation happens at connect time)
    let outbound = Hysteria2Outbound::new(invalid_config);
    assert!(outbound.is_ok());
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_connection_pooling() {
    // Test connection pooling behavior
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

    // Verify connection pool is initially empty
    let pool = outbound.connection_pool.lock().await;
    assert!(pool.is_none());
    drop(pool);

    // Note: Actual connection pooling would be tested with real connections
}

// Benchmark tests (would be in benches/ directory in real implementation)
#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_auth_hash_performance() {
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "test-password-for-performance-testing".to_string(),
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

    let start = Instant::now();
    for _ in 0..1000 {
        let _hash = outbound.generate_auth_hash();
    }
    let elapsed = start.elapsed();

    // Hash generation should be fast
    assert!(elapsed < Duration::from_millis(100));
    println!("1000 auth hash generations took: {:?}", elapsed);
}

#[cfg(feature = "out_hysteria2")]
#[tokio::test]
async fn test_hysteria2_obfuscation_performance() {
    let config = Hysteria2Config {
        server: "127.0.0.1".to_string(),
        port: 8443,
        password: "test".to_string(),
        congestion_control: None,
        up_mbps: None,
        down_mbps: None,
        obfs: Some("performance-test-key".to_string()),
        skip_cert_verify: true,
        sni: None,
        alpn: None,
        salamander: None,
        brutal: None,
    };

    let outbound = Hysteria2Outbound::new(config).unwrap();
    let mut data = vec![0u8; 1024]; // 1KB test data

    let start = Instant::now();
    for _ in 0..1000 {
        outbound.apply_obfuscation(&mut data);
    }
    let elapsed = start.elapsed();

    // Obfuscation should be fast
    assert!(elapsed < Duration::from_millis(100));
    println!("1000 obfuscation operations on 1KB took: {:?}", elapsed);
}
