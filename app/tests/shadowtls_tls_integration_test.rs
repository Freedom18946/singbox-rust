//! E2E Integration Tests for Shadowtls with sb-tls Infrastructure
//!
//! Test Coverage (Sprint 19 Phase 1.3):
//! 1. Configuration with sb-tls Standard TLS
//! 2. Configuration with sb-tls REALITY TLS
//! 3. Configuration with sb-tls ECH
//! 4. RouteCtx field validation (new fields added)

#![allow(unexpected_cfgs)]
#![allow(dead_code)]

#[cfg(feature = "adapter-shadowtls")]
mod shadowtls_tests {
    use sb_transport::tls::{StandardTlsConfig, TlsConfig};

    #[test]
    fn test_shadowtls_standard_tls_config() {
        // Test that Standard TLS configuration can be created
        let config = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            insecure: false,
            cert_path: Some("/path/to/cert.pem".to_string()),
            key_path: Some("/path/to/key.pem".to_string()),
            cert_pem: None,
            key_pem: None,
        });

        // Verify configuration
        match config {
            TlsConfig::Standard(cfg) => {
                assert_eq!(cfg.server_name, Some("example.com".to_string()));
                assert_eq!(cfg.alpn.len(), 2);
                assert!(!cfg.insecure);
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Standard TLS config"),
        }

        println!("✅ Standard TLS config test passed");
    }

    #[cfg(feature = "transport_reality")]
    #[test]
    fn test_shadowtls_reality_tls_config() {
        use sb_transport::tls::RealityTlsConfig;

        // Test that REALITY TLS configuration can be created
        let config = TlsConfig::Reality(RealityTlsConfig {
            target: "example.com:443".to_string(),
            server_name: "example.com".to_string(),
            public_key: "test_public_key".to_string(),
            short_id: Some("01".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string()],
        });

        // Verify configuration
        match config {
            TlsConfig::Reality(cfg) => {
                assert_eq!(cfg.server_name, "example.com");
                assert_eq!(cfg.target, "example.com:443");
            }
            _ => panic!("Expected REALITY TLS config"),
        }

        println!("✅ REALITY TLS config test passed");
    }

    #[cfg(feature = "transport_ech")]
    #[test]
    fn test_shadowtls_ech_tls_config() {
        use sb_transport::tls::EchTlsConfig;

        // Test that ECH TLS configuration can be created
        let config = TlsConfig::Ech(EchTlsConfig {
            enabled: true,
            config: Some("base64_ech_config".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
        });

        // Verify configuration
        match config {
            TlsConfig::Ech(cfg) => {
                assert!(cfg.enabled);
                assert_eq!(cfg.server_name, Some("example.com".to_string()));
            }
            _ => panic!("Expected ECH TLS config"),
        }

        println!("✅ ECH TLS config test passed");
    }

    #[test]
    fn test_shadowtls_routectx_fields() {
        // Test that RouteCtx has expected fields (using Default)
        use sb_core::router::rules::RouteCtx;

        // Create RouteCtx with Default trait - all new fields should have defaults
        let ctx = RouteCtx::default();

        // Verify RouteCtx can be created with default values
        assert!(ctx.domain.is_none());
        assert!(ctx.port.is_none());

        println!("✅ RouteCtx with default fields test passed");
    }
}

// Note: Full E2E tests with actual TLS handshakes would require:
// 1. Valid TLS certificates and keys
// 2. Starting a Shadowtls server
// 3. Creating a Shadowtls client connection
// 4. Performing TLS handshake and HTTP CONNECT
// 5. Verifying bidirectional relay
//
// These tests focus on configuration validation and integration with sb-tls.
// Full network tests are deferred to integration test suite with proper certificates.
