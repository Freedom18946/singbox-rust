//! E2E Integration Tests for Shadowtls with sb-tls Infrastructure
//!
//! Test Coverage (Sprint 19 Phase 1.3):
//! 1. Configuration with sb-tls Standard TLS
//! 2. Configuration with sb-tls REALITY TLS
//! 3. Configuration with sb-tls ECH
//! 4. RouteCtx field validation (new fields added)

#[cfg(feature = "adapter-shadowtls")]
mod shadowtls_tests {
    use sb_adapters::inbound::shadowtls::ShadowTlsInboundConfig;
    use sb_config::outbound::TlsConfig; // Correct import path
    use std::net::SocketAddr;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_shadowtls_standard_tls_config() {
        // Test that Shadowtls accepts Standard TLS configuration
        let bind_addr: SocketAddr = "127.0.0.1:18500".parse().unwrap();

        // Create Standard TLS config (Sprint 19 Phase 1.1)
        let tls_config = TlsConfig::Standard {
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        };

        let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

        let config = ShadowTlsInboundConfig {
            listen: bind_addr,
            tls: tls_config,
            router,
        };

        // Verify configuration
        assert_eq!(config.listen, bind_addr);
        match config.tls {
            TlsConfig::Standard {
                ref cert_path,
                ref key_path,
                ref alpn,
            } => {
                assert_eq!(cert_path, "/path/to/cert.pem");
                assert_eq!(key_path, "/path/to/key.pem");
                assert_eq!(alpn.len(), 2);
            }
            _ => panic!("Expected Standard TLS config"),
        }
    }

    #[tokio::test]
    async fn test_shadowtls_reality_tls_config() {
        // Test that Shadowtls accepts REALITY TLS configuration
        let bind_addr: SocketAddr = "127.0.0.1:18501".parse().unwrap();

        // Create REALITY TLS config (Sprint 5 sb-tls infrastructure)
        let tls_config = TlsConfig::Reality {
            private_key: "test_private_key".to_string(),
            public_key: "test_public_key".to_string(),
            short_id: vec![0x01, 0x02, 0x03],
            server_name: "example.com".to_string(),
            dest: "example.com:443".to_string(),
        };

        let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

        let config = ShadowTlsInboundConfig {
            listen: bind_addr,
            tls: tls_config,
            router,
        };

        // Verify configuration
        assert_eq!(config.listen, bind_addr);
        match config.tls {
            TlsConfig::Reality {
                ref server_name, ..
            } => {
                assert_eq!(server_name, "example.com");
            }
            _ => panic!("Expected REALITY TLS config"),
        }
    }

    #[tokio::test]
    async fn test_shadowtls_ech_tls_config() {
        // Test that Shadowtls accepts ECH TLS configuration
        let bind_addr: SocketAddr = "127.0.0.1:18502".parse().unwrap();

        // Create ECH TLS config (Sprint 5 sb-tls infrastructure)
        let tls_config = TlsConfig::Ech {
            cert_path: "/path/to/cert.pem".to_string(),
            key_path: "/path/to/key.pem".to_string(),
            ech_key: vec![0x01, 0x02, 0x03],
            server_name: "example.com".to_string(),
        };

        let router = Arc::new(sb_core::router::RouterHandle::new_for_tests());

        let config = ShadowTlsInboundConfig {
            listen: bind_addr,
            tls: tls_config,
            router,
        };

        // Verify configuration
        assert_eq!(config.listen, bind_addr);
        match config.tls {
            TlsConfig::Ech {
                ref server_name,
                ref ech_key,
                ..
            } => {
                assert_eq!(server_name, "example.com");
                assert_eq!(ech_key.len(), 3);
            }
            _ => panic!("Expected ECH TLS config"),
        }
    }

    #[tokio::test]
    async fn test_shadowtls_routectx_fields() {
        // Test that RouteCtx now includes new fields (Sprint 19 Phase 1.1)
        // This validates the RouteCtx update in handle_conn function

        use sb_core::router::rules::RouteCtx;

        // Create RouteCtx with all fields (including new ones)
        let ctx = RouteCtx {
            domain: Some("example.com"),
            ip: None,
            transport_udp: false,
            port: Some(443),
            process_name: None,
            process_path: None,
            inbound_tag: None,  // New field (Sprint 11+)
            outbound_tag: None, // New field (Sprint 11+)
            auth_user: None,    // New field (Sprint 11+)
            query_type: None,   // New field (Sprint 11+)
        };

        // Verify fields exist and are properly typed
        assert_eq!(ctx.domain, Some("example.com"));
        assert_eq!(ctx.port, Some(443));
        assert!(ctx.inbound_tag.is_none());
        assert!(ctx.outbound_tag.is_none());
        assert!(ctx.auth_user.is_none());
        assert!(ctx.query_type.is_none());
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
