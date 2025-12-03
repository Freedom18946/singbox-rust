//! Shadowsocks outbound smoke tests
//!
//! These tests verify that the Shadowsocks outbound implementation compiles and
//! can be instantiated correctly. They do not require external services
//! and are designed to catch basic configuration and implementation issues.

#[cfg(feature = "out_ss")]
mod shadowsocks_tests {
    use sb_core::outbound::crypto_types::{HostPort, OutboundTcp};
    use sb_core::outbound::shadowsocks::{
        ShadowsocksCipher, ShadowsocksConfig, ShadowsocksOutbound,
    };
    use tokio;

    #[tokio::test]
    async fn test_shadowsocks_config_creation() {
        let config = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 8388);
        assert_eq!(config.password, "password123");
    }

    #[tokio::test]
    async fn test_shadowsocks_cipher_properties() {
        let aes_cipher = ShadowsocksCipher::Aes256Gcm;
        assert_eq!(aes_cipher.key_size(), 32);
        assert_eq!(aes_cipher.nonce_size(), 12);
        assert_eq!(aes_cipher.tag_size(), 16);

        let chacha_cipher = ShadowsocksCipher::Chacha20Poly1305;
        assert_eq!(chacha_cipher.key_size(), 32);
        assert_eq!(chacha_cipher.nonce_size(), 12);
        assert_eq!(chacha_cipher.tag_size(), 16);
    }

    #[tokio::test]
    async fn test_shadowsocks_outbound_creation_aes() {
        let config = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        let outbound = ShadowsocksOutbound::new(config);
        assert_eq!(outbound.protocol_name(), "shadowsocks");
    }

    #[tokio::test]
    async fn test_shadowsocks_outbound_creation_chacha() {
        let config = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Chacha20Poly1305,
        );

        let outbound = ShadowsocksOutbound::new(config);
        assert_eq!(outbound.protocol_name(), "shadowsocks");
    }

    #[tokio::test]
    async fn test_shadowsocks_connect_to_invalid_server() {
        let config = ShadowsocksConfig::new(
            "invalid.nonexistent.domain".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        let outbound = ShadowsocksOutbound::new(config);
        let target = HostPort::new("example.com".to_string(), 80);

        // This should fail because the server doesn't exist
        let result = outbound.connect(&target).await;
        assert!(result.is_err(), "Connection to invalid server should fail");
    }

    #[tokio::test]
    async fn test_shadowsocks_key_derivation() {
        // Test that different passwords produce different keys
        let config1 = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password1".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        let config2 = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password2".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        let key1 = config1.derive_key();
        let key2 = config2.derive_key();

        assert_ne!(
            key1, key2,
            "Different passwords should produce different keys"
        );
        assert_eq!(key1.len(), 32, "AES256 key should be 32 bytes");
        assert_eq!(key2.len(), 32, "AES256 key should be 32 bytes");
    }

    #[tokio::test]
    async fn test_shadowsocks_config_clone() {
        let config = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Chacha20Poly1305,
        );

        let cloned = config.clone();
        assert_eq!(config.server, cloned.server);
        assert_eq!(config.port, cloned.port);
        assert_eq!(config.password, cloned.password);
    }
}

#[cfg(not(feature = "out_ss"))]
mod shadowsocks_stub_tests {
    use sb_core::outbound::crypto_types::{HostPort, OutboundTcp};
    use sb_core::outbound::shadowsocks::{
        ShadowsocksCipher, ShadowsocksConfig, ShadowsocksOutbound,
    };

    #[tokio::test]
    async fn test_shadowsocks_stub_config_creation() {
        let _config = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        // Stub implementation should allow config creation
        // assert!(true);
    }

    #[tokio::test]
    async fn test_shadowsocks_stub_outbound_creation() {
        let config = ShadowsocksConfig::new(
            "example.com".to_string(),
            8388,
            "password123".to_string(),
            ShadowsocksCipher::Aes256Gcm,
        );

        let outbound = ShadowsocksOutbound::new(config);
        assert_eq!(outbound.protocol_name(), "shadowsocks");

        let target = HostPort::new("example.com".to_string(), 80);
        let result = outbound.connect(&target).await;
        assert!(result.is_err(), "Stub implementation should fail");

        assert!(result.is_err(), "Stub implementation should fail");
        let error = result.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }
}

// Integration test (requires feature flags)
#[cfg(all(feature = "out_ss", feature = "metrics"))]
#[tokio::test]
async fn test_shadowsocks_metrics_integration() {
    use sb_core::metrics::outbound::{
        record_shadowsocks_connect_error, record_shadowsocks_connect_success,
        record_shadowsocks_encrypt_bytes,
    };

    // These should not panic
    record_shadowsocks_connect_success();
    record_shadowsocks_connect_error();
    record_shadowsocks_encrypt_bytes(1024);
}

#[tokio::test]
async fn test_basic_compilation() {
    // This test just ensures the module compiles correctly
    // assert!(true);
}
