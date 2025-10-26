//! # ECH (Encrypted Client Hello) Support
//!
//! ECH is a TLS extension that encrypts the ClientHello message to prevent
//! traffic analysis and SNI-based blocking. This module provides:
//! - ECH configuration structures
//! - ECHConfigList parsing and validation
//! - HPKE (Hybrid Public Key Encryption) integration
//! - Runtime handshake integration with rustls
//!
//! ## How ECH Works
//!
//! **Client Side:**
//! 1. Obtains ECHConfigList (from DNS, config, or other sources)
//! 2. Encrypts ClientHello using server's public key (HPKE)
//! 3. Sends encrypted ClientHello in TLS extension
//! 4. Server decrypts and processes the real ClientHello
//!
//! **Key Components:**
//! - DHKEM(X25519, HKDF-SHA256): Key encapsulation mechanism
//! - HPKE: Hybrid Public Key Encryption for ClientHello encryption
//! - ECHConfigList: Server's ECH configuration (public key, cipher suites, etc.)
//!
//! ## Current Status
//!
//! - CLI keypair generation: ✅ Complete (app/src/cli/generate.rs)
//! - Runtime handshake integration: 🚧 In Progress
//! - rustls ECH support: ⚠️ Limited (as of rustls 0.23)
//!
//! ## Implementation Notes
//!
//! rustls 0.23 does not have native ECH support. This implementation provides:
//! 1. ECH configuration structures compatible with sing-box
//! 2. ECHConfigList parsing (RFC 9180 format)
//! 3. HPKE encryption primitives
//! 4. Custom TLS extension handling (when rustls adds ECH support)
//!
//! ## References
//!
//! - RFC 9180: HPKE (Hybrid Public Key Encryption)
//! - draft-ietf-tls-esni: TLS Encrypted Client Hello
//! - sing-box ECH implementation

pub mod config;
pub mod hpke;
pub mod parser;

pub use config::{EchClientConfig, EchKeypair, EchServerConfig};
pub use parser::{EchConfigList, parse_ech_config_list};

use thiserror::Error;

/// ECH-specific errors
#[derive(Debug, Error)]
pub enum EchError {
    /// Invalid ECH configuration
    #[error("Invalid ECH configuration: {0}")]
    InvalidConfig(String),

    /// ECH encryption failed
    #[error("ECH encryption failed: {0}")]
    EncryptionFailed(String),

    /// ECH decryption failed
    #[error("ECH decryption failed: {0}")]
    DecryptionFailed(String),

    /// TLS handshake failed with ECH
    #[error("ECH handshake failed: {0}")]
    HandshakeFailed(String),

    /// ECH not supported by server
    #[error("ECH not supported by server")]
    NotSupported,

    /// HPKE operation failed
    #[error("HPKE operation failed: {0}")]
    HpkeFailed(String),

    /// ECHConfigList parsing failed
    #[error("ECHConfigList parsing failed: {0}")]
    ParseFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type EchResult<T> = Result<T, EchError>;

/// ECH connector for client-side ECH encryption
pub struct EchConnector {
    /// ECH client configuration
    config: EchClientConfig,
    /// Parsed ECH config list
    ech_config_list: Option<parser::EchConfigList>,
}

impl EchConnector {
    /// Create a new ECH connector
    pub fn new(config: EchClientConfig) -> EchResult<Self> {
        config.validate()?;

        let ech_config_list = if let Some(config_bytes) = config.get_config_list() {
            Some(parser::parse_ech_config_list(config_bytes)?)
        } else {
            None
        };

        Ok(Self {
            config,
            ech_config_list,
        })
    }

    /// Wrap a TLS stream with ECH encryption
    ///
    /// This method encrypts the ClientHello SNI using the ECH public key
    /// and embeds the encrypted configuration in the TLS extension.
    ///
    /// # Arguments
    /// - `stream`: The underlying stream to wrap
    /// - `server_name`: The real server name to encrypt in the inner ClientHello
    ///
    /// # Returns
    /// An `EchClientHello` structure containing:
    /// - Encrypted inner ClientHello
    /// - Outer ClientHello with public name
    /// - HPKE encapsulated key
    pub fn wrap_tls(&self, server_name: &str) -> EchResult<EchClientHello> {
        if !self.config.enabled {
            return Err(EchError::InvalidConfig("ECH not enabled".to_string()));
        }

        let ech_config_list = self
            .ech_config_list
            .as_ref()
            .ok_or_else(|| EchError::InvalidConfig("No ECH config list available".to_string()))?;

        let ech_config = ech_config_list
            .first()
            .ok_or_else(|| EchError::InvalidConfig("Empty ECH config list".to_string()))?;

        // Select cipher suite (use first supported suite)
        let cipher_suite = ech_config
            .cipher_suites
            .first()
            .ok_or_else(|| EchError::InvalidConfig("No cipher suites available".to_string()))?;

        // Create HPKE sender
        let sender = hpke::HpkeSender::new(cipher_suite.kem, cipher_suite.kdf, cipher_suite.aead);

        // Setup HPKE encryption context
        let info = b"tls ech"; // ECH info string per spec
        let (encapsulated_key, mut hpke_context) = sender.setup(&ech_config.public_key, info)?;

        // Build inner ClientHello with real server name
        let inner_client_hello = self.build_inner_client_hello(server_name)?;

        // Encrypt inner ClientHello
        let aad = b""; // Additional authenticated data (empty for ECH)
        let encrypted_ch = hpke_context.seal(&inner_client_hello, aad)?;

        // Build ECH extension payload
        let ech_payload = self.build_ech_payload(&encapsulated_key, &encrypted_ch, ech_config)?;

        Ok(EchClientHello {
            outer_sni: ech_config.public_name.clone(),
            inner_sni: server_name.to_string(),
            ech_payload,
            encapsulated_key,
        })
    }

    /// Build inner ClientHello with real server name
    fn build_inner_client_hello(&self, server_name: &str) -> EchResult<Vec<u8>> {
        // Simplified ClientHello structure
        // In a full implementation, this would be a complete TLS ClientHello
        let mut ch = Vec::new();

        // Server name (SNI) extension
        let sni_bytes = server_name.as_bytes();
        ch.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        ch.extend_from_slice(sni_bytes);

        Ok(ch)
    }

    /// Build ECH extension payload
    fn build_ech_payload(
        &self,
        encapsulated_key: &[u8],
        encrypted_ch: &[u8],
        ech_config: &parser::EchConfig,
    ) -> EchResult<Vec<u8>> {
        let mut payload = Vec::new();

        // ECH version (2 bytes)
        payload.extend_from_slice(&ech_config.version.to_u16().to_be_bytes());

        // Cipher suite (6 bytes: KEM + KDF + AEAD)
        if let Some(suite) = ech_config.cipher_suites.first() {
            payload.extend_from_slice(&suite.kem.to_u16().to_be_bytes());
            payload.extend_from_slice(&suite.kdf.to_u16().to_be_bytes());
            payload.extend_from_slice(&suite.aead.to_u16().to_be_bytes());
        }

        // Encapsulated key length (2 bytes) + key
        payload.extend_from_slice(&(encapsulated_key.len() as u16).to_be_bytes());
        payload.extend_from_slice(encapsulated_key);

        // Encrypted ClientHello length (2 bytes) + encrypted data
        payload.extend_from_slice(&(encrypted_ch.len() as u16).to_be_bytes());
        payload.extend_from_slice(encrypted_ch);

        Ok(payload)
    }

    /// Verify ECH acceptance from server
    ///
    /// This method checks the server's response to determine if ECH was accepted.
    /// The server indicates ECH acceptance through a specific extension in ServerHello.
    pub fn verify_ech_acceptance(&self, server_hello: &[u8]) -> EchResult<bool> {
        // Look for ECH acceptance indication in ServerHello
        // In the real implementation, this would parse the ServerHello extensions

        // ECH extension type: 0xfe0d (draft-13)
        let ech_extension_type: u16 = 0xfe0d;

        // Simple search for ECH extension in ServerHello
        // This is a simplified check - full implementation would properly parse TLS messages
        let extension_bytes = ech_extension_type.to_be_bytes();

        if server_hello.len() < 2 {
            return Ok(false);
        }

        // Search for ECH extension type in the ServerHello
        for window in server_hello.windows(2) {
            if window == extension_bytes {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get the ECH configuration
    pub fn config(&self) -> &EchClientConfig {
        &self.config
    }
}

/// ECH ClientHello structure
#[derive(Debug, Clone)]
pub struct EchClientHello {
    /// Outer SNI (public name from ECH config)
    pub outer_sni: String,
    /// Inner SNI (real server name, encrypted)
    pub inner_sni: String,
    /// ECH extension payload
    pub ech_payload: Vec<u8>,
    /// HPKE encapsulated key
    pub encapsulated_key: Vec<u8>,
}

/// ECH protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchVersion {
    /// Draft version (0xfe0d)
    Draft13 = 0xfe0d,
}

impl EchVersion {
    /// Parse ECH version from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0xfe0d => Some(Self::Draft13),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// HPKE KDF (Key Derivation Function) identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKdf {
    /// HKDF-SHA256
    HkdfSha256 = 0x0001,
}

impl HpkeKdf {
    /// Parse KDF from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::HkdfSha256),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// HPKE AEAD (Authenticated Encryption with Associated Data) identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeAead {
    /// AES-128-GCM
    Aes128Gcm = 0x0001,
    /// AES-256-GCM
    Aes256Gcm = 0x0002,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305 = 0x0003,
}

impl HpkeAead {
    /// Parse AEAD from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Aes128Gcm),
            0x0002 => Some(Self::Aes256Gcm),
            0x0003 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// HPKE KEM (Key Encapsulation Mechanism) identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpkeKem {
    /// DHKEM(X25519, HKDF-SHA256)
    X25519HkdfSha256 = 0x0020,
}

impl HpkeKem {
    /// Parse KEM from u16
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0020 => Some(Self::X25519HkdfSha256),
            _ => None,
        }
    }

    /// Convert to u16
    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_version_conversion() {
        assert_eq!(EchVersion::from_u16(0xfe0d), Some(EchVersion::Draft13));
        assert_eq!(EchVersion::Draft13.to_u16(), 0xfe0d);
        assert_eq!(EchVersion::from_u16(0x0000), None);
    }

    #[test]
    fn test_hpke_kdf_conversion() {
        assert_eq!(HpkeKdf::from_u16(0x0001), Some(HpkeKdf::HkdfSha256));
        assert_eq!(HpkeKdf::HkdfSha256.to_u16(), 0x0001);
    }

    #[test]
    fn test_hpke_aead_conversion() {
        assert_eq!(HpkeAead::from_u16(0x0001), Some(HpkeAead::Aes128Gcm));
        assert_eq!(HpkeAead::from_u16(0x0002), Some(HpkeAead::Aes256Gcm));
        assert_eq!(HpkeAead::from_u16(0x0003), Some(HpkeAead::ChaCha20Poly1305));
    }

    #[test]
    fn test_hpke_kem_conversion() {
        assert_eq!(HpkeKem::from_u16(0x0020), Some(HpkeKem::X25519HkdfSha256));
        assert_eq!(HpkeKem::X25519HkdfSha256.to_u16(), 0x0020);
    }

    #[test]
    fn test_ech_connector_creation() {
        // Create a minimal ECH config for testing
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_ech_connector_disabled() {
        let config = EchClientConfig {
            enabled: false,
            config: None,
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();
        let result = connector.wrap_tls("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_ech_wrap_tls() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();
        let result = connector.wrap_tls("secret.example.com");

        assert!(result.is_ok());
        let ech_hello = result.unwrap();

        // Verify outer SNI is the public name
        assert_eq!(ech_hello.outer_sni, "public.example.com");

        // Verify inner SNI is the real server name
        assert_eq!(ech_hello.inner_sni, "secret.example.com");

        // Verify ECH payload is not empty
        assert!(!ech_hello.ech_payload.is_empty());

        // Verify encapsulated key is present (X25519 = 32 bytes)
        assert_eq!(ech_hello.encapsulated_key.len(), 32);
    }

    #[test]
    fn test_ech_verify_acceptance() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();

        // Test with ServerHello containing ECH extension
        let mut server_hello_with_ech = vec![0x00; 10];
        server_hello_with_ech.extend_from_slice(&[0xfe, 0x0d]); // ECH extension type
        server_hello_with_ech.extend_from_slice(&[0x00; 10]);

        assert!(
            connector
                .verify_ech_acceptance(&server_hello_with_ech)
                .unwrap()
        );

        // Test with ServerHello without ECH extension
        let server_hello_without_ech = vec![0x00; 20];
        assert!(
            !connector
                .verify_ech_acceptance(&server_hello_without_ech)
                .unwrap()
        );
    }

    #[test]
    fn test_ech_verify_acceptance_empty() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();

        // Test with empty ServerHello
        let empty_server_hello = vec![];
        assert!(
            !connector
                .verify_ech_acceptance(&empty_server_hello)
                .unwrap()
        );

        // Test with very short ServerHello
        let short_server_hello = vec![0x00];
        assert!(
            !connector
                .verify_ech_acceptance(&short_server_hello)
                .unwrap()
        );
    }

    #[test]
    fn test_ech_connector_no_config_list() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();
        let result = connector.wrap_tls("example.com");

        assert!(result.is_err());
        match result.unwrap_err() {
            EchError::InvalidConfig(msg) => {
                assert!(msg.contains("No ECH config list available"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_ech_connector_empty_config_list() {
        // Create an empty config list (should fail parsing)
        let mut empty_list = Vec::new();
        empty_list.extend_from_slice(&[0x00, 0x00]); // Empty list

        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(empty_list),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let result = EchConnector::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_ech_connector_invalid_config_list() {
        // Create an invalid config list
        let invalid_list = vec![0xFF, 0xFF, 0xFF, 0xFF];

        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(invalid_list),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let result = EchConnector::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_ech_wrap_tls_multiple_calls() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();

        // Call wrap_tls multiple times with different server names
        let result1 = connector.wrap_tls("server1.example.com");
        assert!(result1.is_ok());

        let result2 = connector.wrap_tls("server2.example.com");
        assert!(result2.is_ok());

        let hello1 = result1.unwrap();
        let hello2 = result2.unwrap();

        // Both should have the same outer SNI (public name)
        assert_eq!(hello1.outer_sni, hello2.outer_sni);

        // But different inner SNIs
        assert_ne!(hello1.inner_sni, hello2.inner_sni);

        // And different encrypted payloads
        assert_ne!(hello1.ech_payload, hello2.ech_payload);
    }

    #[test]
    fn test_ech_client_hello_structure() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();
        let ech_hello = connector.wrap_tls("secret.example.com").unwrap();

        // Verify ECH payload structure
        // Should contain: version (2) + cipher suite (6) + enc_key_len (2) + enc_key (32) + enc_ch_len (2) + enc_ch
        assert!(ech_hello.ech_payload.len() >= 2 + 6 + 2 + 32 + 2);

        // Check version in payload
        assert_eq!(ech_hello.ech_payload[0], 0xfe);
        assert_eq!(ech_hello.ech_payload[1], 0x0d);
    }

    #[test]
    fn test_ech_connector_config_access() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config.clone()).unwrap();

        // Verify we can access the config
        assert_eq!(connector.config().enabled, config.enabled);
        assert_eq!(connector.config().config, config.config);
    }

    #[test]
    fn test_ech_error_types() {
        // Test InvalidConfig error
        let err = EchError::InvalidConfig("test error".to_string());
        assert!(err.to_string().contains("Invalid ECH configuration"));

        // Test EncryptionFailed error
        let err = EchError::EncryptionFailed("test error".to_string());
        assert!(err.to_string().contains("ECH encryption failed"));

        // Test DecryptionFailed error
        let err = EchError::DecryptionFailed("test error".to_string());
        assert!(err.to_string().contains("ECH decryption failed"));

        // Test HandshakeFailed error
        let err = EchError::HandshakeFailed("test error".to_string());
        assert!(err.to_string().contains("ECH handshake failed"));

        // Test NotSupported error
        let err = EchError::NotSupported;
        assert!(err.to_string().contains("ECH not supported"));

        // Test HpkeFailed error
        let err = EchError::HpkeFailed("test error".to_string());
        assert!(err.to_string().contains("HPKE operation failed"));

        // Test ParseFailed error
        let err = EchError::ParseFailed("test error".to_string());
        assert!(err.to_string().contains("ECHConfigList parsing failed"));
    }

    #[test]
    fn test_ech_version_invalid() {
        assert_eq!(EchVersion::from_u16(0x0001), None);
        assert_eq!(EchVersion::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_hpke_kdf_invalid() {
        assert_eq!(HpkeKdf::from_u16(0x0000), None);
        assert_eq!(HpkeKdf::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_hpke_aead_invalid() {
        assert_eq!(HpkeAead::from_u16(0x0000), None);
        assert_eq!(HpkeAead::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_hpke_kem_invalid() {
        assert_eq!(HpkeKem::from_u16(0x0000), None);
        assert_eq!(HpkeKem::from_u16(0xFFFF), None);
    }

    #[test]
    fn test_ech_wrap_tls_empty_server_name() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();
        let result = connector.wrap_tls("");

        // Should still work with empty server name
        assert!(result.is_ok());
        let ech_hello = result.unwrap();
        assert_eq!(ech_hello.inner_sni, "");
    }

    #[test]
    fn test_ech_wrap_tls_long_server_name() {
        let config = EchClientConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: Some(create_test_ech_config_list()),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        };

        let connector = EchConnector::new(config).unwrap();

        // Very long server name
        let long_name = "a".repeat(255);
        let result = connector.wrap_tls(&long_name);

        assert!(result.is_ok());
        let ech_hello = result.unwrap();
        assert_eq!(ech_hello.inner_sni, long_name);
    }

    #[test]
    fn test_ech_client_hello_clone() {
        let hello = EchClientHello {
            outer_sni: "public.example.com".to_string(),
            inner_sni: "secret.example.com".to_string(),
            ech_payload: vec![1, 2, 3],
            encapsulated_key: vec![4, 5, 6],
        };

        let cloned = hello.clone();
        assert_eq!(cloned.outer_sni, hello.outer_sni);
        assert_eq!(cloned.inner_sni, hello.inner_sni);
        assert_eq!(cloned.ech_payload, hello.ech_payload);
        assert_eq!(cloned.encapsulated_key, hello.encapsulated_key);
    }

    // Helper function to create a test ECH config list
    fn create_test_ech_config_list() -> Vec<u8> {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&secret);

        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version (0xfe0d = Draft-13)
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Public key length + public key (32 bytes for X25519)
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(public_key.as_bytes());

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
}
