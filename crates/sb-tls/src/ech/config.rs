//! ECH configuration structures
//!
//! This module defines the configuration structures for ECH client and server.

use serde::{Deserialize, Serialize};

/// ECH keypair (X25519 for HPKE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchKeypair {
    /// Private key (32 bytes, base64 encoded in config)
    pub private_key: Vec<u8>,
    /// Public key (32 bytes, base64 encoded in config)
    pub public_key: Vec<u8>,
}

impl EchKeypair {
    /// Create a new ECH keypair from raw bytes
    #[must_use]
    pub const fn new(private_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    /// Create from base64-encoded strings (sing-box format)
    ///
    /// # Errors
    /// Returns error if base64 decoding fails or key lengths are invalid
    pub fn from_base64(private_b64: &str, public_b64: &str) -> Result<Self, super::EchError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        let private_key = b64
            .decode(private_b64)
            .map_err(|e| super::EchError::InvalidConfig(format!("Invalid private key: {e}")))?;

        let public_key = b64
            .decode(public_b64)
            .map_err(|e| super::EchError::InvalidConfig(format!("Invalid public key: {e}")))?;

        // Validate key lengths (X25519 keys are 32 bytes)
        if private_key.len() != 32 {
            return Err(super::EchError::InvalidConfig(format!(
                "Private key must be 32 bytes, got {}",
                private_key.len()
            )));
        }

        if public_key.len() != 32 {
            return Err(super::EchError::InvalidConfig(format!(
                "Public key must be 32 bytes, got {}",
                public_key.len()
            )));
        }

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get private key as base64 string
    #[must_use]
    pub fn private_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.private_key)
    }

    /// Get public key as base64 string
    #[must_use]
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.public_key)
    }
}

/// ECH client configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EchClientConfig {
    /// Enable ECH
    #[serde(default)]
    pub enabled: bool,

    /// ECH configuration list (base64 encoded)
    /// This is typically obtained from DNS TXT records or server configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,

    /// ECH configuration list (raw bytes)
    #[serde(skip)]
    pub config_list: Option<Vec<u8>>,

    /// Enable post-quantum signature schemes
    #[serde(default)]
    pub pq_signature_schemes_enabled: bool,

    /// Dynamic record sizing hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_record_sizing_disabled: Option<bool>,
}

impl EchClientConfig {
    /// Create a new ECH client config
    ///
    /// # Errors
    /// Returns error if base64 decoding fails
    pub fn new(config_base64: String) -> Result<Self, super::EchError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;

        let config_list = b64
            .decode(&config_base64)
            .map_err(|e| super::EchError::InvalidConfig(format!("Invalid config: {e}")))?;

        Ok(Self {
            enabled: true,
            config: Some(config_base64),
            config_list: Some(config_list),
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
        })
    }

    /// Validate the configuration
    ///
    /// # Errors
    /// Returns error if config is invalid
    pub fn validate(&self) -> Result<(), super::EchError> {
        if !self.enabled {
            return Ok(());
        }

        if self.config.is_none() && self.config_list.is_none() {
            return Err(super::EchError::InvalidConfig(
                "ECH enabled but no config provided".to_string(),
            ));
        }

        // Parse config list if present
        if let Some(ref config_list) = self.config_list {
            super::parser::parse_ech_config_list(config_list)?;
        }

        Ok(())
    }

    /// Get the ECH config list bytes
    #[must_use]
    pub fn get_config_list(&self) -> Option<&[u8]> {
        self.config_list.as_deref()
    }
}

/// ECH server configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EchServerConfig {
    /// Enable ECH
    #[serde(default)]
    pub enabled: bool,

    /// Server keypair for ECH
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keypair: Option<EchKeypair>,

    /// ECH configuration to advertise (base64 encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
}

impl EchServerConfig {
    /// Validate the configuration
    ///
    /// # Errors
    /// Returns error if config is invalid
    pub fn validate(&self) -> Result<(), super::EchError> {
        if !self.enabled {
            return Ok(());
        }

        if self.keypair.is_none() {
            return Err(super::EchError::InvalidConfig(
                "ECH enabled but no keypair provided".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_keypair_from_base64() {
        // Valid X25519 keypair (32 bytes each)
        let private_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let public_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        let keypair = EchKeypair::from_base64(private_b64, public_b64);
        assert!(keypair.is_ok());

        let keypair = keypair.unwrap();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_ech_keypair_invalid_length() {
        // Invalid length (not 32 bytes)
        let private_b64 = "AAAA";
        let public_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        let result = EchKeypair::from_base64(private_b64, public_b64);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            super::super::EchError::InvalidConfig(_)
        ));
    }

    #[test]
    fn test_ech_keypair_invalid_base64() {
        // Invalid base64 encoding
        let private_b64 = "not-valid-base64!!!";
        let public_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        let result = EchKeypair::from_base64(private_b64, public_b64);
        assert!(result.is_err());
    }

    #[test]
    fn test_ech_keypair_wrong_key_length() {
        // Valid base64 but wrong length (16 bytes instead of 32)
        let private_b64 = "AAAAAAAAAAAAAAAAAAAAAA=="; // 16 bytes
        let public_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        let result = EchKeypair::from_base64(private_b64, public_b64);
        assert!(result.is_err());

        match result.unwrap_err() {
            super::super::EchError::InvalidConfig(msg) => {
                assert!(msg.contains("must be 32 bytes"));
            }
            _ => panic!("Expected InvalidConfig error"),
        }
    }

    #[test]
    fn test_ech_client_config_validation() {
        let mut config = EchClientConfig::default();
        assert!(config.validate().is_ok()); // Disabled is OK

        config.enabled = true;
        assert!(config.validate().is_err()); // Enabled without config should fail
    }

    #[test]
    fn test_ech_client_config_with_valid_config() {
        let config_list = create_test_ech_config_list();
        let config_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &config_list);

        let config = EchClientConfig::new(config_b64);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.enabled);
        assert!(config.config.is_some());
        assert!(config.config_list.is_some());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ech_client_config_with_invalid_config() {
        // Invalid base64
        let result = EchClientConfig::new("not-valid-base64!!!".to_string());
        assert!(result.is_err());

        // Valid base64 but invalid ECHConfigList
        let invalid_config =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"invalid");
        let config = EchClientConfig::new(invalid_config).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ech_client_config_get_config_list() {
        let config_list = create_test_ech_config_list();
        let mut config = EchClientConfig::default();
        config.config_list = Some(config_list.clone());

        let retrieved = config.get_config_list();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), &config_list[..]);
    }

    #[test]
    fn test_ech_server_config_validation() {
        let mut config = EchServerConfig::default();
        assert!(config.validate().is_ok()); // Disabled is OK

        config.enabled = true;
        assert!(config.validate().is_err()); // Enabled without keypair should fail
    }

    #[test]
    fn test_ech_server_config_with_keypair() {
        let keypair = EchKeypair::new(vec![1u8; 32], vec![2u8; 32]);

        let mut config = EchServerConfig::default();
        config.enabled = true;
        config.keypair = Some(keypair);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_keypair_base64_roundtrip() {
        let private_key = vec![1u8; 32];
        let public_key = vec![2u8; 32];

        let keypair = EchKeypair::new(private_key.clone(), public_key.clone());

        let private_b64 = keypair.private_key_base64();
        let public_b64 = keypair.public_key_base64();

        let keypair2 = EchKeypair::from_base64(&private_b64, &public_b64).unwrap();

        assert_eq!(keypair2.private_key, private_key);
        assert_eq!(keypair2.public_key, public_key);
    }

    #[test]
    fn test_ech_client_config_default() {
        let config = EchClientConfig::default();
        assert!(!config.enabled);
        assert!(config.config.is_none());
        assert!(config.config_list.is_none());
        assert!(!config.pq_signature_schemes_enabled);
    }

    #[test]
    fn test_ech_server_config_default() {
        let config = EchServerConfig::default();
        assert!(!config.enabled);
        assert!(config.keypair.is_none());
        assert!(config.config.is_none());
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
