//! REALITY configuration

use serde::{Deserialize, Serialize};

/// REALITY client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityClientConfig {
    /// Target domain to impersonate (e.g., "www.apple.com")
    pub target: String,

    /// Server name for SNI
    pub server_name: String,

    /// Public key for authentication (hex-encoded X25519 public key)
    pub public_key: String,

    /// Short ID for client identification (0-16 hex chars)
    /// Can be empty if server allows
    pub short_id: Option<String>,

    /// TLS fingerprint to emulate (default: "chrome")
    /// Options: chrome, firefox, safari, edge, ios
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,

    /// ALPN protocols
    #[serde(default)]
    pub alpn: Vec<String>,
}

impl RealityClientConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate target domain
        if self.target.is_empty() {
            return Err("target domain cannot be empty".to_string());
        }

        // Validate public key (should be 64 hex chars for X25519)
        if !is_valid_hex(&self.public_key) || self.public_key.len() != 64 {
            return Err("public_key must be 64 hex characters (X25519 public key)".to_string());
        }

        // Validate short_id if present
        if let Some(ref short_id) = self.short_id {
            if !short_id.is_empty() {
                if !is_valid_hex(short_id) {
                    return Err("short_id must be hex characters".to_string());
                }
                if short_id.len() > 16 || short_id.len() % 2 != 0 {
                    return Err("short_id must be 0-16 hex chars (length multiple of 2)".to_string());
                }
            }
        }

        Ok(())
    }

    /// Get short ID as bytes
    pub fn short_id_bytes(&self) -> Option<Vec<u8>> {
        self.short_id
            .as_ref()
            .and_then(|s| hex::decode(s).ok())
    }

    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(&self.public_key)
            .map_err(|e| format!("invalid public key hex: {}", e))?;

        bytes.try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())
    }
}

/// REALITY server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityServerConfig {
    /// Target domain to forward traffic to (e.g., "www.apple.com:443")
    pub target: String,

    /// Accepted server names (SNI values)
    pub server_names: Vec<String>,

    /// Private key for authentication (hex-encoded X25519 private key)
    pub private_key: String,

    /// Accepted short IDs
    /// Empty vec means accept all
    #[serde(default)]
    pub short_ids: Vec<String>,

    /// Maximum handshake time in seconds
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout: u64,

    /// Fallback to target on auth failure
    #[serde(default = "default_true")]
    pub enable_fallback: bool,
}

impl RealityServerConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate target
        if self.target.is_empty() {
            return Err("target cannot be empty".to_string());
        }

        // Validate private key (should be 64 hex chars for X25519)
        if !is_valid_hex(&self.private_key) || self.private_key.len() != 64 {
            return Err("private_key must be 64 hex characters (X25519 private key)".to_string());
        }

        // Validate server names
        if self.server_names.is_empty() {
            return Err("server_names cannot be empty".to_string());
        }

        // Validate short IDs
        for short_id in &self.short_ids {
            if !is_valid_hex(short_id) {
                return Err(format!("invalid short_id hex: {}", short_id));
            }
            if short_id.len() > 16 || short_id.len() % 2 != 0 {
                return Err(format!("short_id must be 0-16 hex chars: {}", short_id));
            }
        }

        Ok(())
    }

    /// Get private key as bytes
    pub fn private_key_bytes(&self) -> Result<[u8; 32], String> {
        let bytes = hex::decode(&self.private_key)
            .map_err(|e| format!("invalid private key hex: {}", e))?;

        bytes.try_into()
            .map_err(|_| "private key must be 32 bytes".to_string())
    }

    /// Get short IDs as bytes
    pub fn short_ids_bytes(&self) -> Vec<Vec<u8>> {
        self.short_ids
            .iter()
            .filter_map(|s| hex::decode(s).ok())
            .collect()
    }

    /// Check if a short ID is accepted
    pub fn accepts_short_id(&self, short_id: &[u8]) -> bool {
        if self.short_ids.is_empty() {
            return true; // Accept all if no restrictions
        }

        for accepted in self.short_ids_bytes() {
            if accepted == short_id {
                return true;
            }
        }

        false
    }
}

// Helper functions

fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}

fn default_handshake_timeout() -> u64 {
    5 // 5 seconds
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_client_config_validation() {
        let mut config = RealityClientConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec!["h2".to_string()],
        };

        assert!(config.validate().is_ok());

        // Invalid public key
        config.public_key = "invalid".to_string();
        assert!(config.validate().is_err());

        // Fix public key
        config.public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();

        // Invalid short_id (odd length)
        config.short_id = Some("abc".to_string());
        assert!(config.validate().is_err());

        // Invalid short_id (too long)
        config.short_id = Some("01234567890123456789".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_reality_server_config_validation() {
        let config = RealityServerConfig {
            target: "www.apple.com:443".to_string(),
            server_names: vec!["example.com".to_string()],
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            short_ids: vec!["01ab".to_string()],
            handshake_timeout: 5,
            enable_fallback: true,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_short_id_acceptance() {
        let config = RealityServerConfig {
            target: "www.apple.com:443".to_string(),
            server_names: vec!["example.com".to_string()],
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            short_ids: vec!["01ab".to_string(), "cdef".to_string()],
            handshake_timeout: 5,
            enable_fallback: true,
        };

        assert!(config.accepts_short_id(&hex::decode("01ab").unwrap()));
        assert!(config.accepts_short_id(&hex::decode("cdef").unwrap()));
        assert!(!config.accepts_short_id(&hex::decode("ffff").unwrap()));

        // Empty short_ids accepts all
        let config_accept_all = RealityServerConfig {
            short_ids: vec![],
            ..config
        };
        assert!(config_accept_all.accepts_short_id(&hex::decode("ffff").unwrap()));
    }
}
