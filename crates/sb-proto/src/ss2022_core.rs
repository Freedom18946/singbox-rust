//! Shadowsocks 2022 core protocol implementation (placeholder for testing).
//!
//! # ⚠️ Security Warning
//!
//! **This is a TEST-ONLY placeholder implementation without real cryptographic security.**
//! - KDF uses simple blake3 hash instead of proper key derivation
//! - No actual AEAD encryption/decryption
//! - Salt and authentication tags are fixed placeholders
//!
//! **DO NOT use this in production environments.**

#[cfg(feature = "proto_ss2022_core")]
#[allow(clippy::module_inception)]
pub mod ss2022_core {
    use thiserror::Error;

    /// Supported AEAD cipher types for Shadowsocks 2022.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AeadKind {
        /// AES-256-GCM cipher.
        Aes256Gcm,
        /// ChaCha20-Poly1305 cipher.
        Chacha20Poly1305,
    }

    /// Errors that can occur in SS2022 protocol operations.
    #[derive(Error, Debug)]
    pub enum SS2022Error {
        /// Invalid password format (empty or malformed).
        #[error("invalid password format")]
        InvalidPassword,
        /// Unsupported cipher method.
        #[error("invalid method: {0}")]
        InvalidMethod(String),
        /// Buffer size insufficient for operation.
        #[error("buffer too small")]
        BufferTooSmall,
    }

    const PLACEHOLDER_SALT: &[u8; 16] = b"SS2022_TEST_SALT";
    const PLACEHOLDER_TAG: &[u8; 16] = b"SS2022_TEST__TAG";

    /// Derives a subkey from password and salt using blake3 (PLACEHOLDER).
    ///
    /// # Security Warning
    /// This is NOT a proper KDF implementation. Uses blake3(password || salt) for testing only.
    #[must_use]
    pub fn derive_subkey_b3(password: &str, salt: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.as_bytes()[..32]);
        key
    }

    /// Builds a client first packet with unified byte layout (PLACEHOLDER).
    ///
    /// # Security Warning
    /// This does NOT perform real AEAD encryption. Packet structure is for testing byte shapes only.
    ///
    /// # Errors
    /// Returns `SS2022Error` if password or host is empty.
    pub fn build_client_first(
        method: &str,
        password: &str,
        host: &str,
        port: u16,
        aead: AeadKind,
    ) -> Result<Vec<u8>, SS2022Error> {
        if password.is_empty() || host.is_empty() {
            return Err(SS2022Error::InvalidPassword);
        }

        let mut result = Vec::new();

        // Simulated header: method + aead_kind
        let header = format!("{}:{:?}", method, aead);
        let header_bytes = header.as_bytes();
        result.extend_from_slice(&u16::try_from(header_bytes.len()).unwrap_or(0).to_be_bytes());
        result.extend_from_slice(header_bytes);

        // Simulated payload: target address
        let payload = format!("{}:{}", host, port);
        let payload_bytes = payload.as_bytes();
        result.extend_from_slice(&u16::try_from(payload_bytes.len()).unwrap_or(0).to_be_bytes());
        result.extend_from_slice(payload_bytes);

        // Placeholder salt and tag
        result.extend_from_slice(PLACEHOLDER_SALT);
        result.extend_from_slice(PLACEHOLDER_TAG);

        Ok(result)
    }

    /// Returns the standard string identifier for an AEAD cipher type.
    #[must_use]
    pub const fn aead_kind_str(aead: AeadKind) -> &'static str {
        match aead {
            AeadKind::Aes256Gcm => "aes-256-gcm",
            AeadKind::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Parses an AEAD cipher type from a method string.
    ///
    /// Supports both hyphenated and non-hyphenated formats (case-insensitive).
    #[must_use]
    pub fn parse_aead_kind(s: &str) -> Option<AeadKind> {
        match s.to_lowercase().as_str() {
            "aes-256-gcm" | "aes256gcm" => Some(AeadKind::Aes256Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Some(AeadKind::Chacha20Poly1305),
            _ => None,
        }
    }
}

#[cfg(feature = "proto_ss2022_core")]
pub use ss2022_core::*;
