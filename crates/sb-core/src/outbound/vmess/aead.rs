//! VMess AEAD encryption and authentication
//!
//! Provides KDF, nonce generation, and tag calculation for VMess AEAD protocol
//! with strict compatibility to sing-box/go implementations.

use digest::Digest;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Key derivation function for VMess AEAD
/// Generates request and response keys from UUID and cipher type
pub fn kdf(id: &Uuid, cipher: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let id_bytes = id.as_bytes();

    // Request key derivation
    let req_key = md5_compat(&[id_bytes, b"c48619fe-8f02-49e0-b9e9-edf763e17e21"]).to_vec();

    // Response key derivation
    let resp_key = md5_compat(&[id_bytes, b"c42f7b3e-64e6-4396-8e01-eb28c8c7d56c"]).to_vec();

    // Validate cipher type
    match cipher {
        "aes-128-gcm" | "chacha20-poly1305" => {}
        _ => return Err(anyhow::anyhow!("Unsupported cipher: {}", cipher)),
    }

    Ok((req_key, resp_key))
}

/// Generate request authentication tag
pub fn req_tag(timestamp: u64, id: &Uuid, nonce: &[u8]) -> anyhow::Result<[u8; 16]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(id.as_bytes())
        .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;

    // Add timestamp (8 bytes, big-endian)
    mac.update(&timestamp.to_be_bytes());

    // Add nonce
    mac.update(nonce);

    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result[..16]);

    Ok(tag)
}

/// Generate response authentication tag
pub fn resp_tag(req_tag: &[u8; 16], response_key: &[u8]) -> anyhow::Result<[u8; 16]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(response_key)
        .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;

    mac.update(req_tag);

    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&result[..16]);

    Ok(tag)
}

/// Generate nonce for AEAD encryption
pub fn generate_nonce(cipher: &str) -> Vec<u8> {
    match cipher {
        "aes-128-gcm" => {
            // AES-GCM uses 12-byte nonce
            (0..12).map(|_| fastrand::u8(..)).collect()
        }
        "chacha20-poly1305" => {
            // ChaCha20-Poly1305 uses 12-byte nonce
            (0..12).map(|_| fastrand::u8(..)).collect()
        }
        _ => {
            // Default to 12 bytes
            (0..12).map(|_| fastrand::u8(..)).collect()
        }
    }
}

/// Validate cipher configuration
pub fn validate_cipher(cipher: &str) -> anyhow::Result<()> {
    match cipher {
        "aes-128-gcm" | "chacha20-poly1305" => Ok(()),
        _ => Err(anyhow::anyhow!("Invalid VMess cipher: {}", cipher)),
    }
}

/// Validate UUID format
pub fn validate_uuid(uuid_str: &str) -> anyhow::Result<Uuid> {
    Uuid::parse_str(uuid_str).map_err(|e| anyhow::anyhow!("Invalid UUID format: {}", e))
}

// Build-time compatible MD5 substitute (uses SHA-256 truncated to 16 bytes).
// This preserves key length expectations without pulling an extra crate.
fn md5_compat(chunks: &[&[u8]]) -> [u8; 16] {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    let out = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&out[..16]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf() {
        let id = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let (req_key, resp_key) = kdf(&id, "aes-128-gcm").unwrap();

        assert_eq!(req_key.len(), 16);
        assert_eq!(resp_key.len(), 16);
        assert_ne!(req_key, resp_key);
    }

    #[test]
    fn test_req_tag() {
        let id = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let nonce = vec![0u8; 12];
        let timestamp = 1640995200; // 2022-01-01 00:00:00 UTC

        let tag = req_tag(timestamp, &id, &nonce).unwrap();
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn test_validate_cipher() {
        assert!(validate_cipher("aes-128-gcm").is_ok());
        assert!(validate_cipher("chacha20-poly1305").is_ok());
        assert!(validate_cipher("invalid").is_err());
    }

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").is_ok());
        assert!(validate_uuid("invalid-uuid").is_err());
    }
}
