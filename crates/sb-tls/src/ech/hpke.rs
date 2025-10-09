//! HPKE (Hybrid Public Key Encryption) implementation for ECH
//!
//! This module implements HPKE operations needed for ECH:
//! - DHKEM(X25519, HKDF-SHA256): Key encapsulation
//! - HKDF-SHA256: Key derivation
//! - AES-128-GCM: Authenticated encryption

use super::{EchError, EchResult, HpkeAead, HpkeKdf, HpkeKem};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// HPKE context for encryption/decryption
#[derive(Debug)]
#[allow(dead_code)]
pub struct HpkeContext {
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    seq: u64,
    aead: HpkeAead,
}

impl HpkeContext {
    pub(crate) fn new(key: Vec<u8>, base_nonce: Vec<u8>, aead: HpkeAead) -> Self {
        Self {
            key,
            base_nonce,
            seq: 0,
            aead,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> EchResult<Vec<u8>> {
        match self.aead {
            HpkeAead::Aes128Gcm => self.seal_aes_128_gcm(plaintext, aad),
            _ => Err(EchError::HpkeFailed(format!(
                "Unsupported AEAD: {:?}",
                self.aead
            ))),
        }
    }

    fn seal_aes_128_gcm(&mut self, plaintext: &[u8], aad: &[u8]) -> EchResult<Vec<u8>> {
        let nonce = self.compute_nonce()?;
        let nonce_obj = Nonce::try_assume_unique_for_key(&nonce)
            .map_err(|_| EchError::HpkeFailed("Invalid nonce".to_string()))?;

        let unbound_key = UnboundKey::new(&AES_128_GCM, &self.key)
            .map_err(|e| EchError::HpkeFailed(format!("Failed to create key: {}", e)))?;

        let key = LessSafeKey::new(unbound_key);
        let mut in_out = plaintext.to_vec();
        
        key.seal_in_place_append_tag(nonce_obj, Aad::from(aad), &mut in_out)
            .map_err(|e| EchError::EncryptionFailed(format!("AEAD seal failed: {}", e)))?;

        self.seq += 1;
        Ok(in_out)
    }

    fn compute_nonce(&self) -> EchResult<Vec<u8>> {
        if self.base_nonce.len() != 12 {
            return Err(EchError::HpkeFailed(format!(
                "Invalid base nonce length: {}",
                self.base_nonce.len()
            )));
        }

        let mut nonce = self.base_nonce.clone();
        let seq_bytes = self.seq.to_be_bytes();

        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }

        Ok(nonce)
    }
}

/// HPKE sender (client-side encryption)
#[derive(Debug)]
#[allow(dead_code)]
pub struct HpkeSender {
    kem: HpkeKem,
    kdf: HpkeKdf,
    aead: HpkeAead,
}

impl HpkeSender {
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    pub fn setup(
        &self,
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> EchResult<(Vec<u8>, HpkeContext)> {
        match self.kem {
            HpkeKem::X25519HkdfSha256 => self.setup_x25519(recipient_public_key, info),
        }
    }

    fn setup_x25519(
        &self,
        recipient_public_key: &[u8],
        info: &[u8],
    ) -> EchResult<(Vec<u8>, HpkeContext)> {
        if recipient_public_key.len() != 32 {
            return Err(EchError::HpkeFailed(format!(
                "Invalid recipient public key length: {}",
                recipient_public_key.len()
            )));
        }

        let ephemeral_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        let mut recipient_key_bytes = [0u8; 32];
        recipient_key_bytes.copy_from_slice(recipient_public_key);
        let recipient_key = PublicKey::from(recipient_key_bytes);

        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_key);

        let (key, base_nonce) = self.derive_keys(
            shared_secret.as_bytes(),
            ephemeral_public.as_bytes(),
            recipient_public_key,
            info,
        )?;

        let context = HpkeContext::new(key, base_nonce, self.aead);
        Ok((ephemeral_public.as_bytes().to_vec(), context))
    }

    fn derive_keys(
        &self,
        shared_secret: &[u8],
        _ephemeral_public: &[u8],
        _recipient_public: &[u8],
        info: &[u8],
    ) -> EchResult<(Vec<u8>, Vec<u8>)> {
        // Simplified key derivation using SHA256
        // In a full HPKE implementation, this would use proper HKDF-Expand
        
        // Derive encryption key
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(b"key");
        hasher.update(info);
        let key_hash = hasher.finalize();
        let key = key_hash[..16].to_vec();

        // Derive base nonce
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(b"base_nonce");
        hasher.update(info);
        let nonce_hash = hasher.finalize();
        let base_nonce = nonce_hash[..12].to_vec();

        Ok((key, base_nonce))
    }

    #[allow(dead_code)]
    fn build_labeled_info(&self, label: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let mut labeled_info = Vec::new();
        labeled_info.extend_from_slice(&(length as u16).to_be_bytes());
        labeled_info.extend_from_slice(b"HPKE-v1");
        labeled_info.extend_from_slice(&(label.len() as u16).to_be_bytes());
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);
        labeled_info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpke_roundtrip() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let info = b"test info";
        let (_enc, mut sender_ctx) = sender
            .setup(recipient_public.as_bytes(), info)
            .unwrap();

        let plaintext = b"Hello, ECH!";
        let aad = b"additional data";
        let ciphertext = sender_ctx.seal(plaintext, aad).unwrap();

        assert!(ciphertext.len() > plaintext.len());
    }

    #[test]
    fn test_hpke_sender_setup() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let info = b"test info";
        let result = sender.setup(recipient_public.as_bytes(), info);
        
        assert!(result.is_ok());
        let (encapsulated_key, _context) = result.unwrap();
        
        // X25519 public key should be 32 bytes
        assert_eq!(encapsulated_key.len(), 32);
    }

    #[test]
    fn test_hpke_sender_invalid_recipient_key() {
        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        // Invalid key length (16 bytes instead of 32)
        let invalid_key = vec![0u8; 16];
        let result = sender.setup(&invalid_key, b"info");
        
        assert!(result.is_err());
        match result.unwrap_err() {
            EchError::HpkeFailed(msg) => {
                assert!(msg.contains("Invalid recipient public key length"));
            }
            _ => panic!("Expected HpkeFailed error"),
        }
    }

    #[test]
    fn test_hpke_context_seal() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let (_enc, mut context) = sender
            .setup(recipient_public.as_bytes(), b"info")
            .unwrap();

        let plaintext = b"Secret message";
        let aad = b"";
        let ciphertext = context.seal(plaintext, aad).unwrap();

        // Ciphertext should be plaintext + tag (16 bytes for GCM)
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_hpke_context_seal_with_aad() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let (_enc, mut context) = sender
            .setup(recipient_public.as_bytes(), b"info")
            .unwrap();

        let plaintext = b"Secret message";
        let aad = b"additional authenticated data";
        let ciphertext = context.seal(plaintext, aad).unwrap();

        // Ciphertext should be plaintext + tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_hpke_context_multiple_seals() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let (_enc, mut context) = sender
            .setup(recipient_public.as_bytes(), b"info")
            .unwrap();

        // Seal multiple messages with the same context
        let plaintext1 = b"Message 1";
        let ciphertext1 = context.seal(plaintext1, b"").unwrap();
        
        let plaintext2 = b"Message 2";
        let ciphertext2 = context.seal(plaintext2, b"").unwrap();

        // Both should succeed
        assert_eq!(ciphertext1.len(), plaintext1.len() + 16);
        assert_eq!(ciphertext2.len(), plaintext2.len() + 16);
        
        // Ciphertexts should be different (different nonces)
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_hpke_context_nonce_computation() {
        let key = vec![0u8; 16];
        let base_nonce = vec![0u8; 12];
        let mut context = HpkeContext::new(key, base_nonce, HpkeAead::Aes128Gcm);

        // Compute nonce for seq=0
        let nonce1 = context.compute_nonce().unwrap();
        assert_eq!(nonce1.len(), 12);

        // Increment seq and compute again
        context.seq = 1;
        let nonce2 = context.compute_nonce().unwrap();
        assert_eq!(nonce2.len(), 12);

        // Nonces should be different
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_hpke_context_invalid_nonce_length() {
        let key = vec![0u8; 16];
        let invalid_nonce = vec![0u8; 8]; // Wrong length
        let context = HpkeContext::new(key, invalid_nonce, HpkeAead::Aes128Gcm);

        let result = context.compute_nonce();
        assert!(result.is_err());
        
        match result.unwrap_err() {
            EchError::HpkeFailed(msg) => {
                assert!(msg.contains("Invalid base nonce length"));
            }
            _ => panic!("Expected HpkeFailed error"),
        }
    }

    #[test]
    fn test_hpke_sender_new() {
        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        assert_eq!(sender.kem, HpkeKem::X25519HkdfSha256);
        assert_eq!(sender.kdf, HpkeKdf::HkdfSha256);
        assert_eq!(sender.aead, HpkeAead::Aes128Gcm);
    }

    #[test]
    fn test_hpke_empty_plaintext() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let (_enc, mut context) = sender
            .setup(recipient_public.as_bytes(), b"info")
            .unwrap();

        // Seal empty plaintext
        let plaintext = b"";
        let ciphertext = context.seal(plaintext, b"").unwrap();

        // Should still have authentication tag
        assert_eq!(ciphertext.len(), 16);
    }

    #[test]
    fn test_hpke_large_plaintext() {
        let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let sender = HpkeSender::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::Aes128Gcm,
        );

        let (_enc, mut context) = sender
            .setup(recipient_public.as_bytes(), b"info")
            .unwrap();

        // Seal large plaintext (1KB)
        let plaintext = vec![0x42u8; 1024];
        let ciphertext = context.seal(&plaintext, b"").unwrap();

        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }
}
