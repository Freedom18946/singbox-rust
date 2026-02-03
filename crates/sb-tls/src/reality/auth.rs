//! REALITY authentication using X25519 key exchange

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha512;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// REALITY authentication helper
/// REALITY 认证助手
pub struct RealityAuth {
    secret: StaticSecret,
    public_key: PublicKey,
}

impl RealityAuth {
    /// Create new auth from private key bytes
    /// 从私钥字节创建新的认证
    #[must_use]
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&secret);

        Self { secret, public_key }
    }

    /// Generate new random keypair
    /// 生成新的随机密钥对
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);

        Self { secret, public_key }
    }

    /// Get public key bytes
    /// 获取公钥字节
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Get private key bytes
    /// 获取私钥字节
    #[must_use]
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform ECDH key exchange with peer public key
    /// 与对端公钥执行 ECDH 密钥交换
    #[must_use]
    pub fn derive_shared_secret(&self, peer_public_key: &[u8; 32]) -> [u8; 32] {
        let peer_key = PublicKey::from(*peer_public_key);
        let shared = self.secret.diffie_hellman(&peer_key);
        *shared.as_bytes()
    }

    /// Compute authentication hash
    /// 计算认证哈希
    ///
    /// This creates a deterministic hash from the shared secret and other parameters
    /// for authentication verification.
    /// 这将从共享密钥和其他参数创建一个确定性的哈希，用于认证验证。
    #[must_use]
    pub fn compute_auth_hash(
        &self,
        peer_public_key: &[u8; 32],
        short_id: &[u8],
        session_data: &[u8],
    ) -> [u8; 32] {
        let shared_secret = self.derive_shared_secret(peer_public_key);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(short_id);
        hasher.update(session_data);

        let result = hasher.finalize();
        result.into()
    }

    /// Verify authentication hash
    /// 验证认证哈希
    #[must_use]
    pub fn verify_auth_hash(
        &self,
        peer_public_key: &[u8; 32],
        short_id: &[u8],
        session_data: &[u8],
        expected_hash: &[u8; 32],
    ) -> bool {
        let computed = self.compute_auth_hash(peer_public_key, short_id, session_data);
        constant_time_compare(&computed, expected_hash)
    }
}

/// Derive REALITY auth key from shared secret and session data.
/// 从共享密钥和会话数据派生 REALITY 认证密钥。
///
/// This follows the Go reference behavior: HKDF-SHA256 with salt = session_data[0..20],
/// info = "REALITY", output = 32 bytes.
/// 该流程遵循 Go 参考实现：HKDF-SHA256，salt 为 session_data[0..20]，info 为 "REALITY"，输出 32 字节。
pub fn derive_auth_key(
    shared_secret: [u8; 32],
    session_data: &[u8; 32],
) -> Result<[u8; 32], String> {
    let salt = &session_data[..20];
    let hkdf = Hkdf::<Sha256>::new(Some(salt), &shared_secret);
    let mut okm = [0u8; 32];
    hkdf.expand(b"REALITY", &mut okm)
        .map_err(|_| "REALITY HKDF expand failed".to_string())?;
    Ok(okm)
}

/// Compute REALITY temporary certificate signature (HMAC-SHA512 over public key).
/// 计算 REALITY 临时证书签名（对公钥做 HMAC-SHA512）。
pub fn compute_temp_cert_signature(
    auth_key: &[u8; 32],
    public_key: &[u8],
) -> Result<[u8; 64], String> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(auth_key).map_err(|_| "invalid auth_key".to_string())?;
    mac.update(public_key);
    let result = mac.finalize().into_bytes();
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&result);
    Ok(signature)
}

/// Generate a new keypair and return as hex strings
/// 生成一个新的密钥对并作为十六进制字符串返回
#[must_use]
pub fn generate_keypair() -> (String, String) {
    let auth = RealityAuth::generate();
    let private_key = hex::encode(auth.private_key_bytes());
    let public_key = hex::encode(auth.public_key_bytes());
    (private_key, public_key)
}

/// Constant-time comparison to prevent timing attacks
/// 防止时序攻击的恒定时间比较
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Key Generation Tests ==========

    #[test]
    fn test_key_generation() {
        let (private_key, public_key) = generate_keypair();

        assert_eq!(private_key.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(public_key.len(), 64);

        // Verify it's valid hex
        assert!(hex::decode(&private_key).is_ok());
        assert!(hex::decode(&public_key).is_ok());
    }

    #[test]
    fn test_key_generation_uniqueness() {
        let (priv1, pub1) = generate_keypair();
        let (priv2, pub2) = generate_keypair();

        // Different keypairs should be generated
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_reality_auth_generate() {
        let auth1 = RealityAuth::generate();
        let auth2 = RealityAuth::generate();

        // Different instances should have different keys
        assert_ne!(auth1.public_key_bytes(), auth2.public_key_bytes());
        assert_ne!(auth1.private_key_bytes(), auth2.private_key_bytes());
    }

    #[test]
    fn test_reality_auth_from_private_key() {
        let private_key = [0x42u8; 32];
        let auth = RealityAuth::from_private_key(private_key);

        assert_eq!(auth.private_key_bytes(), private_key);
        assert_eq!(auth.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_derivation_from_private() {
        // Test that public key is correctly derived from private key
        let private_key = [0x77u8; 32];
        let auth1 = RealityAuth::from_private_key(private_key);
        let auth2 = RealityAuth::from_private_key(private_key);

        // Same private key should always produce same public key
        assert_eq!(auth1.public_key_bytes(), auth2.public_key_bytes());
    }

    // ========== X25519 Key Exchange Tests ==========

    #[test]
    fn test_ecdh_key_exchange() {
        let alice = RealityAuth::generate();
        let bob = RealityAuth::generate();

        let alice_shared = alice.derive_shared_secret(&bob.public_key_bytes());
        let bob_shared = bob.derive_shared_secret(&alice.public_key_bytes());

        // X25519 ECDH should produce the same shared secret on both sides
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_ecdh_different_peers_different_secrets() {
        let alice = RealityAuth::generate();
        let bob = RealityAuth::generate();
        let charlie = RealityAuth::generate();

        let alice_bob_shared = alice.derive_shared_secret(&bob.public_key_bytes());
        let alice_charlie_shared = alice.derive_shared_secret(&charlie.public_key_bytes());

        // Different peers should produce different shared secrets
        assert_ne!(alice_bob_shared, alice_charlie_shared);
    }

    #[test]
    fn test_ecdh_commutative() {
        // Test that ECDH is commutative: alice->bob == bob->alice
        let alice = RealityAuth::generate();
        let bob = RealityAuth::generate();

        let shared1 = alice.derive_shared_secret(&bob.public_key_bytes());
        let shared2 = bob.derive_shared_secret(&alice.public_key_bytes());

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_multiple_key_exchanges() {
        let auth = RealityAuth::generate();
        let peer = RealityAuth::generate();
        let peer_pub = peer.public_key_bytes();

        // Should be able to derive shared secret multiple times
        let shared1 = auth.derive_shared_secret(&peer_pub);
        let shared2 = auth.derive_shared_secret(&peer_pub);
        let shared3 = auth.derive_shared_secret(&peer_pub);

        assert_eq!(shared1, shared2);
        assert_eq!(shared2, shared3);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let private_key = [42u8; 32];
        let auth1 = RealityAuth::from_private_key(private_key);
        let auth2 = RealityAuth::from_private_key(private_key);

        // Same private key should produce same public key
        assert_eq!(auth1.public_key_bytes(), auth2.public_key_bytes());

        // Shared secret with same peer should be identical
        let peer = RealityAuth::generate();
        let peer_pub = peer.public_key_bytes();

        let shared1 = auth1.derive_shared_secret(&peer_pub);
        let shared2 = auth2.derive_shared_secret(&peer_pub);

        assert_eq!(shared1, shared2);
    }

    // ========== Authentication Hash Tests ==========

    #[test]
    fn test_auth_hash_verification() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let short_id = b"test";
        let session_data = b"session123";

        let hash = client.compute_auth_hash(&server.public_key_bytes(), short_id, session_data);

        assert!(
            server.verify_auth_hash(&client.public_key_bytes(), short_id, session_data, &hash,)
        );

        // Wrong session data should fail
        assert!(!server.verify_auth_hash(&client.public_key_bytes(), short_id, b"wrong", &hash,));
    }

    #[test]
    fn test_auth_hash_wrong_short_id() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let short_id = b"test";
        let session_data = b"session123";

        let hash = client.compute_auth_hash(&server.public_key_bytes(), short_id, session_data);

        // Wrong short_id should fail
        assert!(!server.verify_auth_hash(
            &client.public_key_bytes(),
            b"wrong",
            session_data,
            &hash,
        ));
    }

    #[test]
    fn test_auth_hash_wrong_peer_key() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();
        let imposter = RealityAuth::generate();

        let short_id = b"test";
        let session_data = b"session123";

        let hash = client.compute_auth_hash(&server.public_key_bytes(), short_id, session_data);

        // Wrong peer public key should fail
        assert!(!server.verify_auth_hash(
            &imposter.public_key_bytes(),
            short_id,
            session_data,
            &hash,
        ));
    }

    #[test]
    fn test_auth_hash_deterministic() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let short_id = b"test";
        let session_data = b"session123";

        let hash1 = client.compute_auth_hash(&server.public_key_bytes(), short_id, session_data);

        let hash2 = client.compute_auth_hash(&server.public_key_bytes(), short_id, session_data);

        // Same inputs should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_auth_hash_different_inputs() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let hash1 = client.compute_auth_hash(&server.public_key_bytes(), b"short1", b"session1");

        let hash2 = client.compute_auth_hash(&server.public_key_bytes(), b"short2", b"session2");

        // Different inputs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_auth_hash_empty_short_id() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let session_data = b"session123";

        let hash = client.compute_auth_hash(&server.public_key_bytes(), b"", session_data);

        // Empty short_id should work
        assert!(server.verify_auth_hash(&client.public_key_bytes(), b"", session_data, &hash,));
    }

    #[test]
    fn test_auth_hash_large_session_data() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let short_id = b"test";
        let session_data = vec![0x42u8; 1024]; // Large session data

        let hash = client.compute_auth_hash(&server.public_key_bytes(), short_id, &session_data);

        assert!(server.verify_auth_hash(
            &client.public_key_bytes(),
            short_id,
            &session_data,
            &hash,
        ));
    }

    // ========== Constant-Time Comparison Tests ==========

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &[1, 2, 3]));
    }

    #[test]
    fn test_constant_time_compare_empty() {
        assert!(constant_time_compare(&[], &[]));
        assert!(!constant_time_compare(&[1], &[]));
        assert!(!constant_time_compare(&[], &[1]));
    }

    #[test]
    fn test_constant_time_compare_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_single_bit_difference() {
        let a = [0xFF; 32];
        let mut b = [0xFF; 32];
        b[15] = 0xFE; // Single bit difference

        assert!(!constant_time_compare(&a, &b));
    }

    #[test]
    fn test_constant_time_compare_length_mismatch() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4, 5];

        assert!(!constant_time_compare(&a, &b));
    }
}
