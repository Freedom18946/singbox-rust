//! REALITY authentication using X25519 key exchange

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// REALITY authentication helper
pub struct RealityAuth {
    secret: StaticSecret,
    public_key: PublicKey,
}

impl RealityAuth {
    /// Create new auth from private key bytes
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
        }
    }

    /// Generate new random keypair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);

        Self {
            secret,
            public_key,
        }
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Perform ECDH key exchange with peer public key
    pub fn derive_shared_secret(&self, peer_public_key: &[u8; 32]) -> [u8; 32] {
        let peer_key = PublicKey::from(*peer_public_key);
        let shared = self.secret.diffie_hellman(&peer_key);
        *shared.as_bytes()
    }

    /// Compute authentication hash
    ///
    /// This creates a deterministic hash from the shared secret and other parameters
    /// for authentication verification.
    pub fn compute_auth_hash(
        &self,
        peer_public_key: &[u8; 32],
        short_id: &[u8],
        session_data: &[u8],
    ) -> [u8; 32] {
        let shared_secret = self.derive_shared_secret(peer_public_key);

        let mut hasher = Sha256::new();
        hasher.update(&shared_secret);
        hasher.update(short_id);
        hasher.update(session_data);

        let result = hasher.finalize();
        result.into()
    }

    /// Verify authentication hash
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

/// Generate a new keypair and return as hex strings
pub fn generate_keypair() -> (String, String) {
    let auth = RealityAuth::generate();
    let private_key = hex::encode(auth.private_key_bytes());
    let public_key = hex::encode(auth.public_key_bytes());
    (private_key, public_key)
}

/// Constant-time comparison to prevent timing attacks
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
    fn test_ecdh_key_exchange() {
        let alice = RealityAuth::generate();
        let bob = RealityAuth::generate();

        let alice_shared = alice.derive_shared_secret(&bob.public_key_bytes());
        let bob_shared = bob.derive_shared_secret(&alice.public_key_bytes());

        // X25519 ECDH should produce the same shared secret on both sides
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_auth_hash_verification() {
        let server = RealityAuth::generate();
        let client = RealityAuth::generate();

        let short_id = b"test";
        let session_data = b"session123";

        let hash = client.compute_auth_hash(
            &server.public_key_bytes(),
            short_id,
            session_data,
        );

        assert!(server.verify_auth_hash(
            &client.public_key_bytes(),
            short_id,
            session_data,
            &hash,
        ));

        // Wrong session data should fail
        assert!(!server.verify_auth_hash(
            &client.public_key_bytes(),
            short_id,
            b"wrong",
            &hash,
        ));
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
}
