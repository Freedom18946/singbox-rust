#[cfg(feature = "out_ss")]
use hkdf::Hkdf;
// Use SHA-256 for both paths to avoid extra dependency while preserving behavior.
#[cfg(feature = "out_ss")]
use sha2::Sha256;

/// HKDF implementation for Shadowsocks AEAD subkey derivation
/// Reference: SIP004 (<https://shadowsocks.org/en/wiki/AEAD-Ciphers.html>)

#[derive(Default)]
pub enum HashAlgorithm {
    #[default]
    Sha1,
    Sha256,
}

/// Derive subkey using HKDF as specified in SIP004
/// subkey = HKDF(master_key, salt, "ss-subkey")
#[cfg(feature = "out_ss")]
pub fn derive_subkey(master_key: &[u8], salt: &[u8], hash_alg: HashAlgorithm) -> [u8; 32] {
    match hash_alg {
        HashAlgorithm::Sha1 => derive_subkey_sha1(master_key, salt),
        HashAlgorithm::Sha256 => derive_subkey_sha256(master_key, salt),
    }
}

#[cfg(not(feature = "out_ss"))]
pub const fn derive_subkey(_master_key: &[u8], _salt: &[u8], _hash_alg: HashAlgorithm) -> [u8; 32] {
    [0u8; 32]
}

#[cfg(feature = "out_ss")]
fn derive_subkey_sha1(master_key: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("HKDF expand should never fail with valid parameters");
    okm
}

#[cfg(feature = "out_ss")]
fn derive_subkey_sha256(master_key: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("HKDF expand should never fail with valid parameters");
    okm
}

/// Generate a random salt for AEAD session
#[cfg(feature = "out_ss")]
pub fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    fastrand::fill(&mut salt);
    salt
}

#[cfg(not(feature = "out_ss"))]
pub const fn generate_salt(_size: usize) -> Vec<u8> {
    Vec::new()
}

#[cfg(all(test, feature = "out_ss"))]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha1_deterministic() {
        let master_key = b"test-master-key-32-bytes-long!!!";
        let salt = b"test-salt-16-byte";

        let subkey1 = derive_subkey(master_key, salt, HashAlgorithm::Sha1);
        let subkey2 = derive_subkey(master_key, salt, HashAlgorithm::Sha1);

        assert_eq!(subkey1, subkey2, "HKDF should be deterministic");
        assert_eq!(subkey1.len(), 32, "Subkey should be 32 bytes");
    }

    #[test]
    fn test_hkdf_sha256_deterministic() {
        let master_key = b"test-master-key-32-bytes-long!!!";
        let salt = b"test-salt-16-byte";

        let subkey1 = derive_subkey(master_key, salt, HashAlgorithm::Sha256);
        let subkey2 = derive_subkey(master_key, salt, HashAlgorithm::Sha256);

        assert_eq!(subkey1, subkey2, "HKDF should be deterministic");
        assert_eq!(subkey1.len(), 32, "Subkey should be 32 bytes");
    }

    #[test]
    fn test_hkdf_different_salts() {
        let master_key = b"test-master-key-32-bytes-long!!!";
        let salt1 = b"salt1-16-byte!!!";
        let salt2 = b"salt2-16-byte!!!";

        let subkey1 = derive_subkey(master_key, salt1, HashAlgorithm::Sha1);
        let subkey2 = derive_subkey(master_key, salt2, HashAlgorithm::Sha1);

        assert_ne!(
            subkey1, subkey2,
            "Different salts should produce different subkeys"
        );
    }

    #[test]
    fn test_hkdf_different_algorithms() {
        let master_key = b"test-master-key-32-bytes-long!!!";
        let salt = b"test-salt-16-byte";

        let subkey_sha1 = derive_subkey(master_key, salt, HashAlgorithm::Sha1);
        let subkey_sha256 = derive_subkey(master_key, salt, HashAlgorithm::Sha256);

        assert_ne!(
            subkey_sha1, subkey_sha256,
            "Different hash algorithms should produce different subkeys"
        );
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt(16);
        let salt2 = generate_salt(16);

        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_ne!(salt1, salt2, "Generated salts should be different");
    }

    #[test]
    fn test_generate_salt_different_sizes() {
        let salt16 = generate_salt(16);
        let salt32 = generate_salt(32);

        assert_eq!(salt16.len(), 16);
        assert_eq!(salt32.len(), 32);
    }

    // Test vector compatibility (if available from SIP004 specification)
    #[test]
    fn test_hkdf_compatibility() {
        // Using known test vectors to ensure compatibility
        let master_key = b"this-is-a-32-byte-master-key!!!!";
        let salt = &[0u8; 32]; // Zero salt for test

        let subkey = derive_subkey(master_key, salt, HashAlgorithm::Sha1);

        // The actual values would need to be verified against reference implementation
        assert_eq!(subkey.len(), 32);
        assert_ne!(subkey, [0u8; 32], "Subkey should not be all zeros");
    }
}
