//! ECH (Encrypted Client Hello) keypair generation with Go-compatible PEM output.
//!
//! Implements the wire format for ECHConfig per draft-ietf-tls-esni and produces
//! PEM-encoded config/key blocks compatible with sing-box Go (`common/tls/ech_shared.go`).

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

// ── Wire-format constants ────────────────────────────────────────────

const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
const KDF_HKDF_SHA256: u16 = 0x0001;
const AEAD_AES_128_GCM: u16 = 0x0001;
const AEAD_AES_256_GCM: u16 = 0x0002;
const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

// ── Public API ───────────────────────────────────────────────────────

/// Build an ECHConfig wire-format blob (no outer length prefix).
///
/// This matches the Go `marshalECHConfig` function from `common/tls/ech_shared.go`.
pub fn marshal_ech_config(
    id: u8,
    pub_key: &[u8],
    public_name: &str,
    max_name_len: u8,
) -> Vec<u8> {
    // Inner content (everything inside the outer u16-length-prefixed block)
    let mut inner = Vec::new();
    inner.push(id);
    inner.extend_from_slice(&DHKEM_X25519_HKDF_SHA256.to_be_bytes());

    // pub_key with u16 length prefix
    append_u16_length_prefixed(&mut inner, pub_key);

    // Cipher suites with u16 length prefix
    let mut suites = Vec::new();
    for &aead_id in &[AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305] {
        suites.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
        suites.extend_from_slice(&aead_id.to_be_bytes());
    }
    append_u16_length_prefixed(&mut inner, &suites);

    inner.push(max_name_len);

    // public_name with u8 length prefix
    append_u8_length_prefixed(&mut inner, public_name.as_bytes());

    // extensions: empty (u16 zero)
    inner.extend_from_slice(&0u16.to_be_bytes());

    // Outer: version (u16) + u16-length-prefixed(inner)
    let mut out = Vec::new();
    out.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
    append_u16_length_prefixed(&mut out, &inner);
    out
}

/// Generate an ECH keypair and return Go-compatible PEM strings.
///
/// Returns `(config_pem, key_pem)` where:
/// - `config_pem` is a PEM block of type `ECH CONFIGS`
/// - `key_pem`    is a PEM block of type `ECH KEYS`
///
/// This matches the Go `ECHKeygenDefault` function from `common/tls/ech_shared.go`.
pub fn ech_keygen_default(public_name: &str) -> (String, String) {
    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    let ech_config = marshal_ech_config(0, public_key.as_bytes(), public_name, 0);

    // config_bytes = u16_length_prefix(ech_config)
    let config_bytes = u16_length_prefixed(&ech_config);

    // key_bytes = u16_length_prefix(private_key) + u16_length_prefix(ech_config)
    let mut key_bytes = u16_length_prefixed(&private_key.to_bytes());
    key_bytes.extend_from_slice(&u16_length_prefixed(&ech_config));

    let config_pem = encode_pem("ECH CONFIGS", &config_bytes);
    let key_pem = encode_pem("ECH KEYS", &key_bytes);

    (config_pem, key_pem)
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Append `data` preceded by a big-endian u16 length prefix to `buf`.
fn append_u16_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Append `data` preceded by a u8 length prefix to `buf`.
fn append_u8_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

/// Return `data` with a big-endian u16 length prefix.
fn u16_length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Encode binary data as a PEM block with the given type label.
///
/// Produces output like:
/// ```text
/// -----BEGIN ECH CONFIGS-----
/// <base64, wrapped at 64 chars>
/// -----END ECH CONFIGS-----
/// ```
fn encode_pem(label: &str, data: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marshal_ech_config_structure() {
        let pub_key = [0xABu8; 32]; // dummy 32-byte key
        let config = marshal_ech_config(0, &pub_key, "example.com", 0);

        // First two bytes: extension type 0xfe0d
        assert_eq!(config[0], 0xfe);
        assert_eq!(config[1], 0x0d);

        // Bytes 2-3: u16 length of inner content
        let inner_len = u16::from_be_bytes([config[2], config[3]]) as usize;
        assert_eq!(config.len(), 4 + inner_len);

        // Byte 4: id = 0
        assert_eq!(config[4], 0);

        // Bytes 5-6: DHKEM = 0x0020
        assert_eq!(config[5], 0x00);
        assert_eq!(config[6], 0x20);

        // Bytes 7-8: pub_key length = 32
        assert_eq!(u16::from_be_bytes([config[7], config[8]]), 32);
    }

    #[test]
    fn test_marshal_ech_config_contains_public_name() {
        let pub_key = [0x42u8; 32];
        let config = marshal_ech_config(0, &pub_key, "test.example.org", 0);

        // The config should contain the public name bytes
        let name_bytes = b"test.example.org";
        let config_str = config
            .windows(name_bytes.len())
            .any(|w| w == name_bytes);
        assert!(config_str, "ECHConfig must contain the public_name");
    }

    #[test]
    fn test_marshal_ech_config_cipher_suites() {
        let pub_key = [0x00u8; 32];
        let config = marshal_ech_config(0, &pub_key, "a.com", 0);

        // After the pub_key block (offset 9 + 32 = 41), we have the cipher suites block.
        // Offset 41-42: u16 length of cipher suites
        let suites_len = u16::from_be_bytes([config[41], config[42]]) as usize;
        // 3 suites * 4 bytes each = 12
        assert_eq!(suites_len, 12);

        // First suite: KDF=0x0001, AEAD=0x0001
        assert_eq!(u16::from_be_bytes([config[43], config[44]]), KDF_HKDF_SHA256);
        assert_eq!(u16::from_be_bytes([config[45], config[46]]), AEAD_AES_128_GCM);

        // Second suite: KDF=0x0001, AEAD=0x0002
        assert_eq!(u16::from_be_bytes([config[47], config[48]]), KDF_HKDF_SHA256);
        assert_eq!(u16::from_be_bytes([config[49], config[50]]), AEAD_AES_256_GCM);

        // Third suite: KDF=0x0001, AEAD=0x0003
        assert_eq!(u16::from_be_bytes([config[51], config[52]]), KDF_HKDF_SHA256);
        assert_eq!(u16::from_be_bytes([config[53], config[54]]), AEAD_CHACHA20_POLY1305);
    }

    #[test]
    fn test_ech_keygen_pem_format() {
        let (config_pem, key_pem) = ech_keygen_default("example.com");

        // Config PEM has correct headers
        assert!(config_pem.starts_with("-----BEGIN ECH CONFIGS-----\n"));
        assert!(config_pem.ends_with("-----END ECH CONFIGS-----\n"));

        // Key PEM has correct headers
        assert!(key_pem.starts_with("-----BEGIN ECH KEYS-----\n"));
        assert!(key_pem.ends_with("-----END ECH KEYS-----\n"));
    }

    #[test]
    fn test_ech_keygen_pem_base64_roundtrip() {
        use base64::Engine;
        let (config_pem, key_pem) = ech_keygen_default("roundtrip.test");

        // Extract base64 body from config PEM
        let config_b64: String = config_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let config_bytes = base64::engine::general_purpose::STANDARD
            .decode(&config_b64)
            .expect("config PEM body must be valid base64");

        // First two bytes of decoded config_bytes are u16 length prefix
        let inner_len = u16::from_be_bytes([config_bytes[0], config_bytes[1]]) as usize;
        assert_eq!(config_bytes.len(), 2 + inner_len);

        // The inner bytes should start with 0xfe0d (ECH extension type)
        assert_eq!(config_bytes[2], 0xfe);
        assert_eq!(config_bytes[3], 0x0d);

        // Extract base64 body from key PEM
        let key_b64: String = key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .expect("key PEM body must be valid base64");

        // key_bytes = u16_prefix(32-byte private key) + u16_prefix(ech_config)
        let priv_len = u16::from_be_bytes([key_bytes[0], key_bytes[1]]) as usize;
        assert_eq!(priv_len, 32, "X25519 private key must be 32 bytes");

        // After private key block, the rest is u16_prefix(ech_config)
        let rest = &key_bytes[2 + priv_len..];
        let cfg_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        assert_eq!(rest.len(), 2 + cfg_len);
        // And the ech_config should start with 0xfe0d
        assert_eq!(rest[2], 0xfe);
        assert_eq!(rest[3], 0x0d);
    }

    #[test]
    fn test_ech_keygen_unique_keys() {
        let (config1, key1) = ech_keygen_default("test.com");
        let (config2, key2) = ech_keygen_default("test.com");

        // Two generations should produce different keys
        assert_ne!(key1, key2, "each invocation must produce a unique keypair");
        assert_ne!(config1, config2, "configs embed different public keys");
    }
}
