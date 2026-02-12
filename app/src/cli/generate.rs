//! CLI commands for key generation
//!
//! Implements sing-box compatible key generation commands:
//! - generate uuid: Generate a V4 UUID string
//! - generate rand: Generate random bytes (raw / base64 / hex)
//! - generate reality-keypair: X25519 keypair for REALITY protocol
//! - generate ech-keypair: X25519 keypair for ECH with Go-compatible PEM output
//! - generate tls-keypair: Self-signed TLS certificate + private key (PEM)
//! - generate vapid-keypair: VAPID (WebPush) P-256 keypair
//! - generate wireguard-keypair: WireGuard X25519 keypair

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
pub struct GenerateArgs {
    #[command(subcommand)]
    pub command: GenerateCommands,
}

#[derive(Subcommand, Debug)]
pub enum GenerateCommands {
    /// Generate UUID string (V4)
    Uuid,
    /// Generate random bytes
    Rand {
        /// Number of random bytes to generate
        length: usize,
        /// Output as base64 string
        #[arg(long)]
        base64: bool,
        /// Output as hex string
        #[arg(long)]
        hex: bool,
    },
    /// Generate REALITY X25519 keypair
    RealityKeypair,
    /// Generate ECH (Encrypted Client Hello) keypair with PEM output
    EchKeypair {
        /// Plain server name for the ECHConfig public_name field
        server_name: String,
    },
    /// Generate a self-signed TLS keypair (PEM)
    TlsKeypair {
        /// Common Name / DNS name
        #[arg(long = "cn", default_value = "localhost")]
        cn: String,
        /// Validity in days
        #[arg(long = "days", default_value_t = 365u32)]
        days: u32,
    },
    /// Generate VAPID (`WebPush`) P-256 keypair
    #[cfg(feature = "jwt")]
    VapidKeypair,
    /// Generate `WireGuard` X25519 keypair
    WireguardKeypair,
}

pub fn run(args: GenerateArgs) -> Result<()> {
    match args.command {
        GenerateCommands::Uuid => generate_uuid(),
        GenerateCommands::Rand {
            length,
            base64,
            hex,
        } => generate_rand(length, base64, hex),
        GenerateCommands::RealityKeypair => generate_reality_keypair(),
        GenerateCommands::EchKeypair { server_name } => generate_ech_keypair(&server_name),
        GenerateCommands::TlsKeypair { cn, days } => generate_tls_keypair(cn, days),
        #[cfg(feature = "jwt")]
        GenerateCommands::VapidKeypair => generate_vapid_keypair(),
        GenerateCommands::WireguardKeypair => generate_wireguard_keypair(),
    }
}

// ── L15.1.1: generate uuid ──────────────────────────────────────────

/// Generate a V4 UUID and print it to stdout.
///
/// Matches Go `generateUUID()` from `cmd_generate.go`.
fn generate_uuid() -> Result<()> {
    let id = uuid::Uuid::new_v4();
    println!("{id}");
    Ok(())
}

// ── L15.1.2: generate rand ──────────────────────────────────────────

/// Generate random bytes and output them (raw, base64, or hex).
///
/// Matches Go `generateRandom()` from `cmd_generate.go`:
/// - `--base64`: base64-encoded string + newline
/// - `--hex`:    hex-encoded string + newline
/// - neither:    raw bytes to stdout (no newline)
fn generate_rand(length: usize, output_base64: bool, output_hex: bool) -> Result<()> {
    use rand::RngCore;
    use std::io::Write;

    let mut buf = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut buf);

    if output_base64 {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buf);
        println!("{encoded}");
    } else if output_hex {
        let encoded = hex::encode(&buf);
        println!("{encoded}");
    } else {
        // Raw bytes to stdout, matching Go behaviour (no trailing newline)
        std::io::stdout().write_all(&buf)?;
    }
    Ok(())
}

// ── L15.1.3: generate ech-keypair (Go-compatible PEM) ───────────────

/// Generate ECH keypair and print Go-compatible PEM blocks.
///
/// Matches Go `generateECHKeyPair()` from `cmd_generate_ech.go`.
fn generate_ech_keypair(server_name: &str) -> Result<()> {
    let (config_pem, key_pem) = ech_keygen::ech_keygen_default(server_name);
    print!("{config_pem}");
    print!("{key_pem}");
    Ok(())
}

/// Inline ECH keypair generation module.
///
/// This duplicates the wire-format logic from `sb-tls::ech_keygen` so that the
/// CLI `generate ech-keypair` command works without requiring the optional `sb-tls`
/// dependency in the `app` crate.
mod ech_keygen {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Wire-format constants (draft-ietf-tls-esni)
    const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
    const DHKEM_X25519_HKDF_SHA256: u16 = 0x0020;
    const KDF_HKDF_SHA256: u16 = 0x0001;
    const AEAD_AES_128_GCM: u16 = 0x0001;
    const AEAD_AES_256_GCM: u16 = 0x0002;
    const AEAD_CHACHA20_POLY1305: u16 = 0x0003;

    /// Generate an ECH keypair and return Go-compatible PEM strings.
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

    /// Build an ECHConfig wire-format blob.
    ///
    /// Matches Go `marshalECHConfig` from `common/tls/ech_shared.go`.
    pub fn marshal_ech_config(
        id: u8,
        pub_key: &[u8],
        public_name: &str,
        max_name_len: u8,
    ) -> Vec<u8> {
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
        inner.push(public_name.len() as u8);
        inner.extend_from_slice(public_name.as_bytes());

        // extensions: empty (u16 zero)
        inner.extend_from_slice(&0u16.to_be_bytes());

        // Outer: version (u16) + u16-length-prefixed(inner)
        let mut out = Vec::new();
        out.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        append_u16_length_prefixed(&mut out, &inner);
        out
    }

    fn append_u16_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
    }

    fn u16_length_prefixed(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + data.len());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

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
}

// ── Existing commands ────────────────────────────────────────────────

/// Generate REALITY X25519 keypair
fn generate_reality_keypair() -> Result<()> {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Generate private key
    let private_key = StaticSecret::random_from_rng(OsRng);

    // Derive public key
    let public_key = PublicKey::from(&private_key);

    // Convert to base64 for output (compatible with sing-box format)
    let private_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        private_key.to_bytes(),
    );
    let public_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_key.as_bytes(),
    );

    // Output in sing-box compatible format
    println!("PrivateKey: {private_base64}");
    println!("PublicKey: {public_base64}");

    Ok(())
}

/// Generate self-signed TLS cert + private key (PEM)
fn generate_tls_keypair(cn: String, days: u32) -> Result<()> {
    use rcgen::generate_simple_self_signed;
    let _ = days; // rcgen simple API doesn't expose validity; ignore for now.
    let cert =
        generate_simple_self_signed(vec![cn]).map_err(|e| anyhow::anyhow!("generate cert: {e}"))?;
    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| anyhow::anyhow!("serialize cert: {e}"))?;
    let key_pem = cert.serialize_private_key_pem();

    println!("Certificate:\n{}", cert_pem.trim_end());
    println!("PrivateKey:\n{}", key_pem.trim_end());
    Ok(())
}

/// Generate VAPID (P-256) keypair
#[cfg(feature = "jwt")]
fn generate_vapid_keypair() -> Result<()> {
    use p256::ecdsa::SigningKey;
    #[allow(unused_imports)]
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let pk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
    let sk_bytes = sk.to_bytes().to_vec();

    // VAPID commonly uses base64url without padding
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    println!("PrivateKey: {}", base64::Engine::encode(&b64url, &sk_bytes));
    println!("PublicKey: {}", base64::Engine::encode(&b64url, &pk_bytes));
    Ok(())
}

/// Generate `WireGuard` X25519 keypair (base64 like `wg genkey`/`wg pubkey`)
fn generate_wireguard_keypair() -> Result<()> {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    let b64 = &base64::engine::general_purpose::STANDARD;
    println!("PrivateKey: {}", base64::Engine::encode(b64, sk.to_bytes()));
    println!("PublicKey: {}", base64::Engine::encode(b64, pk.as_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── L15.1.1: UUID tests ─────────────────────────────────────────

    #[test]
    fn test_uuid_generates_valid_v4() {
        // Capture UUID output by calling the inner uuid crate directly
        // (generate_uuid() prints to stdout which is hard to capture in unit tests).
        let id = uuid::Uuid::new_v4();
        let s = id.to_string();

        // UUID v4 format: 8-4-4-4-12 hex digits
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|&c| c == '-').count(), 4);

        // Version nibble (char at position 14) must be '4'
        assert_eq!(s.as_bytes()[14], b'4', "UUID version must be 4");

        // Variant nibble (char at position 19) must be 8, 9, a, or b
        let variant_char = s.as_bytes()[19];
        assert!(
            matches!(variant_char, b'8' | b'9' | b'a' | b'b'),
            "UUID variant must be RFC 4122 (8/9/a/b), got: {}",
            variant_char as char,
        );
    }

    #[test]
    fn test_uuid_command_succeeds() {
        let result = generate_uuid();
        assert!(result.is_ok());
    }

    // ── L15.1.2: Rand tests ─────────────────────────────────────────

    #[test]
    fn test_rand_base64_output() {
        // Generating 32 bytes as base64 should succeed
        let result = generate_rand(32, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rand_hex_output() {
        let result = generate_rand(16, false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rand_raw_output() {
        // Raw output of 0 bytes (edge case)
        let result = generate_rand(0, false, false);
        assert!(result.is_ok());
    }

    // ── L15.1.3: ECH keypair tests ──────────────────────────────────

    #[test]
    fn test_ech_keypair_pem_format() {
        let (config_pem, key_pem) = ech_keygen::ech_keygen_default("example.com");

        assert!(
            config_pem.starts_with("-----BEGIN ECH CONFIGS-----\n"),
            "config PEM must have correct header"
        );
        assert!(
            config_pem.ends_with("-----END ECH CONFIGS-----\n"),
            "config PEM must have correct footer"
        );
        assert!(
            key_pem.starts_with("-----BEGIN ECH KEYS-----\n"),
            "key PEM must have correct header"
        );
        assert!(
            key_pem.ends_with("-----END ECH KEYS-----\n"),
            "key PEM must have correct footer"
        );
    }

    #[test]
    fn test_ech_keypair_config_contains_ech_extension() {
        use base64::Engine;
        let (config_pem, _) = ech_keygen::ech_keygen_default("test.example.org");

        // Decode the PEM body
        let b64_body: String = config_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&b64_body)
            .expect("valid base64");

        // Skip u16 length prefix, then check 0xfe0d extension type
        assert!(raw.len() > 4);
        assert_eq!(raw[2], 0xfe, "ECH extension type high byte");
        assert_eq!(raw[3], 0x0d, "ECH extension type low byte");
    }

    #[test]
    fn test_ech_keypair_roundtrip_key_structure() {
        use base64::Engine;
        let (_, key_pem) = ech_keygen::ech_keygen_default("roundtrip.test");

        let b64_body: String = key_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&b64_body)
            .expect("valid base64");

        // key_bytes = u16_prefix(32-byte private key) + u16_prefix(ech_config)
        let priv_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        assert_eq!(priv_len, 32, "X25519 private key must be 32 bytes");

        let rest = &raw[2 + priv_len..];
        let cfg_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        assert_eq!(rest.len(), 2 + cfg_len, "remaining bytes must match config length prefix");
    }

    #[test]
    fn test_ech_marshal_config_wire_format() {
        let pub_key = [0xABu8; 32];
        let config = ech_keygen::marshal_ech_config(0, &pub_key, "example.com", 0);

        // First two bytes: extension type 0xfe0d
        assert_eq!(config[0], 0xfe);
        assert_eq!(config[1], 0x0d);

        // Bytes 2-3: u16 length of inner content
        let inner_len = u16::from_be_bytes([config[2], config[3]]) as usize;
        assert_eq!(config.len(), 4 + inner_len);
    }

    #[test]
    fn test_ech_keypair_command_succeeds() {
        let result = generate_ech_keypair("localhost");
        assert!(result.is_ok());
    }

    // ── Existing tests ──────────────────────────────────────────────

    #[test]
    fn test_reality_keypair_generation() {
        // Should not panic
        let result = generate_reality_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_wireguard_keypair_generation() {
        let result = generate_wireguard_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_tls_keypair_generation() {
        let result = generate_tls_keypair("localhost".to_string(), 1);
        assert!(result.is_ok());
    }
}
