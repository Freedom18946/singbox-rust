//! CLI commands for key generation
//!
//! Implements sing-box compatible key generation commands:
//! - generate reality-keypair: X25519 keypair for REALITY protocol
//! - generate ech-keypair: X25519 keypair for ECH (Encrypted Client Hello) with HPKE

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
pub struct GenerateArgs {
    #[command(subcommand)]
    pub command: GenerateCommands,
}

#[derive(Subcommand, Debug)]
pub enum GenerateCommands {
    /// Generate REALITY X25519 keypair
    RealityKeypair,
    /// Generate ECH (Encrypted Client Hello) X25519 keypair for HPKE
    EchKeypair,
    /// Generate a self-signed TLS keypair (PEM)
    TlsKeypair {
        /// Common Name / DNS name
        #[arg(long = "cn", default_value = "localhost")]
        cn: String,
        /// Validity in days
        #[arg(long = "days", default_value_t = 365u32)]
        days: u32,
    },
}

pub fn run(args: GenerateArgs) -> Result<()> {
    match args.command {
        GenerateCommands::RealityKeypair => generate_reality_keypair(),
        GenerateCommands::EchKeypair => generate_ech_keypair(),
        GenerateCommands::TlsKeypair { cn, days } => generate_tls_keypair(cn, days),
    }
}

/// Generate REALITY X25519 keypair
fn generate_reality_keypair() -> Result<()> {
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;

    // Generate private key
    let private_key = StaticSecret::random_from_rng(OsRng);

    // Derive public key
    let public_key = PublicKey::from(&private_key);

    // Convert to base64 for output (compatible with sing-box format)
    let private_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        private_key.to_bytes()
    );
    let public_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_key.as_bytes()
    );

    // Output in sing-box compatible format
    println!("PrivateKey: {private_base64}");
    println!("PublicKey: {public_base64}");

    Ok(())
}

/// Generate ECH keypair (X25519 for HPKE)
fn generate_ech_keypair() -> Result<()> {
    use x25519_dalek::{PublicKey, StaticSecret};
    use rand::rngs::OsRng;

    // Generate private key (X25519 scalar)
    let private_key = StaticSecret::random_from_rng(OsRng);

    // Derive public key (X25519 point)
    let public_key = PublicKey::from(&private_key);

    // Convert to base64 for output (compatible with sing-box format)
    let private_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        private_key.to_bytes()
    );
    let public_base64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        public_key.as_bytes()
    );

    // Output in sing-box compatible format
    println!("PrivateKey: {private_base64}");
    println!("PublicKey: {public_base64}");

    // Note for users
    eprintln!();
    eprintln!("Note: ECH uses DHKEM(X25519, HKDF-SHA256) with HPKE");
    eprintln!("      The public key should be published in DNS ECHConfig");

    Ok(())
}

/// Generate self-signed TLS cert + private key (PEM)
fn generate_tls_keypair(cn: String, days: u32) -> Result<()> {
    use rcgen::generate_simple_self_signed;
    let _ = days; // rcgen simple API doesn't expose validity; ignore for now.
    let cert = generate_simple_self_signed(vec![cn])
        .map_err(|e| anyhow::anyhow!("generate cert: {e}"))?;
    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| anyhow::anyhow!("serialize cert: {e}"))?;
    let key_pem = cert.serialize_private_key_pem();

    println!("Certificate:\n{}", cert_pem.trim_end());
    println!("PrivateKey:\n{}", key_pem.trim_end());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_keypair_generation() {
        // Should not panic
        let result = generate_reality_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ech_keypair_generation() {
        // Should not panic
        let result = generate_ech_keypair();
        assert!(result.is_ok());
    }
}
