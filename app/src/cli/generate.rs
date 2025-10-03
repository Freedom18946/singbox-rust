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
}

pub fn run(args: GenerateArgs) -> Result<()> {
    match args.command {
        GenerateCommands::RealityKeypair => generate_reality_keypair(),
        GenerateCommands::EchKeypair => generate_ech_keypair(),
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
