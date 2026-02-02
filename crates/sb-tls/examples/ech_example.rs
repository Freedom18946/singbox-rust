//! ECH (Encrypted Client Hello) usage example
//!
//! This example demonstrates how to use the ECH connector to encrypt
//! the ClientHello SNI field.

#[cfg(feature = "ech")]
use sb_tls::ech::{EchClientConfig, EchConnector};

#[cfg(not(feature = "ech"))]
fn main() {
    eprintln!("This example requires the 'ech' feature to be enabled.");
    eprintln!("Run with: cargo run --example ech_example --features ech");
    std::process::exit(1);
}

#[cfg(feature = "ech")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ECH (Encrypted Client Hello) Example");
    println!("=====================================\n");

    // Example 1: Create ECH configuration
    println!("1. Creating ECH configuration...");

    // In a real scenario, this would come from DNS TXT records or server config
    let ech_config_base64 = create_example_ech_config();

    let config = EchClientConfig::new(ech_config_base64)?;
    println!("   ✓ ECH configuration created\n");

    // Example 2: Create ECH connector
    println!("2. Creating ECH connector...");
    let connector = EchConnector::new(config)?;
    println!("   ✓ ECH connector initialized\n");

    // Example 3: Wrap TLS connection with ECH
    println!("3. Encrypting ClientHello with ECH...");
    let real_server_name = "secret.example.com";
    let ech_hello = connector.wrap_tls(real_server_name)?;

    println!("   ✓ ClientHello encrypted successfully");
    println!("   - Outer SNI (public): {}", ech_hello.outer_sni);
    println!("   - Inner SNI (encrypted): {}", ech_hello.inner_sni);
    println!(
        "   - ECH payload size: {} bytes",
        ech_hello.ech_payload.len()
    );
    println!(
        "   - Encapsulated key size: {} bytes\n",
        ech_hello.encapsulated_key.len()
    );

    // Example 4: Verify ECH acceptance (simulated)
    println!("4. Verifying ECH acceptance...");
    let simulated_server_hello = create_simulated_server_hello();
    let accepted = connector.verify_ech_acceptance(&simulated_server_hello)?;

    if accepted {
        println!("   ✓ Server accepted ECH");
    } else {
        println!("   ✗ Server did not accept ECH");
    }

    println!("\n✓ ECH example completed successfully!");

    Ok(())
}

/// Create an example ECH config list for demonstration
#[cfg(feature = "ech")]
fn create_example_ech_config() -> String {
    use base64::Engine;
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public_key = PublicKey::from(&secret);

    let mut config_list = Vec::new();

    // List length (will be filled later)
    let list_start = config_list.len();
    config_list.extend_from_slice(&[0x00, 0x00]);

    // ECH version (0xfe0d = Draft-13)
    config_list.extend_from_slice(&[0xfe, 0x0d]);

    // Config length (will be filled later)
    let config_start = config_list.len();
    config_list.extend_from_slice(&[0x00, 0x00]);

    // Config id + KEM id
    config_list.push(0x01);
    config_list.extend_from_slice(&[0x00, 0x20]); // X25519

    // Public key length + public key (32 bytes for X25519)
    config_list.extend_from_slice(&[0x00, 0x20]);
    config_list.extend_from_slice(public_key.as_bytes());

    // Cipher suites length + cipher suite (KDF + AEAD)
    config_list.extend_from_slice(&[0x00, 0x04]);
    config_list.extend_from_slice(&[0x00, 0x01]); // KDF: HKDF-SHA256
    config_list.extend_from_slice(&[0x00, 0x01]); // AEAD: AES-128-GCM

    // Maximum name length
    config_list.push(64);

    // Public name length + public name
    let public_name = b"public.example.com";
    config_list.push(public_name.len() as u8);
    config_list.extend_from_slice(public_name);

    // Extensions length (empty)
    config_list.extend_from_slice(&[0x00, 0x00]);

    // Fill in config length
    let config_len = config_list.len() - config_start - 2;
    config_list[config_start..config_start + 2].copy_from_slice(&(config_len as u16).to_be_bytes());

    // Fill in list length
    let list_len = config_list.len() - list_start - 2;
    config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

    base64::engine::general_purpose::STANDARD.encode(&config_list)
}

/// Create a simulated ServerHello with ECH acceptance
#[cfg(feature = "ech")]
fn create_simulated_server_hello() -> Vec<u8> {
    let mut server_hello = vec![0x00; 10];
    // Add ECH extension type (0xfe0d) to indicate acceptance
    server_hello.extend_from_slice(&[0xfe, 0x0d]);
    server_hello.extend_from_slice(&[0x00; 10]);
    server_hello
}
