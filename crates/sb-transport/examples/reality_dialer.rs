//! Example demonstrating REALITY TLS dialer usage
//!
//! This example shows how to create and configure a REALITY dialer
//! for anti-censorship TLS connections.
//!
//! Run with:
//! ```bash
//! cargo run --example reality_dialer --features transport_reality
//! ```

#[cfg(feature = "transport_reality")]
fn main() {
    use sb_tls::RealityClientConfig;
    use sb_transport::{RealityDialer, TcpDialer};

    println!("=== REALITY TLS Dialer Example ===\n");

    // Example 1: Create REALITY dialer with explicit configuration
    println!("1. Creating REALITY dialer with explicit config:");
    let config = RealityClientConfig {
        target: "www.apple.com".to_string(),
        server_name: "www.apple.com".to_string(),
        public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        short_id: Some("01ab".to_string()),
        fingerprint: "chrome".to_string(),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
    };

    match RealityDialer::new(TcpDialer::default(), config) {
        Ok(_dialer) => {
            println!("   ✓ REALITY dialer created successfully");
            println!("   - Target: www.apple.com");
            println!("   - Fingerprint: chrome");
            println!("   - ALPN: h2, http/1.1");
        }
        Err(e) => {
            println!("   ✗ Failed to create dialer: {}", e);
        }
    }

    println!();

    // Example 2: Create REALITY dialer from environment variables
    println!("2. Creating REALITY dialer from environment variables:");

    // Set environment variables
    std::env::set_var("SB_REALITY_TARGET", "www.cloudflare.com");
    std::env::set_var(
        "SB_REALITY_PUBLIC_KEY",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    );
    std::env::set_var("SB_REALITY_SHORT_ID", "abcd");
    std::env::set_var("SB_REALITY_FINGERPRINT", "firefox");

    match RealityDialer::from_env(TcpDialer::default()) {
        Ok(dialer) => {
            println!("   ✓ REALITY dialer created from environment");
            println!("   - Target: {}", dialer.connector.config().target);
            println!(
                "   - Server Name: {}",
                dialer.connector.config().server_name
            );
            println!(
                "   - Fingerprint: {}",
                dialer.connector.config().fingerprint
            );
        }
        Err(e) => {
            println!("   ✗ Failed to create dialer: {}", e);
        }
    }

    // Clean up environment variables
    std::env::remove_var("SB_REALITY_TARGET");
    std::env::remove_var("SB_REALITY_PUBLIC_KEY");
    std::env::remove_var("SB_REALITY_SHORT_ID");
    std::env::remove_var("SB_REALITY_FINGERPRINT");

    println!();

    // Example 3: Configuration validation
    println!("3. Configuration validation:");

    let invalid_config = RealityClientConfig {
        target: "".to_string(), // Invalid: empty target
        server_name: "www.example.com".to_string(),
        public_key: "invalid_key".to_string(), // Invalid: wrong format
        short_id: None,
        fingerprint: "chrome".to_string(),
        alpn: vec![],
    };

    match RealityDialer::new(TcpDialer::default(), invalid_config) {
        Ok(_) => {
            println!("   ✗ Unexpectedly succeeded with invalid config");
        }
        Err(e) => {
            println!("   ✓ Correctly rejected invalid config");
            println!("   - Error: {}", e);
        }
    }

    println!();
    println!("=== Example Complete ===");
    println!();
    println!("Note: This example demonstrates configuration only.");
    println!("Actual connections require a REALITY server to connect to.");
}

#[cfg(not(feature = "transport_reality"))]
fn main() {
    println!("This example requires the 'transport_reality' feature.");
    println!("Run with: cargo run --example reality_dialer --features transport_reality");
}
