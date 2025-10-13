//! ECH (Encrypted Client Hello) Example
//!
//! This example demonstrates how to use the ECH dialer to establish
//! a TLS connection with encrypted SNI.
//!
//! Run with:
//! ```bash
//! export SB_ECH_CONFIG="your_base64_encoded_ech_config"
//! cargo run --example ech_example --features transport_ech
//! ```

#[cfg(feature = "transport_ech")]
use sb_transport::{webpki_roots_config, Dialer, EchDialer, TcpDialer};

#[cfg(feature = "transport_ech")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("ECH (Encrypted Client Hello) Example");
    println!("=====================================\n");

    // Method 1: Create ECH dialer from environment variables
    println!("Method 1: Using environment variables");
    match std::env::var("SB_ECH_CONFIG") {
        Ok(config) => {
            println!("  ECH_CONFIG found: {}...", &config[..config.len().min(20)]);

            let tls_config = webpki_roots_config();
            match EchDialer::from_env(TcpDialer, tls_config) {
                Ok(dialer) => {
                    println!("  ✓ ECH dialer created successfully");

                    // Try to connect (this will fail without a real server)
                    println!("  Attempting connection to example.com:443...");
                    match dialer.connect("example.com", 443).await {
                        Ok(_stream) => {
                            println!("  ✓ Connection successful!");
                        }
                        Err(e) => {
                            println!("  ✗ Connection failed: {}", e);
                            println!("    (This is expected without a real ECH server)");
                        }
                    }
                }
                Err(e) => {
                    println!("  ✗ Failed to create ECH dialer: {}", e);
                }
            }
        }
        Err(_) => {
            println!("  ✗ SB_ECH_CONFIG not set");
            println!("    Set it with: export SB_ECH_CONFIG=\"your_base64_config\"");
        }
    }

    println!("\nMethod 2: Manual configuration");

    // Method 2: Create ECH dialer with manual configuration
    use sb_tls::EchClientConfig;

    // Example configuration (this is a placeholder, not a real config)
    let ech_config = EchClientConfig {
        enabled: true,
        config: Some("example_base64_config".to_string()),
        config_list: None,
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };

    let tls_config = webpki_roots_config();
    match EchDialer::new(TcpDialer, tls_config, ech_config) {
        Ok(_dialer) => {
            println!("  ✗ ECH dialer created (unexpected with invalid config)");
        }
        Err(e) => {
            println!("  ✓ ECH dialer creation failed as expected: {}", e);
            println!("    (Invalid config is expected to fail)");
        }
    }

    println!("\nMethod 3: Disabled ECH");

    // Method 3: Create ECH dialer with ECH disabled
    let ech_config = EchClientConfig {
        enabled: false,
        config: None,
        config_list: None,
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };

    let tls_config = webpki_roots_config();
    match EchDialer::new(TcpDialer, tls_config, ech_config) {
        Ok(_dialer) => {
            println!("  ✓ ECH dialer created with ECH disabled");
        }
        Err(e) => {
            println!("  ✗ Failed to create ECH dialer: {}", e);
        }
    }

    println!("\n=====================================");
    println!("Example complete!");

    Ok(())
}

#[cfg(not(feature = "transport_ech"))]
fn main() {
    eprintln!("This example requires the 'transport_ech' feature.");
    eprintln!("Run with: cargo run --example ech_example --features transport_ech");
    std::process::exit(1);
}
