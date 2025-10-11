//! Example demonstrating the TlsTransport wrapper
//!
//! This example shows how to use the unified TlsTransport interface
//! to wrap streams with different TLS variants (Standard, REALITY, ECH).

use sb_transport::{TlsTransport, TlsConfig, StandardTlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("TlsTransport Example");
    println!("===================\n");

    // Example 1: Standard TLS configuration
    println!("1. Standard TLS Configuration:");
    let standard_config = TlsConfig::Standard(StandardTlsConfig {
        server_name: Some("example.com".to_string()),
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        insecure: false,
        cert_path: None,
        key_path: None,
    });
    
    let transport = TlsTransport::new(standard_config);
    println!("   ✓ Created Standard TLS transport");
    println!("   - Server name: example.com");
    println!("   - ALPN: h2, http/1.1\n");

    // Example 2: REALITY configuration (if feature enabled)
    #[cfg(feature = "transport_reality")]
    {
        use sb_transport::RealityTlsConfig;
        
        println!("2. REALITY TLS Configuration:");
        let reality_config = TlsConfig::Reality(RealityTlsConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        });
        
        let _transport = TlsTransport::new(reality_config);
        println!("   ✓ Created REALITY TLS transport");
        println!("   - Target: www.apple.com");
        println!("   - Fingerprint: chrome\n");
    }

    // Example 3: ECH configuration (if feature enabled)
    #[cfg(feature = "transport_ech")]
    {
        use sb_transport::EchTlsConfig;
        
        println!("3. ECH TLS Configuration:");
        let ech_config = TlsConfig::Ech(EchTlsConfig {
            enabled: true,
            config: Some("test_config".to_string()),
            config_list: None,
            pq_signature_schemes_enabled: false,
            dynamic_record_sizing_disabled: None,
            server_name: Some("public.example.com".to_string()),
            alpn: vec![],
        });
        
        let _transport = TlsTransport::new(ech_config);
        println!("   ✓ Created ECH TLS transport");
        println!("   - Enabled: true");
        println!("   - Public name: public.example.com\n");
    }

    // Example 4: Serialization/Deserialization
    println!("4. Configuration Serialization:");
    let config = TlsConfig::Standard(StandardTlsConfig {
        server_name: Some("example.com".to_string()),
        alpn: vec!["h2".to_string()],
        insecure: false,
        cert_path: None,
        key_path: None,
    });
    
    let json = serde_json::to_string_pretty(&config)?;
    println!("   JSON representation:");
    println!("{}\n", json);
    
    let deserialized: TlsConfig = serde_json::from_str(&json)?;
    println!("   ✓ Successfully deserialized configuration\n");

    println!("Example completed successfully!");
    
    Ok(())
}
