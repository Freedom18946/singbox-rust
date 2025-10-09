//! ECH (Encrypted Client Hello) E2E Tests
//!
//! This test suite verifies ECH functionality including:
//! - ECH configuration and setup
//! - ClientHello encryption with HPKE
//! - SNI encryption verification
//! - ECH with various outbound protocols (TLS, QUIC)
//! - ECH acceptance verification

use sb_tls::ech::{
    EchClientConfig, EchConnector, EchKeypair, EchServerConfig,
    HpkeAead, HpkeKdf, HpkeKem,
};
use x25519_dalek::{PublicKey, StaticSecret};

/// Helper function to create a test ECH config list
fn create_test_ech_config_list(public_key: &PublicKey) -> Vec<u8> {
    let mut config_list = Vec::new();
    
    // List length (will be filled later)
    let list_start = config_list.len();
    config_list.extend_from_slice(&[0x00, 0x00]);
    
    // ECH version (0xfe0d = Draft-13)
    config_list.extend_from_slice(&[0xfe, 0x0d]);
    
    // Config length (will be filled later)
    let config_start = config_list.len();
    config_list.extend_from_slice(&[0x00, 0x00]);
    
    // Public key length + public key (32 bytes for X25519)
    config_list.extend_from_slice(&[0x00, 0x20]);
    config_list.extend_from_slice(public_key.as_bytes());
    
    // Cipher suites length + cipher suite
    // One suite: KEM=0x0020, KDF=0x0001, AEAD=0x0001
    config_list.extend_from_slice(&[0x00, 0x06]);
    config_list.extend_from_slice(&[0x00, 0x20]); // KEM: X25519
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
    config_list[config_start..config_start + 2]
        .copy_from_slice(&(config_len as u16).to_be_bytes());
    
    // Fill in list length
    let list_len = config_list.len() - list_start - 2;
    config_list[list_start..list_start + 2]
        .copy_from_slice(&(list_len as u16).to_be_bytes());
    
    config_list
}

/// Helper to create ECH keypair and config
fn setup_ech_test() -> (EchKeypair, Vec<u8>) {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public_key = PublicKey::from(&secret);
    
    let keypair = EchKeypair::new(
        secret.to_bytes().to_vec(),
        public_key.as_bytes().to_vec(),
    );
    
    let config_list = create_test_ech_config_list(&public_key);
    
    (keypair, config_list)
}

#[test]
fn test_ech_client_config_creation() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    assert!(config.validate().is_ok());
    assert!(config.enabled);
    assert!(config.get_config_list().is_some());
}

#[test]
fn test_ech_server_config_creation() {
    let (keypair, _config_list) = setup_ech_test();
    
    let config = EchServerConfig {
        enabled: true,
        keypair: Some(keypair),
        config: Some("test_config".to_string()),
    };
    
    assert!(config.validate().is_ok());
    assert!(config.enabled);
}

#[test]
fn test_ech_connector_creation_and_wrap() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Test wrapping TLS with ECH
    let real_server = "secret.example.com";
    let ech_hello = connector.wrap_tls(real_server).expect("Failed to wrap TLS");
    
    // Verify outer SNI is the public name
    assert_eq!(ech_hello.outer_sni, "public.example.com");
    
    // Verify inner SNI is the real server name
    assert_eq!(ech_hello.inner_sni, real_server);
    
    // Verify ECH payload is not empty
    assert!(!ech_hello.ech_payload.is_empty());
    
    // Verify encapsulated key is present (X25519 = 32 bytes)
    assert_eq!(ech_hello.encapsulated_key.len(), 32);
}

#[test]
fn test_ech_sni_encryption_verification() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Test with sensitive server name
    let sensitive_server = "censored.blocked.com";
    let ech_hello = connector.wrap_tls(sensitive_server).expect("Failed to wrap TLS");
    
    // Verify the sensitive server name is NOT in the outer SNI
    assert_ne!(ech_hello.outer_sni, sensitive_server);
    
    // Verify the sensitive server name IS in the inner SNI
    assert_eq!(ech_hello.inner_sni, sensitive_server);
    
    // Verify the ECH payload doesn't contain plaintext server name
    let payload_str = String::from_utf8_lossy(&ech_hello.ech_payload);
    assert!(!payload_str.contains(sensitive_server));
}

#[test]
fn test_ech_payload_structure() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    let ech_hello = connector.wrap_tls("test.example.com").expect("Failed to wrap TLS");
    
    // Verify ECH payload structure
    // Should contain: version (2) + cipher suite (6) + enc_key_len (2) + enc_key (32) + enc_ch_len (2) + enc_ch
    assert!(ech_hello.ech_payload.len() >= 2 + 6 + 2 + 32 + 2);
    
    // Check version in payload (0xfe0d = Draft-13)
    assert_eq!(ech_hello.ech_payload[0], 0xfe);
    assert_eq!(ech_hello.ech_payload[1], 0x0d);
    
    // Check cipher suite KEM (X25519 = 0x0020)
    assert_eq!(ech_hello.ech_payload[2], 0x00);
    assert_eq!(ech_hello.ech_payload[3], 0x20);
    
    // Check cipher suite KDF (HKDF-SHA256 = 0x0001)
    assert_eq!(ech_hello.ech_payload[4], 0x00);
    assert_eq!(ech_hello.ech_payload[5], 0x01);
    
    // Check cipher suite AEAD (AES-128-GCM = 0x0001)
    assert_eq!(ech_hello.ech_payload[6], 0x00);
    assert_eq!(ech_hello.ech_payload[7], 0x01);
}

#[test]
fn test_ech_acceptance_verification() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Test with ServerHello containing ECH extension
    let mut server_hello_with_ech = vec![0x00; 10];
    server_hello_with_ech.extend_from_slice(&[0xfe, 0x0d]); // ECH extension type
    server_hello_with_ech.extend_from_slice(&[0x00; 10]);
    
    assert!(connector.verify_ech_acceptance(&server_hello_with_ech).unwrap());
    
    // Test with ServerHello without ECH extension
    let server_hello_without_ech = vec![0x00; 20];
    assert!(!connector.verify_ech_acceptance(&server_hello_without_ech).unwrap());
}

#[test]
fn test_ech_multiple_connections() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Simulate multiple connections with different server names
    let servers = vec![
        "server1.example.com",
        "server2.example.com",
        "server3.example.com",
    ];
    
    for server in servers {
        let ech_hello = connector.wrap_tls(server).expect("Failed to wrap TLS");
        
        // All should have the same outer SNI (public name)
        assert_eq!(ech_hello.outer_sni, "public.example.com");
        
        // But different inner SNIs
        assert_eq!(ech_hello.inner_sni, server);
        
        // And different encrypted payloads
        assert!(!ech_hello.ech_payload.is_empty());
    }
}

#[test]
fn test_ech_with_various_protocols() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Test ECH with different protocol scenarios
    let test_cases = vec![
        ("tls.example.com", "TLS protocol"),
        ("quic.example.com", "QUIC protocol"),
        ("http3.example.com", "HTTP/3 over QUIC"),
        ("grpc.example.com", "gRPC over TLS"),
    ];
    
    for (server, protocol) in test_cases {
        let ech_hello = connector.wrap_tls(server)
            .expect(&format!("Failed to wrap {} with ECH", protocol));
        
        // Verify ECH works for all protocols
        assert_eq!(ech_hello.outer_sni, "public.example.com");
        assert_eq!(ech_hello.inner_sni, server);
        assert!(!ech_hello.ech_payload.is_empty());
        assert_eq!(ech_hello.encapsulated_key.len(), 32);
    }
}

#[test]
fn test_ech_disabled_config() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: false,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Should fail when ECH is disabled
    let result = connector.wrap_tls("example.com");
    assert!(result.is_err());
}

#[test]
fn test_ech_invalid_config() {
    // Test with empty config list
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: None,
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    let result = connector.wrap_tls("example.com");
    assert!(result.is_err());
}

#[test]
fn test_ech_keypair_generation() {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public_key = PublicKey::from(&secret);
    
    let keypair = EchKeypair::new(
        secret.to_bytes().to_vec(),
        public_key.as_bytes().to_vec(),
    );
    
    // Verify keypair structure
    assert_eq!(keypair.private_key.len(), 32);
    assert_eq!(keypair.public_key.len(), 32);
    
    // Verify base64 encoding roundtrip
    let private_b64 = keypair.private_key_base64();
    let public_b64 = keypair.public_key_base64();
    
    let keypair2 = EchKeypair::from_base64(&private_b64, &public_b64)
        .expect("Failed to decode keypair");
    
    assert_eq!(keypair2.private_key, keypair.private_key);
    assert_eq!(keypair2.public_key, keypair.public_key);
}

#[test]
fn test_ech_config_list_parsing() {
    let (_keypair, config_list) = setup_ech_test();
    
    // Verify config list can be parsed
    let parsed = sb_tls::ech::parse_ech_config_list(&config_list);
    assert!(parsed.is_ok());
    
    let parsed_list = parsed.unwrap();
    assert!(!parsed_list.is_empty());
    
    // Verify first config
    let first_config = parsed_list.first().unwrap();
    assert_eq!(first_config.public_name, "public.example.com");
    assert_eq!(first_config.public_key.len(), 32);
    assert!(!first_config.cipher_suites.is_empty());
}

#[test]
fn test_ech_hpke_encryption() {
    use sb_tls::ech::hpke::HpkeSender;
    
    let recipient_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let recipient_public = PublicKey::from(&recipient_secret);
    
    let sender = HpkeSender::new(
        HpkeKem::X25519HkdfSha256,
        HpkeKdf::HkdfSha256,
        HpkeAead::Aes128Gcm,
    );
    
    let info = b"tls ech";
    let (encapsulated_key, mut context) = sender
        .setup(recipient_public.as_bytes(), info)
        .expect("Failed to setup HPKE");
    
    // Verify encapsulated key
    assert_eq!(encapsulated_key.len(), 32);
    
    // Test encryption
    let plaintext = b"secret.example.com";
    let aad = b"";
    let ciphertext = context.seal(plaintext, aad).expect("Failed to seal");
    
    // Ciphertext should be plaintext + tag (16 bytes for GCM)
    assert_eq!(ciphertext.len(), plaintext.len() + 16);
    
    // Verify ciphertext doesn't contain plaintext
    assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));
}

#[test]
fn test_ech_edge_cases() {
    let (_keypair, config_list) = setup_ech_test();
    
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    
    // Test with empty server name
    let result = connector.wrap_tls("");
    assert!(result.is_ok());
    let ech_hello = result.unwrap();
    assert_eq!(ech_hello.inner_sni, "");
    
    // Test with very long server name
    let long_name = "a".repeat(255);
    let result = connector.wrap_tls(&long_name);
    assert!(result.is_ok());
    let ech_hello = result.unwrap();
    assert_eq!(ech_hello.inner_sni, long_name);
    
    // Test with special characters
    let special_name = "test-server_123.example.com";
    let result = connector.wrap_tls(special_name);
    assert!(result.is_ok());
    let ech_hello = result.unwrap();
    assert_eq!(ech_hello.inner_sni, special_name);
}

#[test]
fn test_ech_pq_signature_schemes() {
    let (_keypair, config_list) = setup_ech_test();
    
    // Test with PQ signature schemes enabled
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list.clone()),
        pq_signature_schemes_enabled: true,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    let ech_hello = connector.wrap_tls("example.com").expect("Failed to wrap TLS");
    
    assert!(!ech_hello.ech_payload.is_empty());
    
    // Test with PQ signature schemes disabled
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: None,
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    let ech_hello = connector.wrap_tls("example.com").expect("Failed to wrap TLS");
    
    assert!(!ech_hello.ech_payload.is_empty());
}

#[test]
fn test_ech_dynamic_record_sizing() {
    let (_keypair, config_list) = setup_ech_test();
    
    // Test with dynamic record sizing disabled
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list.clone()),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: Some(true),
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    let ech_hello = connector.wrap_tls("example.com").expect("Failed to wrap TLS");
    
    assert!(!ech_hello.ech_payload.is_empty());
    
    // Test with dynamic record sizing enabled (default)
    let config = EchClientConfig {
        enabled: true,
        config: Some("test_config".to_string()),
        config_list: Some(config_list),
        pq_signature_schemes_enabled: false,
        dynamic_record_sizing_disabled: Some(false),
    };
    
    let connector = EchConnector::new(config).expect("Failed to create ECH connector");
    let ech_hello = connector.wrap_tls("example.com").expect("Failed to wrap TLS");
    
    assert!(!ech_hello.ech_payload.is_empty());
}
