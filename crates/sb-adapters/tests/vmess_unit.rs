//! VMess protocol unit tests

use serde::{Deserialize, Serialize};

// Simplified VMess config for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVmessConfig {
    pub server: String,
    pub uuid: String,
    pub security: String,
    pub alter_id: u16,
}

// VMess security methods
#[derive(Debug, Clone, PartialEq)]
pub enum VmessSecurity {
    Auto,
    Aes128Gcm,
    None,
}

impl VmessSecurity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "auto" => Self::Auto,
            "aes-128-gcm" => Self::Aes128Gcm,
            "none" => Self::None,
            _ => Self::Auto,
        }
    }
}

// VMess command types
#[derive(Debug, Clone, Copy)]
pub enum VmessCommand {
    Tcp = 1,
    Udp = 2,
}

// VMess address types
#[derive(Debug, Clone, Copy)]
pub enum VmessAddressType {
    Ipv4 = 1,
    Domain = 2,
    Ipv6 = 3,
}

#[test]
fn test_vmess_security_from_str() {
    assert_eq!(VmessSecurity::from_str("auto"), VmessSecurity::Auto);
    assert_eq!(
        VmessSecurity::from_str("aes-128-gcm"),
        VmessSecurity::Aes128Gcm
    );
    assert_eq!(VmessSecurity::from_str("none"), VmessSecurity::None);
    assert_eq!(VmessSecurity::from_str("unknown"), VmessSecurity::Auto);
}

#[test]
fn test_vmess_command_values() {
    assert_eq!(VmessCommand::Tcp as u8, 1);
    assert_eq!(VmessCommand::Udp as u8, 2);
}

#[test]
fn test_vmess_address_type_values() {
    assert_eq!(VmessAddressType::Ipv4 as u8, 1);
    assert_eq!(VmessAddressType::Domain as u8, 2);
    assert_eq!(VmessAddressType::Ipv6 as u8, 3);
}

#[test]
fn test_vmess_config_serialization() {
    let config = TestVmessConfig {
        server: "example.com:443".to_string(),
        uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        security: "aes-128-gcm".to_string(),
        alter_id: 0,
    };

    // Test serialization
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("example.com:443"));
    assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(json.contains("aes-128-gcm"));

    // Test deserialization
    let deserialized: TestVmessConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.server, config.server);
    assert_eq!(deserialized.uuid, config.uuid);
    assert_eq!(deserialized.security, config.security);
    assert_eq!(deserialized.alter_id, config.alter_id);
}

#[test]
fn test_uuid_validation() {
    use uuid::Uuid;

    // Valid UUID
    let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
    let parsed = Uuid::parse_str(valid_uuid);
    assert!(parsed.is_ok());

    // Invalid UUID
    let invalid_uuid = "invalid-uuid-format";
    let parsed = Uuid::parse_str(invalid_uuid);
    assert!(parsed.is_err());
}

#[test]
fn test_vmess_header_structure() {
    // Test that we can create the basic header structure
    let mut header = Vec::new();

    // Version (1 byte)
    header.push(1u8);

    // Data IV (16 bytes)
    let data_iv = [0u8; 16];
    header.extend_from_slice(&data_iv);

    // Data Key (16 bytes)
    let data_key = [0u8; 16];
    header.extend_from_slice(&data_key);

    // Response header (1 byte)
    header.push(42u8);

    // Option (1 byte)
    header.push(0x01);

    // Command (1 byte)
    header.push(VmessCommand::Tcp as u8);

    // Port (2 bytes, big endian)
    let port = 443u16;
    header.extend_from_slice(&port.to_be_bytes());

    // Address type
    header.push(VmessAddressType::Domain as u8);

    // Domain
    let domain = "example.com";
    header.push(domain.len() as u8);
    header.extend_from_slice(domain.as_bytes());

    // Verify header structure
    assert_eq!(header[0], 1); // Version
    assert_eq!(header[33], 42); // Response header
    assert_eq!(header[34], 0x01); // Option
    assert_eq!(header[35], VmessCommand::Tcp as u8); // Command
    assert_eq!(u16::from_be_bytes([header[36], header[37]]), 443); // Port
    assert_eq!(header[38], VmessAddressType::Domain as u8); // Address type
    assert_eq!(header[39], domain.len() as u8); // Domain length

    let domain_bytes = &header[40..40 + domain.len()];
    assert_eq!(domain_bytes, domain.as_bytes());
}

#[test]
fn test_aes_gcm_encryption() {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes128Gcm, Key, Nonce,
    };

    let key = Key::<Aes128Gcm>::from_slice(b"an example very very secret key."[..16].as_ref());
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(b"unique nonce");
    let plaintext = b"Hello, VMess!";

    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref());
    assert!(ciphertext.is_ok());

    let decrypted = cipher.decrypt(nonce, ciphertext.unwrap().as_ref());
    assert!(decrypted.is_ok());
    assert_eq!(decrypted.unwrap(), plaintext);
}

#[test]
fn test_hmac_sha256() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let key = b"secret key";
    let message = b"Hello, VMess!";

    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);
    let result = mac.finalize();

    // Verify the MAC
    let mut mac2 = HmacSha256::new_from_slice(key).unwrap();
    mac2.update(message);
    mac2.verify(&result.into_bytes()).unwrap();
}

#[test]
fn test_udp_packet_encoding_structure() {
    use std::net::{IpAddr, Ipv4Addr};

    // Test UDP packet encoding structure
    let mut packet = Vec::new();

    // IPv4 address
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    match ip {
        IpAddr::V4(ipv4) => {
            packet.push(VmessAddressType::Ipv4 as u8);
            packet.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            packet.push(VmessAddressType::Ipv6 as u8);
            packet.extend_from_slice(&ipv6.octets());
        }
    }

    // Port
    let port = 53u16;
    packet.extend_from_slice(&port.to_be_bytes());

    // Data length
    let data = b"test UDP data";
    packet.extend_from_slice(&(data.len() as u16).to_be_bytes());

    // Data
    packet.extend_from_slice(data);

    // Verify packet structure
    assert_eq!(packet[0], VmessAddressType::Ipv4 as u8);
    assert_eq!(&packet[1..5], &[8, 8, 8, 8]);
    assert_eq!(u16::from_be_bytes([packet[5], packet[6]]), 53);
    assert_eq!(
        u16::from_be_bytes([packet[7], packet[8]]),
        data.len() as u16
    );
    assert_eq!(&packet[9..], data);
}

#[test]
fn test_timestamp_generation() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Timestamp should be reasonable (after 2020 and before 2030)
    assert!(timestamp > 1577836800); // 2020-01-01
    assert!(timestamp < 1893456000); // 2030-01-01

    // Test timestamp to bytes conversion
    let timestamp_bytes = timestamp.to_be_bytes();
    assert_eq!(timestamp_bytes.len(), 8);

    let reconstructed = u64::from_be_bytes(timestamp_bytes);
    assert_eq!(reconstructed, timestamp);
}

#[test]
fn test_random_generation() {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    // Test random IV generation
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);

    // IV should not be all zeros (extremely unlikely)
    assert_ne!(iv, [0u8; 16]);

    // Test random key generation
    let mut key = [0u8; 16];
    rng.fill(&mut key);

    // Key should not be all zeros (extremely unlikely)
    assert_ne!(key, [0u8; 16]);

    // Test random padding
    let padding_len = rng.gen_range(0..16);
    assert!(padding_len < 16);
}
