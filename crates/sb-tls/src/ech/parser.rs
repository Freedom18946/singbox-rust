//! ECHConfigList parser
//!
//! This module implements parsing of ECHConfigList structures according to
//! the TLS Encrypted Client Hello specification.
//!
//! ## Wire Format
//!
//! ECHConfigList is a variable-length structure:
//! ```text
//! struct {
//!     ECHConfig configs<1..2^16-1>;
//! } ECHConfigList;
//!
//! struct {
//!     uint16 version;
//!     uint16 length;
//!     select (ECHConfig.version) {
//!         case 0xfe0d: ECHConfigContents contents;
//!     }
//! } ECHConfig;
//!
//! struct {
//!     opaque public_key<1..2^16-1>;
//!     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
//!     uint8 maximum_name_length;
//!     opaque public_name<1..255>;
//!     Extension extensions<0..2^16-1>;
//! } ECHConfigContents;
//! ```

use super::{EchError, EchResult, EchVersion, HpkeAead, HpkeKdf, HpkeKem};

/// Parsed ECH configuration
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// ECH version
    pub version: EchVersion,
    /// Server public key (X25519)
    pub public_key: Vec<u8>,
    /// Supported cipher suites
    pub cipher_suites: Vec<HpkeCipherSuite>,
    /// Maximum name length
    pub maximum_name_length: u8,
    /// Public name (SNI to use in outer ClientHello)
    pub public_name: String,
    /// Extensions (currently unused)
    pub extensions: Vec<u8>,
}

/// HPKE cipher suite
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeCipherSuite {
    /// Key Encapsulation Mechanism
    pub kem: HpkeKem,
    /// Key Derivation Function
    pub kdf: HpkeKdf,
    /// Authenticated Encryption with Associated Data
    pub aead: HpkeAead,
}

impl HpkeCipherSuite {
    /// Create a new cipher suite
    pub fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// Default cipher suite: X25519 + HKDF-SHA256 + AES-128-GCM
    pub fn default_suite() -> Self {
        Self {
            kem: HpkeKem::X25519HkdfSha256,
            kdf: HpkeKdf::HkdfSha256,
            aead: HpkeAead::Aes128Gcm,
        }
    }
}

/// Parsed ECHConfigList
#[derive(Debug, Clone)]
pub struct EchConfigList {
    /// List of ECH configurations
    pub configs: Vec<EchConfig>,
}

impl EchConfigList {
    /// Get the first config (most preferred)
    pub fn first(&self) -> Option<&EchConfig> {
        self.configs.first()
    }

    /// Check if list is empty
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// Get number of configs
    pub fn len(&self) -> usize {
        self.configs.len()
    }
}

/// Parse ECHConfigList from bytes
pub fn parse_ech_config_list(data: &[u8]) -> EchResult<EchConfigList> {
    let mut parser = Parser::new(data);

    // Read list length (2 bytes)
    let list_length = parser.read_u16()? as usize;

    if list_length != data.len() - 2 {
        return Err(EchError::ParseFailed(format!(
            "Invalid list length: expected {}, got {}",
            data.len() - 2,
            list_length
        )));
    }

    let mut configs = Vec::new();

    // Parse each ECHConfig
    while parser.remaining() > 0 {
        let config = parse_ech_config(&mut parser)?;
        configs.push(config);
    }

    if configs.is_empty() {
        return Err(EchError::ParseFailed(
            "ECHConfigList must contain at least one config".to_string(),
        ));
    }

    Ok(EchConfigList { configs })
}

/// Parse a single ECHConfig
fn parse_ech_config(parser: &mut Parser) -> EchResult<EchConfig> {
    // Read version (2 bytes)
    let version_u16 = parser.read_u16()?;
    let version = EchVersion::from_u16(version_u16).ok_or_else(|| {
        EchError::ParseFailed(format!("Unsupported ECH version: 0x{:04x}", version_u16))
    })?;

    // Read length (2 bytes)
    let length = parser.read_u16()? as usize;
    let config_data = parser.read_bytes(length)?;

    // Parse config contents
    let mut config_parser = Parser::new(config_data);
    parse_ech_config_contents(&mut config_parser, version)
}

/// Parse ECHConfigContents
fn parse_ech_config_contents(parser: &mut Parser, version: EchVersion) -> EchResult<EchConfig> {
    // Read public key (variable length with 2-byte length prefix)
    let public_key = parser.read_length_prefixed_bytes()?;

    if public_key.len() != 32 {
        return Err(EchError::ParseFailed(format!(
            "Invalid public key length: expected 32, got {}",
            public_key.len()
        )));
    }

    // Read cipher suites (variable length with 2-byte length prefix)
    let cipher_suites_data = parser.read_length_prefixed_bytes()?;
    let cipher_suites = parse_cipher_suites(cipher_suites_data)?;

    // Read maximum name length (1 byte)
    let maximum_name_length = parser.read_u8()?;

    // Read public name (variable length with 1-byte length prefix)
    let public_name_bytes = parser.read_u8_length_prefixed_bytes()?;
    let public_name = String::from_utf8(public_name_bytes.to_vec())
        .map_err(|e| EchError::ParseFailed(format!("Invalid public name UTF-8: {}", e)))?;

    // Read extensions (variable length with 2-byte length prefix)
    let extensions = parser.read_length_prefixed_bytes()?;

    Ok(EchConfig {
        version,
        public_key: public_key.to_vec(),
        cipher_suites,
        maximum_name_length,
        public_name,
        extensions: extensions.to_vec(),
    })
}

/// Parse cipher suites
fn parse_cipher_suites(data: &[u8]) -> EchResult<Vec<HpkeCipherSuite>> {
    if data.len() % 6 != 0 {
        return Err(EchError::ParseFailed(format!(
            "Invalid cipher suites length: {} (must be multiple of 6)",
            data.len()
        )));
    }

    let mut parser = Parser::new(data);
    let mut suites = Vec::new();

    while parser.remaining() > 0 {
        let kem_u16 = parser.read_u16()?;
        let kdf_u16 = parser.read_u16()?;
        let aead_u16 = parser.read_u16()?;

        let kem = HpkeKem::from_u16(kem_u16)
            .ok_or_else(|| EchError::ParseFailed(format!("Unsupported KEM: 0x{:04x}", kem_u16)))?;

        let kdf = HpkeKdf::from_u16(kdf_u16)
            .ok_or_else(|| EchError::ParseFailed(format!("Unsupported KDF: 0x{:04x}", kdf_u16)))?;

        let aead = HpkeAead::from_u16(aead_u16).ok_or_else(|| {
            EchError::ParseFailed(format!("Unsupported AEAD: 0x{:04x}", aead_u16))
        })?;

        suites.push(HpkeCipherSuite { kem, kdf, aead });
    }

    if suites.is_empty() {
        return Err(EchError::ParseFailed(
            "At least one cipher suite required".to_string(),
        ));
    }

    Ok(suites)
}

/// Simple byte parser helper
struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> EchResult<u8> {
        if self.pos >= self.data.len() {
            return Err(EchError::ParseFailed("Unexpected end of data".to_string()));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> EchResult<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(EchError::ParseFailed("Unexpected end of data".to_string()));
        }
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn read_bytes(&mut self, len: usize) -> EchResult<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(EchError::ParseFailed("Unexpected end of data".to_string()));
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn read_length_prefixed_bytes(&mut self) -> EchResult<&'a [u8]> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    fn read_u8_length_prefixed_bytes(&mut self) -> EchResult<&'a [u8]> {
        let len = self.read_u8()? as usize;
        self.read_bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_read_u8() {
        let data = vec![0x01, 0x02, 0x03];
        let mut parser = Parser::new(&data);

        assert_eq!(parser.read_u8().unwrap(), 0x01);
        assert_eq!(parser.read_u8().unwrap(), 0x02);
        assert_eq!(parser.read_u8().unwrap(), 0x03);
        assert!(parser.read_u8().is_err());
    }

    #[test]
    fn test_parser_read_u16() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut parser = Parser::new(&data);

        assert_eq!(parser.read_u16().unwrap(), 0x0102);
        assert_eq!(parser.read_u16().unwrap(), 0x0304);
        assert!(parser.read_u16().is_err());
    }

    #[test]
    fn test_parser_read_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut parser = Parser::new(&data);

        let bytes = parser.read_bytes(2).unwrap();
        assert_eq!(bytes, &[0x01, 0x02]);

        let bytes = parser.read_bytes(2).unwrap();
        assert_eq!(bytes, &[0x03, 0x04]);

        assert!(parser.read_bytes(1).is_err());
    }

    #[test]
    fn test_parser_read_length_prefixed_bytes() {
        let data = vec![0x00, 0x03, 0x01, 0x02, 0x03];
        let mut parser = Parser::new(&data);

        let bytes = parser.read_length_prefixed_bytes().unwrap();
        assert_eq!(bytes, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_parser_read_u8_length_prefixed_bytes() {
        let data = vec![0x03, 0x01, 0x02, 0x03];
        let mut parser = Parser::new(&data);

        let bytes = parser.read_u8_length_prefixed_bytes().unwrap();
        assert_eq!(bytes, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_parser_remaining() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut parser = Parser::new(&data);

        assert_eq!(parser.remaining(), 4);
        parser.read_u8().unwrap();
        assert_eq!(parser.remaining(), 3);
        parser.read_u16().unwrap();
        assert_eq!(parser.remaining(), 1);
    }

    #[test]
    fn test_parse_cipher_suites() {
        // KEM=0x0020, KDF=0x0001, AEAD=0x0001
        let data = vec![0x00, 0x20, 0x00, 0x01, 0x00, 0x01];
        let suites = parse_cipher_suites(&data).unwrap();

        assert_eq!(suites.len(), 1);
        assert_eq!(suites[0].kem, HpkeKem::X25519HkdfSha256);
        assert_eq!(suites[0].kdf, HpkeKdf::HkdfSha256);
        assert_eq!(suites[0].aead, HpkeAead::Aes128Gcm);
    }

    #[test]
    fn test_parse_cipher_suites_multiple() {
        // Two cipher suites
        let data = vec![
            0x00, 0x20, 0x00, 0x01, 0x00, 0x01, // Suite 1
            0x00, 0x20, 0x00, 0x01, 0x00, 0x02, // Suite 2
        ];
        let suites = parse_cipher_suites(&data).unwrap();

        assert_eq!(suites.len(), 2);
        assert_eq!(suites[0].aead, HpkeAead::Aes128Gcm);
        assert_eq!(suites[1].aead, HpkeAead::Aes256Gcm);
    }

    #[test]
    fn test_parse_cipher_suites_invalid_length() {
        let data = vec![0x00, 0x20, 0x00]; // Not multiple of 6
        let result = parse_cipher_suites(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("must be multiple of 6"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_cipher_suites_empty() {
        let data = vec![];
        let result = parse_cipher_suites(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("At least one cipher suite required"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_cipher_suites_unsupported_kem() {
        // Invalid KEM=0xFFFF
        let data = vec![0xFF, 0xFF, 0x00, 0x01, 0x00, 0x01];
        let result = parse_cipher_suites(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Unsupported KEM"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_cipher_suites_unsupported_kdf() {
        // Invalid KDF=0xFFFF
        let data = vec![0x00, 0x20, 0xFF, 0xFF, 0x00, 0x01];
        let result = parse_cipher_suites(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Unsupported KDF"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_cipher_suites_unsupported_aead() {
        // Invalid AEAD=0xFFFF
        let data = vec![0x00, 0x20, 0x00, 0x01, 0xFF, 0xFF];
        let result = parse_cipher_suites(&data);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Unsupported AEAD"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_hpke_cipher_suite_default() {
        let suite = HpkeCipherSuite::default_suite();
        assert_eq!(suite.kem, HpkeKem::X25519HkdfSha256);
        assert_eq!(suite.kdf, HpkeKdf::HkdfSha256);
        assert_eq!(suite.aead, HpkeAead::Aes128Gcm);
    }

    #[test]
    fn test_hpke_cipher_suite_new() {
        let suite = HpkeCipherSuite::new(
            HpkeKem::X25519HkdfSha256,
            HpkeKdf::HkdfSha256,
            HpkeAead::ChaCha20Poly1305,
        );
        assert_eq!(suite.kem, HpkeKem::X25519HkdfSha256);
        assert_eq!(suite.kdf, HpkeKdf::HkdfSha256);
        assert_eq!(suite.aead, HpkeAead::ChaCha20Poly1305);
    }

    #[test]
    fn test_parse_ech_config_list_valid() {
        let config_list = create_test_ech_config_list();
        let result = parse_ech_config_list(&config_list);

        assert!(result.is_ok());
        let list = result.unwrap();
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());

        let config = list.first().unwrap();
        assert_eq!(config.version, EchVersion::Draft13);
        assert_eq!(config.public_key.len(), 32);
        assert_eq!(config.public_name, "public.example.com");
        assert_eq!(config.maximum_name_length, 64);
        assert!(!config.cipher_suites.is_empty());
    }

    #[test]
    fn test_parse_ech_config_list_empty() {
        // Empty list (just length field)
        let data = vec![0x00, 0x00];
        let result = parse_ech_config_list(&data);

        assert!(result.is_err());
        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("must contain at least one config"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_ech_config_list_invalid_length() {
        // Invalid list length
        let data = vec![0x00, 0xFF, 0x01, 0x02];
        let result = parse_ech_config_list(&data);

        assert!(result.is_err());
        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Invalid list length"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_ech_config_list_truncated() {
        // Truncated data
        let data = vec![0x00, 0x10, 0xfe, 0x0d];
        let result = parse_ech_config_list(&data);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ech_config_unsupported_version() {
        let mut config_list = Vec::new();

        // List length
        config_list.extend_from_slice(&[0x00, 0x04]);

        // Unsupported version (0x0000)
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Config length
        config_list.extend_from_slice(&[0x00, 0x00]);

        let result = parse_ech_config_list(&config_list);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Unsupported ECH version"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_ech_config_invalid_public_key_length() {
        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Invalid public key length (16 bytes instead of 32)
        config_list.extend_from_slice(&[0x00, 0x10]);
        config_list.extend_from_slice(&[0x00; 16]);

        // Fill in lengths
        let config_len = config_list.len() - config_start - 2;
        config_list[config_start..config_start + 2]
            .copy_from_slice(&(config_len as u16).to_be_bytes());

        let list_len = config_list.len() - list_start - 2;
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        let result = parse_ech_config_list(&config_list);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Invalid public key length"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_parse_ech_config_invalid_public_name_utf8() {
        let mut config_list = Vec::new();

        // List length (will be filled later)
        let list_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // ECH version
        config_list.extend_from_slice(&[0xfe, 0x0d]);

        // Config length (will be filled later)
        let config_start = config_list.len();
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Public key
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(&[0x00; 32]);

        // Cipher suites
        config_list.extend_from_slice(&[0x00, 0x06]);
        config_list.extend_from_slice(&[0x00, 0x20, 0x00, 0x01, 0x00, 0x01]);

        // Maximum name length
        config_list.push(64);

        // Invalid UTF-8 in public name
        config_list.push(4);
        config_list.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);

        // Extensions
        config_list.extend_from_slice(&[0x00, 0x00]);

        // Fill in lengths
        let config_len = config_list.len() - config_start - 2;
        config_list[config_start..config_start + 2]
            .copy_from_slice(&(config_len as u16).to_be_bytes());

        let list_len = config_list.len() - list_start - 2;
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        let result = parse_ech_config_list(&config_list);
        assert!(result.is_err());

        match result.unwrap_err() {
            EchError::ParseFailed(msg) => {
                assert!(msg.contains("Invalid public name UTF-8"));
            }
            _ => panic!("Expected ParseFailed error"),
        }
    }

    #[test]
    fn test_ech_config_list_methods() {
        let config_list = create_test_ech_config_list();
        let list = parse_ech_config_list(&config_list).unwrap();

        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
        assert!(list.first().is_some());
    }

    // Helper function to create a test ECH config list
    fn create_test_ech_config_list() -> Vec<u8> {
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

        // Public key length + public key (32 bytes for X25519)
        config_list.extend_from_slice(&[0x00, 0x20]);
        config_list.extend_from_slice(public_key.as_bytes());

        // Cipher suites length + cipher suite
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
        config_list[list_start..list_start + 2].copy_from_slice(&(list_len as u16).to_be_bytes());

        config_list
    }
}
