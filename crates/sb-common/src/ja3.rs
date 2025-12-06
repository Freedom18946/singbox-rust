//! JA3 fingerprinting for TLS client identification.
//! JA3 指纹用于 TLS 客户端识别。
//!
//! JA3 is a method for creating SSL/TLS client fingerprints that are
//! easy to produce on any platform and can be easily shared for threat intelligence.
//!
//! The JA3 fingerprint is created from:
//! - SSLVersion
//! - Cipher Suites
//! - Extensions
//! - Elliptic Curves (Supported Groups)
//! - Elliptic Curve Point Formats
//!
//! Reference: https://github.com/salesforce/ja3
//!
//! # Example
//!
//! ```ignore
//! use sb_common::ja3::Ja3Fingerprint;
//!
//! let fingerprint = Ja3Fingerprint::from_client_hello(&client_hello_data);
//! if let Some(fp) = fingerprint {
//!     println!("JA3 hash: {}", fp.hash());
//!     println!("JA3 string: {}", fp.ja3_string());
//! }
//! ```

use std::fmt;

/// TLS record header size.
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// TLS handshake header size.
const TLS_HANDSHAKE_HEADER_SIZE: usize = 4;

/// Extension type: Supported Groups (formerly Elliptic Curves).
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;

/// Extension type: EC Point Formats.
const EXT_EC_POINT_FORMATS: u16 = 0x000b;

/// Extensions to exclude from JA3 (GREASE values).
/// GREASE values are designed to prevent extension intolerance.
const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Check if a value is a GREASE value.
fn is_grease(value: u16) -> bool {
    GREASE_VALUES.contains(&value)
}

/// JA3 fingerprint data extracted from a TLS ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja3Fingerprint {
    /// TLS version from ClientHello.
    pub version: u16,
    /// Cipher suites (excluding GREASE).
    pub cipher_suites: Vec<u16>,
    /// Extensions (excluding GREASE).
    pub extensions: Vec<u16>,
    /// Supported groups / elliptic curves (excluding GREASE).
    pub supported_groups: Vec<u16>,
    /// EC point formats.
    pub ec_point_formats: Vec<u8>,
}

impl Ja3Fingerprint {
    /// Create a JA3 fingerprint from TLS ClientHello data.
    /// Returns None if the data is not a valid ClientHello.
    pub fn from_client_hello(data: &[u8]) -> Option<Self> {
        if data.len() < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE + 2 {
            return None;
        }

        // Verify TLS handshake record
        if data[0] != 0x16 {
            return None;
        }

        // Skip TLS record header (5 bytes)
        let mut pos = TLS_RECORD_HEADER_SIZE;

        // Verify ClientHello handshake type
        if data[pos] != 0x01 {
            return None;
        }

        // Skip handshake header (4 bytes)
        pos += TLS_HANDSHAKE_HEADER_SIZE;

        // Client version (2 bytes)
        if pos + 2 > data.len() {
            return None;
        }
        let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Skip client random (32 bytes)
        pos += 32;
        if pos >= data.len() {
            return None;
        }

        // Skip session ID
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > data.len() {
            return None;
        }

        // Parse cipher suites
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + cipher_suites_len > data.len() {
            return None;
        }

        let mut cipher_suites = Vec::new();
        let cipher_end = pos + cipher_suites_len;
        while pos + 2 <= cipher_end {
            let cipher = u16::from_be_bytes([data[pos], data[pos + 1]]);
            if !is_grease(cipher) {
                cipher_suites.push(cipher);
            }
            pos += 2;
        }
        pos = cipher_end;

        // Skip compression methods
        if pos >= data.len() {
            return None;
        }
        let compression_len = data[pos] as usize;
        pos += 1 + compression_len;
        if pos + 2 > data.len() {
            return None;
        }

        // Parse extensions
        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let extensions_end = pos + extensions_len;

        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut ec_point_formats = Vec::new();

        while pos + 4 <= extensions_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if !is_grease(ext_type) {
                extensions.push(ext_type);

                // Parse Supported Groups extension
                if ext_type == EXT_SUPPORTED_GROUPS && ext_len >= 2 && pos + ext_len <= data.len() {
                    let groups_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    let mut group_pos = pos + 2;
                    let groups_end = (pos + 2 + groups_len).min(pos + ext_len);
                    while group_pos + 2 <= groups_end {
                        let group = u16::from_be_bytes([data[group_pos], data[group_pos + 1]]);
                        if !is_grease(group) {
                            supported_groups.push(group);
                        }
                        group_pos += 2;
                    }
                }

                // Parse EC Point Formats extension
                if ext_type == EXT_EC_POINT_FORMATS && ext_len >= 1 && pos + ext_len <= data.len() {
                    let formats_len = data[pos] as usize;
                    let formats_start = pos + 1;
                    let formats_end = (formats_start + formats_len).min(pos + ext_len);
                    for i in formats_start..formats_end {
                        if i < data.len() {
                            ec_point_formats.push(data[i]);
                        }
                    }
                }
            }

            pos += ext_len;
        }

        Some(Self {
            version,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats,
        })
    }

    /// Generate the JA3 string (before hashing).
    pub fn ja3_string(&self) -> String {
        let version = self.version.to_string();

        let ciphers: String = self
            .cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let extensions: String = self
            .extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let groups: String = self
            .supported_groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let formats: String = self
            .ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "{},{},{},{},{}",
            version, ciphers, extensions, groups, formats
        )
    }

    /// Generate the JA3 hash (MD5 of the JA3 string).
    pub fn hash(&self) -> String {
        let ja3_str = self.ja3_string();
        format!("{:x}", md5::compute(ja3_str.as_bytes()))
    }
}

impl fmt::Display for Ja3Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hash())
    }
}

/// Simple MD5 implementation for JA3 hashing.
/// This is a minimal implementation - in production, use a proper crypto library.
mod md5 {
    pub(super) struct Digest([u8; 16]);

    impl Digest {
        #[allow(dead_code)]
        pub(super) fn bytes(&self) -> &[u8; 16] {
            &self.0
        }
    }

    impl std::fmt::LowerHex for Digest {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for byte in &self.0 {
                write!(f, "{:02x}", byte)?;
            }
            Ok(())
        }
    }

    /// Compute MD5 hash of data.
    pub(super) fn compute(data: &[u8]) -> Digest {
        // Constants from RFC 1321
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];

        const K: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];

        // Pad message
        let original_len = data.len();
        let mut msg = data.to_vec();
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        let bit_len = (original_len as u64) * 8;
        msg.extend_from_slice(&bit_len.to_le_bytes());

        // Initialize state
        let mut a0: u32 = 0x67452301;
        let mut b0: u32 = 0xefcdab89;
        let mut c0: u32 = 0x98badcfe;
        let mut d0: u32 = 0x10325476;

        // Process each 64-byte chunk
        for chunk in msg.chunks(64) {
            let mut m = [0u32; 16];
            for (i, bytes) in chunk.chunks(4).enumerate() {
                m[i] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            }

            let mut a = a0;
            let mut b = b0;
            let mut c = c0;
            let mut d = d0;

            for i in 0..64 {
                let (f, g) = match i {
                    0..=15 => ((b & c) | (!b & d), i),
                    16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                    _ => (c ^ (b | !d), (7 * i) % 16),
                };

                let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
                a = d;
                d = c;
                c = b;
                b = b.wrapping_add(f.rotate_left(S[i]));
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }

        let mut result = [0u8; 16];
        result[0..4].copy_from_slice(&a0.to_le_bytes());
        result[4..8].copy_from_slice(&b0.to_le_bytes());
        result[8..12].copy_from_slice(&c0.to_le_bytes());
        result[12..16].copy_from_slice(&d0.to_le_bytes());
        Digest(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample TLS 1.2 ClientHello with correct lengths
    fn sample_client_hello() -> Vec<u8> {
        vec![
            // TLS record header
            0x16, 0x03, 0x01, 0x00, 0x65, // Handshake header
            0x01, 0x00, 0x00, 0x61, // Client version (TLS 1.2)
            0x03, 0x03, // Client random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, // Session ID length
            0x00, // Cipher suites (2 bytes length + ciphers)
            0x00, 0x04, 0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            // Compression methods
            0x01, 0x00, // Extensions length = 0x26 (38 bytes)
            0x00, 0x26, // SNI extension (type 0x0000, length 16)
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
            // Supported Groups extension (type 0x000a, length 4)
            0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, // secp256r1
            // EC Point Formats extension (type 0x000b, length 2)
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // 1 format: uncompressed
        ]
    }

    #[test]
    fn test_ja3_from_client_hello() {
        let hello = sample_client_hello();
        let fp = Ja3Fingerprint::from_client_hello(&hello);
        assert!(fp.is_some());

        let fp = fp.unwrap();
        assert_eq!(fp.version, 0x0303); // TLS 1.2
        assert_eq!(fp.cipher_suites, vec![0x002f, 0x0035]);
        assert!(fp.extensions.contains(&0x0000)); // SNI
        assert!(fp.extensions.contains(&0x000a)); // Supported Groups
                                                  // Verify we found supported groups
        assert!(!fp.supported_groups.is_empty());
    }

    #[test]
    fn test_ja3_string() {
        let hello = sample_client_hello();
        let fp = Ja3Fingerprint::from_client_hello(&hello).unwrap();
        let ja3_str = fp.ja3_string();

        // Should contain version, ciphers, extensions, groups, formats
        assert!(ja3_str.starts_with("771,")); // 0x0303 = 771
        assert!(ja3_str.contains("47-53")); // cipher suites
    }

    #[test]
    fn test_ja3_hash() {
        let hello = sample_client_hello();
        let fp = Ja3Fingerprint::from_client_hello(&hello).unwrap();
        let hash = fp.hash();

        // Hash should be 32 hex characters (128 bits)
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_md5() {
        // Test MD5 with known values
        let digest = md5::compute(b"");
        assert_eq!(format!("{:x}", digest), "d41d8cd98f00b204e9800998ecf8427e");

        let digest = md5::compute(b"hello");
        assert_eq!(format!("{:x}", digest), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_grease_filtering() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0035));
        assert!(!is_grease(0x002f));
    }

    #[test]
    fn test_invalid_data() {
        assert!(Ja3Fingerprint::from_client_hello(&[]).is_none());
        assert!(Ja3Fingerprint::from_client_hello(&[0x17, 0x03, 0x03]).is_none()); // Not handshake
        assert!(Ja3Fingerprint::from_client_hello(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x02]).is_none());
        // Not ClientHello
    }
}
