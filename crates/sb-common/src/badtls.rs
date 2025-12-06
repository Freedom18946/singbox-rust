//! Bad TLS detection and version validation utilities.
//! 错误 TLS 检测和版本验证工具。
//!
//! This module provides functionality to detect broken or misconfigured TLS
//! implementations, version mismatches, and other TLS-related issues that
//! may cause connection failures or security problems.
//!
//! # Features
//!
//! - TLS version detection and validation
//! - Bad TLS pattern detection
//! - Version downgrade detection
//! - Certificate issue detection hints

use std::fmt;

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TlsVersion {
    /// SSL 3.0 (deprecated, insecure)
    Ssl30,
    /// TLS 1.0 (deprecated)
    Tls10,
    /// TLS 1.1 (deprecated)
    Tls11,
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
    /// Unknown version
    Unknown(u16),
}

impl TlsVersion {
    /// Parse TLS version from wire format (major, minor).
    pub fn from_bytes(major: u8, minor: u8) -> Self {
        match (major, minor) {
            (3, 0) => Self::Ssl30,
            (3, 1) => Self::Tls10,
            (3, 2) => Self::Tls11,
            (3, 3) => Self::Tls12,
            (3, 4) => Self::Tls13,
            _ => Self::Unknown(u16::from_be_bytes([major, minor])),
        }
    }

    /// Get the wire format bytes.
    pub fn to_bytes(self) -> (u8, u8) {
        match self {
            Self::Ssl30 => (3, 0),
            Self::Tls10 => (3, 1),
            Self::Tls11 => (3, 2),
            Self::Tls12 => (3, 3),
            Self::Tls13 => (3, 4),
            Self::Unknown(v) => {
                let bytes = v.to_be_bytes();
                (bytes[0], bytes[1])
            }
        }
    }

    /// Check if this version is deprecated.
    pub fn is_deprecated(&self) -> bool {
        matches!(self, Self::Ssl30 | Self::Tls10 | Self::Tls11)
    }

    /// Check if this version is secure (TLS 1.2+).
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Tls12 | Self::Tls13)
    }

    /// Get the version name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ssl30 => "SSL 3.0",
            Self::Tls10 => "TLS 1.0",
            Self::Tls11 => "TLS 1.1",
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// TLS issue type detected in a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsIssue {
    /// Using a deprecated TLS version.
    DeprecatedVersion(TlsVersion),
    /// Version mismatch between record and handshake.
    VersionMismatch {
        /// TLS version in the record layer.
        record_version: TlsVersion,
        /// TLS version in the handshake.
        handshake_version: TlsVersion,
    },
    /// Possible version downgrade attack.
    PossibleDowngrade {
        /// TLS version offered by the client.
        offered: TlsVersion,
        /// TLS version negotiated by the server.
        negotiated: TlsVersion,
    },
    /// Invalid or malformed TLS data.
    MalformedData(String),
    /// Empty or missing extensions.
    MissingExtensions,
    /// Weak cipher suite detected.
    WeakCipher(u16),
    /// Self-signed or untrusted certificate hint.
    UntrustedCertificate,
    /// Certificate expired hint.
    ExpiredCertificate,
    /// Hostname mismatch hint.
    HostnameMismatch,
}

impl fmt::Display for TlsIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeprecatedVersion(v) => write!(f, "deprecated TLS version: {}", v),
            Self::VersionMismatch {
                record_version,
                handshake_version,
            } => {
                write!(
                    f,
                    "version mismatch: record={}, handshake={}",
                    record_version, handshake_version
                )
            }
            Self::PossibleDowngrade {
                offered,
                negotiated,
            } => {
                write!(
                    f,
                    "possible downgrade: offered={}, negotiated={}",
                    offered, negotiated
                )
            }
            Self::MalformedData(msg) => write!(f, "malformed TLS data: {}", msg),
            Self::MissingExtensions => write!(f, "missing required TLS extensions"),
            Self::WeakCipher(id) => write!(f, "weak cipher suite: 0x{:04x}", id),
            Self::UntrustedCertificate => write!(f, "untrusted or self-signed certificate"),
            Self::ExpiredCertificate => write!(f, "expired certificate"),
            Self::HostnameMismatch => write!(f, "certificate hostname mismatch"),
        }
    }
}

/// Known weak/insecure cipher suites.
const WEAK_CIPHERS: &[u16] = &[
    // NULL ciphers
    0x0000, 0x0001, 0x0002, // Export ciphers
    0x0003, 0x0006, 0x0008, 0x000b, // DES ciphers
    0x0009, 0x000c, 0x0015, 0x0018, // RC4 ciphers
    0x0004, 0x0005, 0x0017, 0x0018, // IDEA cipher
    0x0007, // Anonymous DH
    0x0017, 0x0018, 0x0019, 0x001a, 0x001b,
];

/// Check if a cipher suite is considered weak.
pub fn is_weak_cipher(cipher: u16) -> bool {
    WEAK_CIPHERS.contains(&cipher)
}

/// TLS analyzer for detecting issues in TLS data.
#[derive(Debug, Default)]
pub struct TlsAnalyzer {
    issues: Vec<TlsIssue>,
}

impl TlsAnalyzer {
    /// Create a new TLS analyzer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a TLS ClientHello and detect potential issues.
    pub fn analyze_client_hello(&mut self, data: &[u8]) -> &[TlsIssue] {
        self.issues.clear();

        if data.len() < 5 {
            self.issues
                .push(TlsIssue::MalformedData("data too short".to_string()));
            return &self.issues;
        }

        // Check record type
        if data[0] != 0x16 {
            self.issues.push(TlsIssue::MalformedData(
                "not a handshake record".to_string(),
            ));
            return &self.issues;
        }

        // Check record version
        let record_version = TlsVersion::from_bytes(data[1], data[2]);
        if record_version.is_deprecated() {
            self.issues
                .push(TlsIssue::DeprecatedVersion(record_version));
        }

        // Parse further if we have enough data
        if data.len() < 9 {
            return &self.issues;
        }

        // Check handshake type
        if data[5] != 0x01 {
            self.issues
                .push(TlsIssue::MalformedData("not a ClientHello".to_string()));
            return &self.issues;
        }

        // Check client version in handshake
        let handshake_version = TlsVersion::from_bytes(data[9], data[10]);

        // Check for version mismatch (common in TLS 1.3 which uses 1.2 in record layer)
        if record_version != handshake_version && handshake_version != TlsVersion::Tls12 {
            self.issues.push(TlsIssue::VersionMismatch {
                record_version,
                handshake_version,
            });
        }

        // Check for deprecated handshake version
        if handshake_version.is_deprecated() && !record_version.is_deprecated() {
            self.issues
                .push(TlsIssue::DeprecatedVersion(handshake_version));
        }

        // Try to parse cipher suites
        if let Some(ciphers) = self.extract_cipher_suites(data) {
            for cipher in ciphers {
                if is_weak_cipher(cipher) {
                    self.issues.push(TlsIssue::WeakCipher(cipher));
                }
            }
        }

        // Check for extensions
        if !self.has_extensions(data) {
            self.issues.push(TlsIssue::MissingExtensions);
        }

        &self.issues
    }

    /// Analyze a TLS ServerHello and detect potential issues.
    pub fn analyze_server_hello(&mut self, data: &[u8], client_version: TlsVersion) -> &[TlsIssue] {
        self.issues.clear();

        if data.len() < 9 {
            self.issues
                .push(TlsIssue::MalformedData("data too short".to_string()));
            return &self.issues;
        }

        // Check record type
        if data[0] != 0x16 {
            self.issues.push(TlsIssue::MalformedData(
                "not a handshake record".to_string(),
            ));
            return &self.issues;
        }

        // Check handshake type (ServerHello = 0x02)
        if data[5] != 0x02 {
            self.issues
                .push(TlsIssue::MalformedData("not a ServerHello".to_string()));
            return &self.issues;
        }

        // Check server version
        let server_version = TlsVersion::from_bytes(data[9], data[10]);

        if server_version.is_deprecated() {
            self.issues
                .push(TlsIssue::DeprecatedVersion(server_version));
        }

        // Check for downgrade
        if server_version < client_version {
            self.issues.push(TlsIssue::PossibleDowngrade {
                offered: client_version,
                negotiated: server_version,
            });
        }

        &self.issues
    }

    /// Get all detected issues.
    pub fn issues(&self) -> &[TlsIssue] {
        &self.issues
    }

    /// Check if any critical issues were detected.
    pub fn has_critical_issues(&self) -> bool {
        self.issues.iter().any(|i| {
            matches!(
                i,
                TlsIssue::MalformedData(_)
                    | TlsIssue::WeakCipher(_)
                    | TlsIssue::PossibleDowngrade { .. }
            )
        })
    }

    /// Extract cipher suites from ClientHello.
    fn extract_cipher_suites(&self, data: &[u8]) -> Option<Vec<u16>> {
        // Skip: record header (5) + handshake header (4) + version (2) + random (32) + session_id_len (1)
        let mut pos = 5 + 4 + 2 + 32;
        if pos >= data.len() {
            return None;
        }

        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > data.len() {
            return None;
        }

        let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + cipher_len > data.len() {
            return None;
        }

        let mut ciphers = Vec::new();
        let cipher_end = pos + cipher_len;
        while pos + 2 <= cipher_end {
            let cipher = u16::from_be_bytes([data[pos], data[pos + 1]]);
            ciphers.push(cipher);
            pos += 2;
        }

        Some(ciphers)
    }

    /// Check if ClientHello has extensions.
    fn has_extensions(&self, data: &[u8]) -> bool {
        // Skip: record header (5) + handshake header (4) + version (2) + random (32)
        let mut pos = 5 + 4 + 2 + 32;
        if pos >= data.len() {
            return false;
        }

        // Skip session ID
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;
        if pos + 2 > data.len() {
            return false;
        }

        // Skip cipher suites
        let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_len;
        if pos >= data.len() {
            return false;
        }

        // Skip compression methods
        let compression_len = data[pos] as usize;
        pos += 1 + compression_len;
        if pos + 2 > data.len() {
            return false;
        }

        // Check extensions length
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        ext_len > 0
    }
}

/// Quick check if TLS data appears valid.
pub fn is_valid_tls(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    // Check content type (valid values: 20-24)
    let content_type = data[0];
    if !(20..=24).contains(&content_type) {
        return false;
    }

    // Check version
    let version = TlsVersion::from_bytes(data[1], data[2]);
    if matches!(version, TlsVersion::Unknown(_)) {
        return false;
    }

    // Check length is reasonable
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    length <= 16384 + 2048 // Max TLS record size with some margin
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_hello() -> Vec<u8> {
        vec![
            // TLS record header (TLS 1.0 for compatibility)
            0x16, 0x03, 0x01, 0x00, 0x45, // Handshake header (ClientHello)
            0x01, 0x00, 0x00, 0x41, // Client version (TLS 1.2)
            0x03, 0x03, // Client random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, // Session ID length
            0x00, // Cipher suites (TLS_RSA_WITH_AES_128_GCM_SHA256)
            0x00, 0x02, 0x00, 0x9c, // Compression methods
            0x01, 0x00, // Extensions length
            0x00, 0x10, // SNI extension
            0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x00, 0x07, b't', b'e', b's', b't', b'.',
            b'c', b'o', b'm',
        ]
    }

    #[test]
    fn test_tls_version() {
        assert_eq!(TlsVersion::from_bytes(3, 1), TlsVersion::Tls10);
        assert_eq!(TlsVersion::from_bytes(3, 3), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_bytes(3, 4), TlsVersion::Tls13);

        assert!(TlsVersion::Tls10.is_deprecated());
        assert!(!TlsVersion::Tls12.is_deprecated());
        assert!(TlsVersion::Tls12.is_secure());
    }

    #[test]
    fn test_weak_cipher_detection() {
        assert!(is_weak_cipher(0x0000)); // NULL cipher
        assert!(is_weak_cipher(0x0004)); // RC4
        assert!(!is_weak_cipher(0x009c)); // AES-128-GCM
        assert!(!is_weak_cipher(0x1301)); // TLS_AES_128_GCM_SHA256
    }

    #[test]
    fn test_analyzer_client_hello() {
        let hello = sample_client_hello();
        let mut analyzer = TlsAnalyzer::new();
        analyzer.analyze_client_hello(&hello);

        // Should not have critical issues with good ciphers
        assert!(!analyzer.has_critical_issues());

        // Should have extensions
        let issues = analyzer.issues();
        assert!(!issues
            .iter()
            .any(|i| matches!(i, TlsIssue::MissingExtensions)));
    }

    #[test]
    fn test_analyzer_deprecated_version() {
        // Create a ClientHello with SSL 3.0
        let mut hello = sample_client_hello();
        hello[1] = 0x03;
        hello[2] = 0x00; // SSL 3.0

        let mut analyzer = TlsAnalyzer::new();
        analyzer.analyze_client_hello(&hello);

        let issues = analyzer.issues();
        assert!(issues
            .iter()
            .any(|i| matches!(i, TlsIssue::DeprecatedVersion(_))));
    }

    #[test]
    fn test_is_valid_tls() {
        let hello = sample_client_hello();
        assert!(is_valid_tls(&hello));

        // Not TLS
        assert!(!is_valid_tls(&[0x00, 0x00, 0x00, 0x00, 0x00]));
        assert!(!is_valid_tls(&[]));

        // Invalid content type
        assert!(!is_valid_tls(&[0x30, 0x03, 0x03, 0x00, 0x10]));
    }

    #[test]
    fn test_tls_issue_display() {
        let issue = TlsIssue::DeprecatedVersion(TlsVersion::Tls10);
        assert!(issue.to_string().contains("TLS 1.0"));

        let issue = TlsIssue::WeakCipher(0x0004);
        assert!(issue.to_string().contains("0004"));
    }
}
