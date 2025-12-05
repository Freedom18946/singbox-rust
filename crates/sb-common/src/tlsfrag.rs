//! TLS fragmentation utilities for DPI bypass.
//! TLS 分片工具，用于绕过深度包检测 (DPI)。
//!
//! This module provides functionality to fragment TLS ClientHello messages
//! into smaller pieces to evade deep packet inspection systems that try to
//! detect and block TLS connections based on SNI or other patterns.
//!
//! # Usage
//!
//! ```ignore
//! use sb_common::tlsfrag::{FragmentConfig, fragment_client_hello};
//!
//! let config = FragmentConfig::default();
//! let fragments = fragment_client_hello(&client_hello_data, &config);
//! for fragment in fragments {
//!     stream.write_all(&fragment).await?;
//!     tokio::time::sleep(config.delay).await;
//! }
//! ```

use std::time::Duration;

/// TLS record header size (type + version + length).
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// TLS handshake header size (type + length[3]).
const TLS_HANDSHAKE_HEADER_SIZE: usize = 4;

/// TLS content type for Handshake.
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS handshake type for ClientHello.
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// Configuration for TLS fragmentation.
#[derive(Debug, Clone)]
pub struct FragmentConfig {
    /// Fragment size range (min, max). Each fragment will be randomly sized
    /// between these values (inclusive).
    pub size_range: (usize, usize),
    /// Delay between sending fragments.
    pub delay: Duration,
    /// Whether to fragment the TLS record header itself.
    pub fragment_header: bool,
    /// Whether to enable fragmentation.
    pub enabled: bool,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            size_range: (1, 5),
            delay: Duration::from_millis(10),
            fragment_header: false,
            enabled: true,
        }
    }
}

impl FragmentConfig {
    /// Create a new fragment config with the given size range.
    pub fn new(min_size: usize, max_size: usize) -> Self {
        Self {
            size_range: (min_size.max(1), max_size.max(1)),
            ..Default::default()
        }
    }

    /// Set the delay between fragments.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Enable or disable header fragmentation.
    pub fn with_header_fragmentation(mut self, enabled: bool) -> Self {
        self.fragment_header = enabled;
        self
    }
}

/// Fragment data into pieces of random sizes within the configured range.
fn fragment_data(data: &[u8], config: &FragmentConfig) -> Vec<Vec<u8>> {
    if data.is_empty() || !config.enabled {
        return vec![data.to_vec()];
    }

    let (min_size, max_size) = config.size_range;
    let mut fragments = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // Use a simple deterministic "random" based on offset for reproducibility
        let range = max_size.saturating_sub(min_size) + 1;
        let size = if range > 1 {
            min_size + (offset % range)
        } else {
            min_size
        };

        let end = (offset + size).min(data.len());
        fragments.push(data[offset..end].to_vec());
        offset = end;
    }

    fragments
}

/// Check if the data looks like a TLS ClientHello.
pub fn is_client_hello(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE {
        return false;
    }

    // Check TLS record header
    let content_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];

    // Should be Handshake (0x16) with TLS version (0x0301 - 0x0303)
    if content_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return false;
    }
    if version_major != 0x03 || version_minor > 0x03 {
        return false;
    }

    // Check handshake type
    let handshake_type = data[TLS_RECORD_HEADER_SIZE];
    handshake_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello.
/// Returns None if SNI is not found or data is malformed.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    if !is_client_hello(data) {
        return None;
    }

    // Skip TLS record header (5 bytes) and handshake header (4 bytes)
    let mut pos = TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE;

    // Skip client version (2 bytes)
    pos += 2;
    if pos >= data.len() {
        return None;
    }

    // Skip client random (32 bytes)
    pos += 32;
    if pos >= data.len() {
        return None;
    }

    // Skip session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos >= data.len() {
        return None;
    }

    // Skip cipher suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= data.len() {
        return None;
    }

    // Skip compression methods
    if pos >= data.len() {
        return None;
    }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;
    if pos + 2 > data.len() {
        return None;
    }

    // Extensions length
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;

    // Parse extensions
    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        // SNI extension type is 0x0000
        if ext_type == 0x0000 && ext_len >= 5 && pos + ext_len <= data.len() {
            // SNI list length (2 bytes)
            let sni_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            if sni_list_len >= 3 && pos + 2 + sni_list_len <= data.len() {
                // Name type (1 byte, should be 0x00 for host_name)
                let name_type = data[pos + 2];
                if name_type == 0x00 {
                    let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                    if pos + 5 + name_len <= data.len() {
                        let sni = &data[pos + 5..pos + 5 + name_len];
                        return String::from_utf8(sni.to_vec()).ok();
                    }
                }
            }
        }

        pos += ext_len;
    }

    None
}

/// Fragment a TLS ClientHello message for DPI bypass.
///
/// Returns a vector of fragments to be sent with delays between them.
/// If the data is not a valid ClientHello or fragmentation is disabled,
/// returns the original data as a single fragment.
pub fn fragment_client_hello(data: &[u8], config: &FragmentConfig) -> Vec<Vec<u8>> {
    if !config.enabled || !is_client_hello(data) {
        return vec![data.to_vec()];
    }

    if config.fragment_header {
        // Fragment everything including the TLS record header
        fragment_data(data, config)
    } else {
        // Keep the TLS record header intact, only fragment the payload
        if data.len() <= TLS_RECORD_HEADER_SIZE {
            return vec![data.to_vec()];
        }

        let header = data[..TLS_RECORD_HEADER_SIZE].to_vec();
        let payload = &data[TLS_RECORD_HEADER_SIZE..];
        let payload_fragments = fragment_data(payload, config);

        // Prepend header to first fragment, rest are pure payload fragments
        let mut result = Vec::with_capacity(payload_fragments.len());
        for (i, frag) in payload_fragments.into_iter().enumerate() {
            if i == 0 {
                let mut combined = header.clone();
                combined.extend(frag);
                result.push(combined);
            } else {
                result.push(frag);
            }
        }
        result
    }
}

/// Statistics about fragmentation.
#[derive(Debug, Clone, Default)]
pub struct FragmentStats {
    /// Total messages fragmented.
    pub messages_fragmented: u64,
    /// Total fragments created.
    pub fragments_created: u64,
    /// Total bytes fragmented.
    pub bytes_fragmented: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample TLS 1.2 ClientHello with SNI "example.com"
    fn sample_client_hello() -> Vec<u8> {
        vec![
            // TLS record header
            0x16, // Content type: Handshake
            0x03, 0x01, // Version: TLS 1.0 (for compatibility)
            0x00, 0x5d, // Length: 93 bytes
            // Handshake header
            0x01, // Type: ClientHello
            0x00, 0x00, 0x59, // Length: 89 bytes
            // Client version
            0x03, 0x03, // TLS 1.2
            // Client random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, // Session ID length
            0x00, // Cipher suites
            0x00, 0x02, // Length: 2 bytes
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            // Compression methods
            0x01, // Length: 1 byte
            0x00, // null compression
            // Extensions
            0x00, 0x26, // Length: 38 bytes
            // SNI extension
            0x00, 0x00, // Type: server_name
            0x00, 0x10, // Length: 16 bytes
            0x00, 0x0e, // SNI list length: 14 bytes
            0x00, // Name type: host_name
            0x00, 0x0b, // Name length: 11 bytes
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            // Supported versions extension (padding)
            0x00, 0x2b, // Type: supported_versions
            0x00, 0x03, // Length: 3 bytes
            0x02, // Versions length: 2 bytes
            0x03, 0x03, // TLS 1.2
        ]
    }

    #[test]
    fn test_is_client_hello() {
        let hello = sample_client_hello();
        assert!(is_client_hello(&hello));

        // Not a ClientHello
        assert!(!is_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x10]));
        assert!(!is_client_hello(&[]));
    }

    #[test]
    fn test_extract_sni() {
        let hello = sample_client_hello();
        let sni = extract_sni(&hello);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_fragment_data() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let config = FragmentConfig::new(2, 3);

        let fragments = fragment_data(&data, &config);
        assert!(fragments.len() > 1);

        // Verify all data is preserved
        let reassembled: Vec<u8> = fragments.into_iter().flatten().collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragment_client_hello() {
        let hello = sample_client_hello();
        let config = FragmentConfig::new(5, 10);

        let fragments = fragment_client_hello(&hello, &config);
        assert!(fragments.len() > 1);

        // First fragment should contain the TLS record header
        assert!(fragments[0].len() >= TLS_RECORD_HEADER_SIZE);
        assert_eq!(fragments[0][0], TLS_CONTENT_TYPE_HANDSHAKE);

        // Verify all data is preserved
        let reassembled: Vec<u8> = fragments.into_iter().flatten().collect();
        assert_eq!(reassembled, hello);
    }

    #[test]
    fn test_fragment_with_header() {
        let hello = sample_client_hello();
        let config = FragmentConfig::new(2, 4).with_header_fragmentation(true);

        let fragments = fragment_client_hello(&hello, &config);
        assert!(fragments.len() > 1);

        // With header fragmentation, first fragment may be smaller
        assert!(fragments[0].len() < TLS_RECORD_HEADER_SIZE + 5);

        // Verify all data is preserved
        let reassembled: Vec<u8> = fragments.into_iter().flatten().collect();
        assert_eq!(reassembled, hello);
    }

    #[test]
    fn test_disabled_fragmentation() {
        let hello = sample_client_hello();
        let mut config = FragmentConfig::default();
        config.enabled = false;

        let fragments = fragment_client_hello(&hello, &config);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], hello);
    }
}
