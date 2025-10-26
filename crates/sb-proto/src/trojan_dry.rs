//! Trojan dry-run packet builder for testing (no actual network I/O).
//!
//! Provides functions to build Trojan handshake packets and generate test reports
//! without performing real connections. Useful for admin dry-run scenarios.

#[cfg(feature = "proto_trojan_dry")]
#[allow(clippy::module_inception)]
pub mod trojan_dry {
    use serde::{Deserialize, Serialize};

    /// Encodes bytes to hexadecimal string.
    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Report structure for dry-run connection attempts.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DryrunReport {
        /// Length of generated packet in bytes.
        pub bytes_len: usize,
        /// Metadata about the connection attempt.
        pub meta: ConnectMeta,
    }

    /// Metadata for a dry-run connection.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConnectMeta {
        /// Connection kind ("hello" or "tls_first").
        pub kind: String,
        /// Whether password hashing is enabled (placeholder).
        pub hashes: bool,
        /// Whether ordering is preserved (placeholder).
        pub ordered: bool,
        /// Whether normalization is applied (placeholder).
        pub normalized: bool,
    }

    /// Builds a Trojan hello packet.
    ///
    /// # Packet Format (Placeholder)
    /// ```text
    /// hex(blake3(password)[..28]) CRLF
    /// SOCKS5-address CRLF
    /// ```
    ///
    /// # Security Warning
    /// Uses blake3 to simulate sha224 for testing. Not cryptographically equivalent to real Trojan.
    #[must_use]
    pub fn build_hello(password: &str, host: &str, port: u16) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let hash_hex = hex_encode(&hash.as_bytes()[..28]); // Simulate sha224

        let mut result = Vec::new();

        // Password hash
        result.extend_from_slice(hash_hex.as_bytes());
        result.extend_from_slice(b"\r\n");

        // Target address (SOCKS5-like format)
        result.push(0x03); // Domain name type
        result.push(host.len() as u8);
        result.extend_from_slice(host.as_bytes());
        result.extend_from_slice(&port.to_be_bytes());
        result.extend_from_slice(b"\r\n");

        result
    }

    /// Generates a dry-run report for a packet.
    #[must_use]
    pub fn report_shape(bytes_len: usize, with_tls: bool) -> DryrunReport {
        DryrunReport {
            bytes_len,
            meta: ConnectMeta {
                kind: if with_tls {
                    "tls_first".to_string()
                } else {
                    "hello".to_string()
                },
                hashes: false,
                ordered: false,
                normalized: false,
            },
        }
    }

    /// Builds a TLS-first Trojan packet (placeholder).
    ///
    /// Appends a TLS marker to the standard hello packet for testing.
    #[must_use]
    pub fn build_tls_first(password: &str, host: &str, port: u16) -> Vec<u8> {
        let mut hello = build_hello(password, host, port);
        hello.extend_from_slice(b"TLS_CLIENT_HELLO_PLACEHOLDER");
        hello
    }
}

#[cfg(feature = "proto_trojan_dry")]
pub use trojan_dry::*;
