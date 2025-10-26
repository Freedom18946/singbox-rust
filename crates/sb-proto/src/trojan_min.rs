//! Minimal Trojan handshake packet builder (pure byte manipulation, no networking).
//!
//! This module provides [`TrojanHello`] for constructing Trojan protocol handshake packets.
//!
//! # Packet Format (Simplified)
//!
//! ```text
//! [password]CRLF
//! CONNECT SP host ":" port CRLF
//! CRLF
//! ```
//!
//! # Example
//!
//! ```rust
//! use sb_proto::trojan_min::TrojanHello;
//!
//! let hello = TrojanHello {
//!     password: "secret".to_string(),
//!     host: "example.com".to_string(),
//!     port: 443,
//! };
//! let bytes = hello.to_bytes();
//! assert!(bytes.starts_with(b"secret\r\nCONNECT example.com:443\r\n\r\n"));
//! ```

use bytes::{BufMut, BytesMut};

/// Trojan protocol hello packet.
///
/// Represents the initial handshake sent by a Trojan client to establish a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanHello {
    /// Password for authentication (sent in plaintext over TLS).
    pub password: String,
    /// Target hostname or IP.
    pub host: String,
    /// Target port.
    pub port: u16,
}

impl TrojanHello {
    /// Serializes the hello packet to bytes.
    ///
    /// # Format
    /// `{password}\r\nCONNECT {host}:{port}\r\n\r\n`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = self.password.len() + self.host.len() + 32;
        let mut buffer = BytesMut::with_capacity(capacity);

        buffer.put(self.password.as_bytes());
        buffer.put(&b"\r\n"[..]);
        buffer.put(&b"CONNECT "[..]);
        buffer.put(self.host.as_bytes());
        buffer.put_u8(b':');
        buffer.put(self.port.to_string().as_bytes());
        buffer.put(&b"\r\n"[..]);
        buffer.put(&b"\r\n"[..]);

        buffer.to_vec()
    }
}
