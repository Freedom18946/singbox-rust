//! Minimal Shadowsocks 2022 handshake packet builder.
//!
//! Provides [`Ss2022Hello`] for constructing SS2022 protocol handshake packets.
//! Integrates with `ss2022_core` when available, otherwise uses fallback implementation.
//!
//! # Security Warning
//! This is a minimal implementation for admin dry-runs and testing. Real production
//! implementation should be extended with proper cryptographic primitives.

use bytes::{BufMut, BytesMut};

/// Shadowsocks 2022 protocol hello packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ss2022Hello {
    /// Cipher method (e.g., "2022-blake3-aes-256-gcm").
    pub method: String,
    /// Password/key for authentication.
    pub password: String,
    /// Target hostname or IP.
    pub host: String,
    /// Target port.
    pub port: u16,
}

impl Ss2022Hello {
    /// Serializes the hello packet to bytes.
    ///
    /// Attempts to use `ss2022_core::build_client_first` if feature `proto_ss2022_core`
    /// is enabled and the method can be parsed. Falls back to a simple marker format otherwise.
    ///
    /// # Fallback Format
    /// `SS2022\0{method}\0{password}\0{host}:{port}`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        #[cfg(feature = "proto_ss2022_core")]
        {
            if let Some(aead) = crate::ss2022_core::parse_aead_kind(&self.method) {
                if let Ok(bytes) = crate::ss2022_core::build_client_first(
                    &self.method,
                    &self.password,
                    &self.host,
                    self.port,
                    aead,
                ) {
                    return bytes;
                }
            }
        }

        // Fallback implementation
        let capacity = 64 + self.host.len() + self.password.len() + self.method.len();
        let mut buffer = BytesMut::with_capacity(capacity);

        buffer.put(&b"SS2022\0"[..]);
        buffer.put(self.method.as_bytes());
        buffer.put_u8(0);
        buffer.put(self.password.as_bytes());
        buffer.put_u8(0);
        buffer.put(self.host.as_bytes());
        buffer.put_u8(b':');
        buffer.put(self.port.to_string().as_bytes());

        buffer.to_vec()
    }
}
