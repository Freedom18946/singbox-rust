//! Shadowsocks 2022 dry-run marker builder.
//! Shadowsocks 2022 空跑标记构建器。
//!
//! Provides [`Ss2022DryRunMarker`] for constructing deterministic marker bytes
//! used by admin dry-runs and API shape tests. These bytes are not a
//! Shadowsocks 2022 encrypted handshake or production protocol packet.
//!
//! # Scope / 范围
//! This module intentionally does not implement Shadowsocks 2022 cryptography.
//! Production outbound support lives in `sb-adapters`.

use bytes::{BufMut, BytesMut};

/// Deterministic Shadowsocks 2022 dry-run marker.
///
/// This is a structured marker for local tests and admin diagnostics, not an
/// SS2022 protocol handshake packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ss2022DryRunMarker {
    /// Cipher method (e.g., "2022-blake3-aes-256-gcm").
    /// 加密方法（例如 "2022-blake3-aes-256-gcm"）。
    pub method: String,
    /// Password/key for authentication.
    /// 用于认证的密码/密钥。
    pub password: String,
    /// Target hostname or IP.
    /// 目标主机名或 IP。
    pub host: String,
    /// Target port.
    /// 目标端口。
    pub port: u16,
}

/// Compatibility alias for older callers.
///
/// The aliased type emits dry-run marker bytes, not an SS2022 protocol
/// handshake.
pub type Ss2022Hello = Ss2022DryRunMarker;

impl Ss2022DryRunMarker {
    /// Serializes the marker to bytes.
    /// 将标记序列化为字节。
    ///
    /// # Format / 格式
    /// `SS2022\0{method}\0{password}\0{host}:{port}`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
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
