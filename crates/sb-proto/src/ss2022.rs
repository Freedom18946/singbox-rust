//! Shadowsocks 2022 handshake packet builder.
//! Shadowsocks 2022 握手数据包构建器。
//!
//! Provides [`Ss2022Hello`] for constructing SS2022 protocol handshake packets.
//!
//! # Security Warning / 安全警告
//! This is a minimal implementation for admin dry-runs and testing. Real production
//! implementation should be extended with proper cryptographic primitives.
//! 这是一个用于管理空跑和测试的最小化实现。真正的生产实现应扩展适当的加密原语。

use bytes::{BufMut, BytesMut};

/// Shadowsocks 2022 protocol hello packet.
/// Shadowsocks 2022 协议 hello 数据包。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ss2022Hello {
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

impl Ss2022Hello {
    /// Serializes the hello packet to bytes.
    /// 将 hello 数据包序列化为字节。
    ///
    /// # Format / 格式
    /// `SS2022\0{method}\0{password}\0{host}:{port}`
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple marker format implementation
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
