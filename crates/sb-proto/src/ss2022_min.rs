//! Minimal Shadowsocks 2022 handshake packet builder.
//! 最小化 Shadowsocks 2022 握手数据包构建器。
//!
//! Provides [`Ss2022Hello`] for constructing SS2022 protocol handshake packets.
//! Integrates with `ss2022_core` when available, otherwise uses fallback implementation.
//! 提供 [`Ss2022Hello`] 用于构建 SS2022 协议握手数据包。
//! 当可用时与 `ss2022_core` 集成，否则使用回退实现。
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
    /// Attempts to use `ss2022_core::build_client_first` if feature `proto_ss2022_core`
    /// is enabled and the method can be parsed. Falls back to a simple marker format otherwise.
    /// 如果启用了 `proto_ss2022_core` 特性且方法可解析，则尝试使用 `ss2022_core::build_client_first`。
    /// 否则回退到简单的标记格式。
    ///
    /// # Fallback Format / 回退格式
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
