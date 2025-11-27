//! Minimal Trojan handshake packet builder (pure byte manipulation, no networking).
//! 最小化 Trojan 握手数据包构建器（纯字节操作，无网络）。
//!
//! This module provides [`TrojanHello`] for constructing Trojan protocol handshake packets.
//! 本模块提供 [`TrojanHello`] 用于构建 Trojan 协议握手数据包。
//!
//! # Packet Format (Simplified) / 数据包格式（简化）
//!
//! ```text
//! [password]CRLF
//! CONNECT SP host ":" port CRLF
//! CRLF
//! ```
//!
//! # Example / 示例
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
/// Trojan 协议 hello 数据包。
///
/// Represents the initial handshake sent by a Trojan client to establish a connection.
/// 表示 Trojan 客户端为建立连接而发送的初始握手。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanHello {
    /// Password for authentication (sent in plaintext over TLS).
    /// 用于认证的密码（在 TLS 上以明文发送）。
    pub password: String,
    /// Target hostname or IP.
    /// 目标主机名或 IP。
    pub host: String,
    /// Target port.
    /// 目标端口。
    pub port: u16,
}

impl TrojanHello {
    /// Serializes the hello packet to bytes.
    /// 将 hello 数据包序列化为字节。
    ///
    /// # Format / 格式
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
