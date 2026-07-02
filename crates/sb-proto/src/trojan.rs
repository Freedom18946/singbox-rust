//! Trojan CONNECT request packet builder.
//! Trojan CONNECT 请求包构建器。
//!
//! This module provides [`TrojanHello`] for constructing the first Trojan request
//! written after the transport/TLS layer has been established.
//! 本模块提供 [`TrojanHello`]，用于构建传输/TLS 层建立后写入的首个 Trojan 请求。
//!
//! # Packet Format / 数据包格式
//!
//! ```text
//! HEX(SHA224(password)) CRLF
//! CMD ATYP DST.ADDR DST.PORT CRLF
//! ```
//!
//! # Example / 示例
//!
//! ```rust
//! use sb_proto::trojan::TrojanHello;
//!
//! let hello = TrojanHello {
//!     password: "secret".to_string(),
//!     host: "example.com".to_string(),
//!     port: 443,
//! };
//! let bytes = hello.to_bytes().unwrap();
//! assert!(bytes.starts_with(b"95c7fbca92ac5083afda62a564a3d014fc3b72c9140e3cb99ea6bf12\r\n"));
//! assert_eq!(bytes[58], 0x01); // CONNECT
//! assert_eq!(bytes[59], 0x03); // domain name
//! ```

use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use thiserror::Error;

/// Error returned while building a Trojan request packet.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrojanHelloError {
    /// Target host cannot be empty.
    #[error("target host cannot be empty")]
    EmptyHost,

    /// Domain names in Trojan requests are length-prefixed with one byte.
    #[error("domain target is too long: {0} bytes")]
    DomainTooLong(usize),
}

/// Trojan protocol CONNECT request packet.
/// Trojan 协议 CONNECT 请求包。
///
/// Represents the initial request sent by a Trojan client to establish a connection.
/// 表示 Trojan 客户端为建立连接而发送的初始请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanHello {
    /// Password for authentication. The packet carries its SHA224 hex digest.
    /// 用于认证的密码。请求包携带它的 SHA224 十六进制摘要。
    pub password: String,
    /// Target hostname or IP.
    /// 目标主机名或 IP。
    pub host: String,
    /// Target port.
    /// 目标端口。
    pub port: u16,
}

impl TrojanHello {
    /// Serializes the Trojan CONNECT request packet to bytes.
    /// 将 Trojan CONNECT 请求包序列化为字节。
    ///
    /// # Format / 格式
    /// `hex(sha224(password))\r\n\x01{atyp}{addr}{port_be}\r\n`
    ///
    /// # Errors
    /// Returns [`TrojanHelloError`] if the target host cannot be represented in
    /// a Trojan address field.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TrojanHelloError> {
        if self.host.is_empty() {
            return Err(TrojanHelloError::EmptyHost);
        }

        let capacity = 56 + 2 + 1 + 1 + self.host.len() + 2 + 2;
        let mut buffer = BytesMut::with_capacity(capacity);

        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let password_hash = hasher.finalize();
        buffer.put(hex::encode(password_hash).as_bytes());
        buffer.put(&b"\r\n"[..]);

        buffer.put_u8(0x01); // CONNECT
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    buffer.put_u8(0x01);
                    buffer.put(&ipv4.octets()[..]);
                }
                std::net::IpAddr::V6(ipv6) => {
                    buffer.put_u8(0x04);
                    buffer.put(&ipv6.octets()[..]);
                }
            }
        } else {
            let host_len = u8::try_from(self.host.len())
                .map_err(|_| TrojanHelloError::DomainTooLong(self.host.len()))?;
            buffer.put_u8(0x03);
            buffer.put_u8(host_len);
            buffer.put(self.host.as_bytes());
        }

        buffer.put_u16(self.port);
        buffer.put(&b"\r\n"[..]);

        Ok(buffer.to_vec())
    }
}
