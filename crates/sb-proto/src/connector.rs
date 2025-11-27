//! Core protocol abstraction layer for outbound connections.
//! 出站连接的核心协议抽象层。
//!
//! This module provides fundamental traits and types for implementing proxy protocols:
//! 本模块提供了实现代理协议的基础 trait 和类型：
//! - [`OutboundConnector`]: Trait for establishing outbound connections
//!   - 用于建立出站连接的 trait
//! - [`Target`]: Represents a connection target (host:port)
//!   - 表示连接目标 (主机:端口)
//! - [`IoStream`]: Trait alias for async I/O streams
//!   - 异步 I/O 流的 trait 别名
//! - [`ProtoError`]: Common error types for protocol operations
//!   - 协议操作的通用错误类型
//!
//! # Strategic Significance / 战略意义
//!
//! The `OutboundConnector` trait is the primary interface between the protocol layer and the
//! application logic. By standardizing how connections are established, it allows the upper layers
//! to be agnostic to the specific protocol details (Trojan, Shadowsocks, etc.).
//! `OutboundConnector` trait 是协议层和应用逻辑之间的主要接口。
//! 通过标准化连接建立的方式，它允许上层逻辑对具体协议细节（Trojan, Shadowsocks 等）保持不可知。

use thiserror::Error;

/// Errors that can occur during protocol operations.
/// 协议操作期间可能发生的错误。
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Feature not yet implemented.
    /// 特性尚未实现。
    #[error("not implemented")]
    NotImplemented,

    /// Invalid configuration with dynamic error message.
    /// 带有动态错误消息的无效配置。
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// I/O error during protocol operations.
    /// 协议操作期间的 I/O 错误。
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Represents a connection target with host and port.
/// 表示带有主机和端口的连接目标。
///
/// This struct encapsulates the destination information required to establish a connection.
/// It is used by `OutboundConnector` to determine where to connect.
/// 此结构体封装了建立连接所需的目标信息。`OutboundConnector` 使用它来确定连接位置。
///
/// # Examples
/// ```
/// # use sb_proto::Target;
/// let target = Target::new("example.com", 443);
/// assert_eq!(target.host(), "example.com");
/// assert_eq!(target.port(), 443);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    host: String,
    port: u16,
}

impl Target {
    /// Creates a new target with the specified host and port.
    /// 使用指定的主机和端口创建一个新目标。
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Returns the target host.
    /// 返回目标主机。
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the target port.
    /// 返回目标端口。
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Consumes the target and returns the host and port as a tuple.
    /// 消耗目标并以元组形式返回主机和端口。
    #[must_use]
    pub fn into_parts(self) -> (String, u16) {
        (self.host, self.port)
    }
}

/// Trait alias for async I/O streams used in protocol implementations.
/// 协议实现中使用的异步 I/O 流的 trait 别名。
///
/// Any type implementing `AsyncRead + AsyncWrite + Unpin + Send` automatically
/// implements this trait via blanket implementation.
/// 任何实现了 `AsyncRead + AsyncWrite + Unpin + Send` 的类型都会通过覆盖实现自动实现此 trait。
pub trait IoStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Trait for outbound connection establishment.
/// 用于建立出站连接的 trait。
///
/// Implementors provide protocol-specific logic to establish connections to remote targets.
/// 实现者提供特定于协议的逻辑来建立到远程目标的连接。
///
/// This is the key abstraction for the "Strategy Pattern" in protocol handling.
/// 这是协议处理中“策略模式”的关键抽象。
#[async_trait::async_trait]
pub trait OutboundConnector: Send + Sync {
    /// Establishes a connection to the specified target.
    /// 建立到指定目标的连接。
    ///
    /// # Errors
    /// Returns [`ProtoError`] if the connection cannot be established.
    /// 如果无法建立连接，则返回 [`ProtoError`]。
    async fn connect(&self, target: &Target) -> Result<Box<dyn IoStream>, ProtoError>;
}
