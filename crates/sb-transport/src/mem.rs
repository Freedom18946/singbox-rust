//! # Memory Transport Module / 内存传输模块
//!
//! This module provides a memory-pipe based dialer implementation, primarily used for:
//! 该模块提供基于内存管道的拨号器实现，主要用于：
//! - Mocking network connections in unit tests
//!   单元测试中模拟网络连接
//! - Network-less communication in integration tests
//!   集成测试中的无网络通信
//! - Local data stream testing in development environments
//!   开发环境中的本地数据流测试
//!
//! ## Design Philosophy / 设计理念
//! - **Zero Network**: Runs entirely in memory, involving no actual network I/O.
//!   **零网络**: 完全在内存中进行，不涉及实际网络 IO。
//! - **Bidirectional Communication**: Provides full-duplex communication based on `tokio::io::DuplexStream`.
//!   **双向通信**: 基于 `tokio::io::DuplexStream` 提供全双工通信。
//! - **One-time Use**: Each dialer instance can only connect once to prevent test state confusion.
//!   **一次性使用**: 每个拨号器实例只能连接一次，防止测试状态混乱。
//!
//! ## Thread Safety / 线程安全性
//! This module uses `std::sync::Mutex` to implement thread-safe interior mutability,
//! meeting the `Send + Sync` requirements of the `Dialer` trait. The implementation is fully safe and contains no unsafe code.
//! 该模块使用 `std::sync::Mutex` 来实现线程安全的内部可变性，
//! 满足 `Dialer` trait 的 `Send + Sync` 要求。实现完全安全，不包含 unsafe 代码。

use super::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use tokio::io::duplex;
use tokio::sync::Mutex;

/// Memory Duplex Dialer / 内存双工拨号器
///
/// This struct provides a memory-pipe based dialer implementation,
/// primarily used for mocking network connections in test scenarios.
/// 该结构体提供了一个基于内存管道的拨号器实现，
/// 主要用于测试场景中模拟网络连接。
///
/// ## How it works / 工作原理
/// This dialer internally holds a `tokio::io::DuplexStream`. When `connect` is called:
/// 该拨号器内部包含一个 `tokio::io::DuplexStream`，当调用 `connect` 方法时：
/// 1. Returns the internal DuplexStream as the connection result.
///    返回内部的 DuplexStream 作为连接结果。
/// 2. Sets the internal DuplexStream to None to prevent reuse.
///    将内部的 DuplexStream 设置为 None，防止重复使用。
/// 3. Subsequent `connect` calls will return a `NotSupported` error.
///    后续的 `connect` 调用将返回 `NotSupported` 错误。
///
/// ## Usage Pattern / 使用模式
/// Usually created via `new_pair()`, which returns:
/// 通常通过 `new_pair()` 创建，该方法返回：
/// - A `DuplexDialer` instance (as client)
///   一个 `DuplexDialer` 实例（作为客户端）
/// - A `DuplexStream` (as server)
///   一个 `DuplexStream`（作为服务端）
///
/// ## Thread Safety / 线程安全性
/// This implementation uses `std::sync::Mutex` to provide thread safety guarantees, meeting the
/// `Send + Sync` requirements of the `Dialer` trait. It can be safely used in multi-threaded environments.
/// 该实现使用 `std::sync::Mutex` 提供线程安全保证，满足 `Dialer` trait
/// 的 `Send + Sync` 要求。可以安全地在多线程环境中使用。
///
/// ## Limitations and Warnings / 限制和警告
/// - **One-time Use**: Each instance can only call `connect` once.
///   **一次性使用**: 每个实例只能调用一次 `connect`。
/// - **Testing Only**: Do not use in production environments.
///   **仅用于测试**: 禁止在生产环境中使用。
/// - **No Real Network**: Involves no actual network I/O operations.
///   **没有真实网络**: 不涉及实际的网络 IO 操作。
pub struct DuplexDialer {
    /// Internal client DuplexStream
    /// 内部的客户端 DuplexStream
    /// Uses Mutex<Option> to implement interior mutability and one-time consumption semantics
    /// 使用 Mutex<Option> 来实现内部可变性和一次性消费语义
    /// Initially Some, becomes None after connect is called
    /// 初始为 Some，调用 connect 后变为 None
    cli: Mutex<Option<tokio::io::DuplexStream>>,
}

impl DuplexDialer {
    /// Create a memory dialer and server stream pair
    /// 创建内存拨号器和服务端流对
    ///
    /// This method creates a complete memory communication pair, including:
    /// 该方法创建一个完整的内存通信对，包括：
    /// - A client dialer (returned `DuplexDialer`)
    ///   一个客户端拨号器（返回的 `DuplexDialer`）
    /// - A server stream (returned `DuplexStream`)
    ///   一个服务端流（返回的 `DuplexStream`）
    ///
    /// ## How it works / 工作原理
    /// 1. Creates a pair of memory pipes using `tokio::io::duplex()`.
    ///    使用 `tokio::io::duplex()` 创建一对内存管道。
    /// 2. Wraps one as a client in `DuplexDialer`.
    ///    将其中一个作为客户端封装在 `DuplexDialer` 中。
    /// 3. Returns the other directly as the server.
    ///    将另一个作为服务端直接返回。
    ///
    /// ## Buffer Size / 缓冲区大小
    /// Defaults to 4096 bytes internal buffer, which is sufficient for most test scenarios.
    /// Modify this constant if larger buffers are needed.
    /// 默认使用 4096 字节的内部缓冲区，这对于大多数测试场景都足够。
    /// 如需要更大的缓冲区，可以修改此常数。
    ///
    /// # Returns / 返回值
    /// Returns a tuple containing:
    /// 返回一个元组包含：
    /// - `DuplexDialer`: Client dialer, can call `connect` method.
    ///   `DuplexDialer`: 客户端拨号器，可以调用 `connect` 方法。
    /// - `DuplexStream`: Server stream, can be used directly for read/write operations.
    ///   `DuplexStream`: 服务端流，可以直接用于读写操作。
    ///
    /// # Example / 使用示例
    /// ```rust,no_run
    /// use sb_transport::mem::DuplexDialer;
    /// use tokio::io::{AsyncReadExt, AsyncWriteExt};
    /// use sb_transport::Dialer;
    ///
    /// #[tokio::test]
    /// async fn test_duplex_communication() {
    ///     let (dialer, mut server) = DuplexDialer::new_pair();
    ///
    ///     // Client connect
    ///     // 客户端连接
    ///     let mut client = dialer.connect("test", 0).await.unwrap();
    ///
    ///     // Bidirectional communication
    ///     // 双向通信
    ///     tokio::spawn(async move {
    ///         client.write_all(b"hello").await.unwrap();
    ///     });
    ///
    ///     let mut buf = [0u8; 5];
    ///     server.read_exact(&mut buf).await.unwrap();
    ///     assert_eq!(&buf, b"hello");
    /// }
    /// ```
    ///
    /// # Performance Characteristics / 性能特性
    /// - **Zero Latency**: Runs entirely in memory, no network latency.
    ///   **零延迟**: 完全在内存中运行，没有网络延迟。
    /// - **High Throughput**: Limited only by memory bandwidth and CPU performance.
    ///   **高吞吐**: 受限于内存带宽和 CPU 性能。
    /// - **Predictable**: No network jitter or packet loss issues.
    ///   **可预测**: 没有网络抖动和丢包问题。
    pub fn new_pair() -> (Self, tokio::io::DuplexStream) {
        // Create a pair of memory pipes, buffer size 4KB
        // This size is sufficient for most test scenarios
        // 创建一对内存管道，缓冲区大小为 4KB
        // 这个大小对于大多数测试场景都足够了
        let (a, b) = duplex(4096);

        // Return client dialer and server stream
        // 返回客户端拨号器和服务端流
        (
            Self {
                cli: Mutex::new(Some(a)),
            }, // Client wrapped in DuplexDialer / 客户端装在 DuplexDialer 中
            b, // Server returned directly / 服务端直接返回
        )
    }
}

#[async_trait]
impl Dialer for DuplexDialer {
    /// Simulate network connection and return memory stream
    /// 模拟网络连接并返回内存流
    ///
    /// This method implements the `Dialer` trait, but differs from a real network dialer:
    /// 该方法实现了 `Dialer` trait，但与真实的网络拨号器不同：
    /// - **Ignores Parameters**: host and port parameters are ignored as there is no actual network connection.
    ///   **忽略参数**: host 和 port 参数被忽略，因为没有实际网络连接。
    /// - **One-time Consumption**: Each instance can only be called once; subsequent calls return an error.
    ///   **一次性消费**: 每个实例只能调用一次，第二次调用将返回错误。
    /// - **Immediate Return**: Involves no actual network I/O, returns result immediately.
    ///   **立即返回**: 不涉及实际的网络 IO，立即返回结果。
    ///
    /// ## Thread-Safe Implementation / 线程安全实现
    /// Uses `std::sync::Mutex` to protect internal state, providing thread-safe interior mutability.
    /// This is a standard Rust pattern for modifying internal state in `&self` methods.
    /// 使用 `std::sync::Mutex` 保护内部状态，提供线程安全的内部可变性。
    /// 这是在 `&self` 方法中修改内部状态的标准 Rust 模式。
    ///
    /// ## Implementation Details / 实现细节
    /// Uses `Option::take()` to implement one-time consumption semantics:
    /// 使用 `Option::take()` 来实现一次性消费语义：
    /// - First call: `cli` is `Some`, returns internal DuplexStream.
    ///   第一次调用: `cli` 为 `Some`，返回内部的 DuplexStream。
    /// - Second call: `cli` is `None`, returns `NotSupported` error.
    ///   第二次调用: `cli` 为 `None`，返回 `NotSupported` 错误。
    ///
    /// # Parameters / 参数
    /// - `_host`: Ignored, as there is no actual network connection.
    ///   `_host`: 被忽略，因为没有实际网络连接。
    /// - `_port`: Ignored, as there is no actual network connection.
    ///   `_port`: 被忽略，因为没有实际网络连接。
    ///
    /// # Returns / 返回值
    /// - `Ok(IoStream)`: Returns internal DuplexStream on first call.
    ///   `Ok(IoStream)`: 第一次调用时返回内部的 DuplexStream。
    /// - `Err(DialError::NotSupported)`: On second and subsequent calls.
    ///   `Err(DialError::NotSupported)`: 第二次及以后的调用。
    ///
    /// # Usage Note / 使用注意
    /// - Use only in testing.
    ///   仅在测试中使用。
    /// - Call connect only once per instance (enforced via Option::take).
    ///   每个实例只调用一次 connect（通过 Option::take 强制）。
    async fn connect(&self, _host: &str, _port: u16) -> Result<IoStream, DialError> {
        // Use tokio::sync::Mutex for thread-safe interior mutability
        // This is a standard Rust pattern for modifying internal state in &self methods:
        // 1. Mutex provides thread-safe exclusive access
        // 2. Meets Dialer trait's Send + Sync requirements
        // 3. Implements one-time consumption semantics via Option::take
        // 使用 tokio::sync::Mutex 实现线程安全的内部可变性
        // 这是在 &self 方法中修改内部状态的标准 Rust 模式：
        // 1. Mutex 提供线程安全的互斥访问
        // 2. 满足 Dialer trait 的 Send + Sync 要求
        // 3. 通过 Option::take 实现一次性消费语义

        // Take DuplexStream from Mutex
        // tokio::sync::Mutex does not poison, so no need to handle poison cases
        // 从 Mutex 中取出 DuplexStream
        // tokio::sync::Mutex 不会 poison，因此无需处理 poison 情况
        let mut guard = self.cli.lock().await;
        let s = guard.take().ok_or(DialError::NotSupported)?;

        // Wrap DuplexStream as IoStream and return
        // 将 DuplexStream 包装为 IoStream 返回
        Ok(Box::new(s))
    }
}
