//! # 内存传输模块
//!
//! 该模块提供基于内存管道的拨号器实现，主要用于：
//! - 单元测试中模拟网络连接
//! - 集成测试中的无网络通信
//! - 开发环境中的本地数据流测试
//!
//! R75: 内存拨号器（Duplex）用于无网络测试
//!
//! ## 设计理念
//! - **零网络**: 完全在内存中进行，不涉及实际网络 IO
//! - **双向通信**: 基于 tokio::io::DuplexStream 提供全双工通信
//! - **一次性使用**: 每个拨号器实例只能连接一次，防止测试状态混乱
//!
//! ## 安全性注意
//! 该模块中使用了 `unsafe` 代码来实现内部可变性，
//! 这是为了在保持 `Dialer` trait 的 `&self` 约束下实现一次性消费。
//! 在实际使用中，请确保不要并发调用同一个实例的 `connect` 方法。

use super::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use std::sync::Mutex;
use tokio::io::duplex;

/// 内存双工拨号器
///
/// 该结构体提供了一个基于内存管道的拨号器实现，
/// 主要用于测试场景中模拟网络连接。
///
/// ## 工作原理
/// 该拨号器内部包含一个 `tokio::io::DuplexStream`，当调用 `connect` 方法时：
/// 1. 返回内部的 DuplexStream 作为连接结果
/// 2. 将内部的 DuplexStream 设置为 None，防止重复使用
/// 3. 后续的 `connect` 调用将返回 `NotSupported` 错误
///
/// ## 使用模式
/// 通常通过 `new_pair()` 创建，该方法返回：
/// - 一个 `DuplexDialer` 实例（作为客户端）
/// - 一个 `DuplexStream`（作为服务端）
///
/// ## 线程安全性
/// ⚠️ **重要**: 该实现使用了 `unsafe` 代码，不是线程安全的。
/// 在测试中应避免：
/// - 并发调用同一个实例的 `connect` 方法
/// - 在多个线程中同时使用同一个实例
///
/// ## 限制和警告
/// - **一次性使用**: 每个实例只能调用一次 `connect`
/// - **仅用于测试**: 禁止在生产环境中使用
/// - **没有真实网络**: 不涉及实际的网络 IO 操作
pub struct DuplexDialer {
    /// 内部的客户端 DuplexStream
    /// 使用 Mutex<Option> 来实现内部可变性和一次性消费语义
    /// 初始为 Some，调用 connect 后变为 None
    cli: Mutex<Option<tokio::io::DuplexStream>>,
}

impl DuplexDialer {
    /// 创建内存拨号器和服务端流对
    ///
    /// 该方法创建一个完整的内存通信对，包括：
    /// - 一个客户端拨号器（返回的 `DuplexDialer`）
    /// - 一个服务端流（返回的 `DuplexStream`）
    ///
    /// ## 工作原理
    /// 1. 使用 `tokio::io::duplex()` 创建一对内存管道
    /// 2. 将其中一个作为客户端封装在 `DuplexDialer` 中
    /// 3. 将另一个作为服务端直接返回
    ///
    /// ## 缓冲区大小
    /// 默认使用 4096 字节的内部缓冲区，这对于大多数测试场景都足够。
    /// 如需要更大的缓冲区，可以修改此常数。
    ///
    /// # 返回值
    /// 返回一个元组包含：
    /// - `DuplexDialer`: 客户端拨号器，可以调用 `connect` 方法
    /// - `DuplexStream`: 服务端流，可以直接用于读写操作
    ///
    /// # 使用示例
    /// ```rust,no_run
    /// use sb_transport::DuplexDialer;
    /// use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ///
    /// #[tokio::test]
    /// async fn test_duplex_communication() {
    ///     let (dialer, mut server) = DuplexDialer::new_pair();
    ///
    ///     // 客户端连接
    ///     let mut client = dialer.connect("test", 0).await.unwrap();
    ///
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
    /// # 性能特性
    /// - **零延迟**: 完全在内存中运行，没有网络延迟
    /// - **高吞吐**: 受限于内存带宽和 CPU 性能
    /// - **可预测**: 没有网络抖动和丢包问题
    pub fn new_pair() -> (Self, tokio::io::DuplexStream) {
        // 创建一对内存管道，缓冲区大小为 4KB
        // 这个大小对于大多数测试场景都足够了
        let (a, b) = duplex(4096);

        // 返回客户端拨号器和服务端流
        (
            Self {
                cli: Mutex::new(Some(a)),
            }, // 客户端装在 DuplexDialer 中
            b, // 服务端直接返回
        )
    }
}

#[async_trait]
impl Dialer for DuplexDialer {
    /// 模拟网络连接并返回内存流
    ///
    /// 该方法实现了 `Dialer` trait，但与真实的网络拨号器不同：
    /// - **忽略参数**: host 和 port 参数被忽略，因为没有实际网络连接
    /// - **一次性消费**: 每个实例只能调用一次，第二次调用将返回错误
    /// - **立即返回**: 不涉及实际的网络 IO，立即返回结果
    ///
    /// ## 安全性警告
    /// ⚠️ 该实现使用了 `unsafe` 代码来绕过 Rust 的借用检查器，
    /// 实现在 `&self` 上的内部可变性。这在理论上是不安全的，但在
    /// 测试场景中是可接受的，因为：
    /// 1. 测试通常是单线程的
    /// 2. 每个测试实例都是独立的
    /// 3. 不会出现并发访问的情况
    ///
    /// ## 实现细节
    /// 使用 `Option::take()` 来实现一次性消费语义：
    /// - 第一次调用: `cli` 为 `Some`，返回内部的 DuplexStream
    /// - 第二次调用: `cli` 为 `None`，返回 `NotSupported` 错误
    ///
    /// # 参数
    /// - `_host`: 被忽略，因为没有实际网络连接
    /// - `_port`: 被忽略，因为没有实际网络连接
    ///
    /// # 返回值
    /// - `Ok(IoStream)`: 第一次调用时返回内部的 DuplexStream
    /// - `Err(DialError::NotSupported)`: 第二次及以后的调用
    ///
    /// # 使用注意
    /// - 仅在测试中使用
    /// - 避免并发调用
    /// - 每个实例只调用一次 connect
    async fn connect(&self, _host: &str, _port: u16) -> Result<IoStream, DialError> {
        // 使用 Mutex 来实现内部可变性和线程安全
        // 这是处理在 &self 方法中需要修改内部状态的安全方式
        //
        // 使用说明：
        // 1. Mutex 提供线程安全的互斥访问
        // 2. 满足 Dialer trait 的 Send + Sync 要求
        // 3. 每个 DuplexDialer 实例只使用一次

        // 从 Mutex 中取出 DuplexStream
        let s = self
            .cli
            .lock()
            .unwrap()
            .take()
            .ok_or(DialError::NotSupported)?;

        // 将 DuplexStream 包装为 IoStream 返回
        Ok(Box::new(s))
    }
}
