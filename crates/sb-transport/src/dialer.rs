//! # 网络拨号器抽象模块
//!
//! 该模块定义了网络连接的核心抽象，包括：
//! - `DialError`: 拨号过程中可能出现的错误类型
//! - `Dialer` trait: 异步网络连接拨号器接口
//! - `TcpDialer`: 基础 TCP 连接拨号器实现
//! - `FnDialer`: 基于闭包的自定义拨号器
//! - `IoStream`: 统一的异步 IO 流类型别名

use async_trait::async_trait;
use thiserror::Error;

/// 拨号过程中可能出现的错误类型
///
/// 该枚举统一了所有拨号操作可能遇到的错误情况，
/// 提供清晰的错误分类和转换机制
#[derive(Debug, Error)]
pub enum DialError {
    /// IO 错误：底层网络 IO 操作失败
    /// 自动从 `std::io::Error` 转换而来
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// TLS 错误：TLS 握手或配置错误
    /// 包含具体的错误描述信息
    #[error("tls: {0}")]
    Tls(String),

    /// 不支持的操作：当前拨号器不支持请求的操作
    #[error("not supported")]
    NotSupported,

    /// 其他错误：通用错误类型，包含具体错误描述
    /// 用于处理不属于上述分类的错误情况
    #[error("other: {0}")]
    Other(String),

    /// 超时错误（已弃用）
    ///
    /// 注意：请使用 `Other("timeout")` 代替
    /// util 模块会自动将超时映射为 `Other("timeout")`
    #[deprecated(
        note = "use Other(\"timeout\") instead; util maps timeouts to Other(\"timeout\")"
    )]
    #[error("timeout")]
    Timeout,
}

/// 异步读写 trait 标记
///
/// 该 trait 是一个标记 trait，用于统一表示同时支持异步读取和写入的类型。
/// 所有满足以下条件的类型都会自动实现该 trait：
/// - 实现 `tokio::io::AsyncRead`（异步读取）
/// - 实现 `tokio::io::AsyncWrite`（异步写入）
/// - 实现 `Unpin`（可安全移动）
/// - 实现 `Send`（可在线程间传递）
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// 为所有满足条件的类型自动实现 `AsyncReadWrite`
///
/// 这是一个 blanket implementation，意味着任何同时满足
/// AsyncRead + AsyncWrite + Unpin + Send 的类型都会自动获得该实现
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// 统一的异步 IO 流类型别名
///
/// 该类型是一个装箱的 trait object，用于在运行时处理不同类型的异步 IO 流。
/// 这种设计允许：
/// - 统一处理不同底层实现的网络连接（TCP、TLS、内存管道等）
/// - 在编译时擦除具体类型，提供灵活的接口
/// - 支持动态分发，便于在不同传输类型之间切换
pub type IoStream = Box<dyn AsyncReadWrite>;

/// 异步网络拨号器 trait
///
/// 该 trait 定义了统一的网络连接建立接口。所有拨号器实现都必须：
/// - 支持线程安全（`Send + Sync`）
/// - 提供异步连接方法
/// - 返回统一的 IoStream 或 DialError
///
/// ## 设计原则
/// - **简单性**: 仅提供必要的连接抽象
/// - **可扩展性**: 通过不同实现支持各种传输协议
/// - **一致性**: 统一的错误处理和返回类型
///
/// ## 使用示例
/// ```rust,no_run
/// use sb_transport::{Dialer, TcpDialer};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let dialer = TcpDialer;
///     let stream = dialer.connect("example.com", 80).await?;
///     // 使用 stream 进行通信...
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait Dialer: Send + Sync {
    /// 建立到指定主机和端口的连接
    ///
    /// # 参数
    /// - `host`: 目标主机名或 IP 地址
    /// - `port`: 目标端口号
    ///
    /// # 返回值
    /// - `Ok(IoStream)`: 成功建立的连接流
    /// - `Err(DialError)`: 连接失败的具体错误
    ///
    /// # 错误处理
    /// 该方法可能返回以下错误：
    /// - `DialError::Io`: 底层网络 IO 错误
    /// - `DialError::Other`: 超时或其他通用错误
    /// - `DialError::NotSupported`: 拨号器不支持该操作
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError>;
}

/// 基础 TCP 拨号器
///
/// 这是最基本的拨号器实现，直接使用 tokio 的 `TcpStream` 建立 TCP 连接。
/// 该拨号器：
/// - 不包含任何状态，因此可以安全地在多个地方复用
/// - 直接映射到系统的 TCP 连接能力
/// - 适用于大多数基础网络连接需求
///
/// ## 使用场景
/// - 直接的 TCP 连接（如 HTTP、原始 TCP 代理）
/// - 作为其他拨号器的底层传输（如 TLS 拨号器的内部实现）
/// - 测试和开发环境中的简单连接需求
pub struct TcpDialer;

#[async_trait]
impl Dialer for TcpDialer {
    /// 建立 TCP 连接到指定的主机和端口
    ///
    /// 该实现直接使用 `tokio::net::TcpStream::connect` 进行连接，
    /// 支持以下特性：
    /// - 自动 DNS 解析（支持域名和 IP 地址）
    /// - 异步非阻塞连接
    /// - 自动错误转换（将 IO 错误转换为 DialError::Io）
    ///
    /// # 网络行为
    /// - 使用系统默认的 TCP 连接超时
    /// - 遵循系统 DNS 配置进行域名解析
    /// - 支持 IPv4 和 IPv6（取决于系统配置）
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 使用 tokio 的异步 TCP 连接
        // (host, port) 元组会自动处理 DNS 解析
        let s = tokio::net::TcpStream::connect((host, port)).await?;

        // 将具体的 TcpStream 装箱为通用的 IoStream
        // 这允许调用者统一处理不同类型的连接
        Ok(Box::new(s))
    }
}

/// 基于闭包的自定义拨号器
///
/// 该拨号器允许通过闭包注入自定义的连接逻辑，非常适用于：
/// - 单元测试中模拟各种网络行为
/// - 开发环境中的连接调试和监控
/// - 特殊场景下的连接定制（如连接池、负载均衡等）
/// - admin 端点的只读示例构造
///
/// ## 类型参数
/// - `F`: 闭包类型，必须满足复杂的约束以支持异步操作
///
/// ## 设计考虑
/// 该拨号器使用了类型擦除的设计，闭包返回装箱的 Future，
/// 这虽然增加了一些运行时开销，但提供了最大的灵活性。
///
/// ## 使用示例
/// ```rust,no_run
/// use sb_transport::{FnDialer, IoStream, DialError};
/// use std::pin::Pin;
/// use std::future::Future;
///
/// let mock_dialer = FnDialer::new(|host, port| {
///     Box::pin(async move {
///         // 自定义连接逻辑
///         println!("连接到 {}:{}", host, port);
///         Err(DialError::NotSupported)
///     }) as Pin<Box<dyn Future<Output = Result<IoStream, DialError>> + Send>>
/// });
/// ```
pub struct FnDialer<F>(pub F);

#[async_trait]
impl<F> Dialer for FnDialer<F>
where
    F: Send
        + Sync
        + Fn(
            &str,
            u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<IoStream, DialError>> + Send>,
        >,
{
    /// 调用内部闭包执行自定义连接逻辑
    ///
    /// 该方法简单地将调用委托给内部的闭包函数，
    /// 允许完全自定义的连接行为。
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 调用闭包并等待其返回的 Future 完成
        (self.0)(host, port).await
    }
}

impl<F> FnDialer<F> {
    /// 创建新的函数拨号器
    ///
    /// R69: 便于 admin 端点构造只读示例
    ///
    /// # 参数
    /// - `f`: 实现拨号逻辑的闭包函数
    ///
    /// # 返回值
    /// 包装了给定闭包的 `FnDialer` 实例
    ///
    /// ## 使用场景
    /// - 测试中注入模拟连接行为
    /// - 特殊网络环境的连接定制
    /// - 连接监控和调试
    pub fn new(f: F) -> Self {
        Self(f)
    }
}

/// 兼容性转换：将 tokio 超时错误统一映射为 DialError
///
/// 这个实现确保了整个传输层对超时错误的一致处理：
/// - 将 `tokio::time::error::Elapsed` 转换为 `DialError::Other("timeout")`
/// - 避免使用已弃用的 `DialError::Timeout`
/// - 与 util 模块的超时处理策略保持一致
///
/// ## 设计理由
/// 使用字符串 "timeout" 而不是专门的枚举变体：
/// - 保持错误类型的简洁性
/// - 便于日志记录和调试
/// - 与现有的错误处理模式一致
impl From<tokio::time::error::Elapsed> for DialError {
    /// 将 tokio 超时错误转换为标准化的拨号错误
    ///
    /// # 参数
    /// - `_`: tokio 的超时错误（具体内容被忽略）
    ///
    /// # 返回值
    /// 标准化的 `DialError::Other("timeout")` 错误
    fn from(_: tokio::time::error::Elapsed) -> Self {
        DialError::Other("timeout".into())
    }
}

// Bridge mapping to unified SbError in sb-core without changing public API.
impl From<DialError> for sb_core::error::SbError {
    fn from(e: DialError) -> Self {
        match e {
            DialError::Io(ioe) => sb_core::error::SbError::io(ioe),
            DialError::Tls(msg) => sb_core::error::SbError::other(format!("tls: {}", msg)),
            DialError::NotSupported => sb_core::error::SbError::other("not supported"),
            #[allow(deprecated)]
            DialError::Timeout => sb_core::error::SbError::Timeout { operation: "dial".into(), timeout_ms: 0 },
            DialError::Other(msg) => sb_core::error::SbError::other(msg),
        }
    }
}

/// 私有 IO 工具模块
///
/// 该模块包含一些内部使用的 IO 相关类型和工具函数，
/// 主要用于类型检查和内部测试。
pub(crate) mod priv_io {
    use tokio::io::{AsyncRead, AsyncWrite};

    /// tokio DuplexStream 的类型别名
    ///
    /// 该类型别名将 tokio 的双工流类型暴露为 IoStream 的实现者，
    /// 主要用于：
    /// - 内存中的双向通信管道
    /// - 测试中模拟网络连接
    /// - 进程间或任务间的数据传递
    ///
    /// 注意：该类型当前未被使用，但保留以备将来扩展
    #[allow(dead_code)]
    pub type DuplexStream = tokio::io::DuplexStream;

    /// 编译时类型约束检查函数
    ///
    /// 该函数用于在编译时验证类型是否满足 AsyncReadWrite 的要求，
    /// 包括：
    /// - `AsyncRead`: 支持异步读取
    /// - `AsyncWrite`: 支持异步写入
    /// - `Unpin`: 可以安全地在内存中移动
    /// - `Send`: 可以在线程间传递
    /// - `'static`: 具有静态生命周期
    ///
    /// # 参数
    /// - `_`: 要检查的类型的引用（参数被忽略，仅用于类型推断）
    ///
    /// # 用途
    /// - 编译时类型验证
    /// - 确保类型满足 IoStream 的要求
    /// - 测试和开发中的类型检查
    #[allow(dead_code)]
    pub fn is_async_read_write<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(_: &T) {}
}
