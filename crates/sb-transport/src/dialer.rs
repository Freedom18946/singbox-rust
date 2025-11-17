//! # 网络拨号器抽象模块
//!
//! 该模块定义了网络连接的核心抽象，包括：
//! - `DialError`: 拨号过程中可能出现的错误类型
//! - `Dialer` trait: 异步网络连接拨号器接口
//! - `TcpDialer`: 基础 TCP 连接拨号器实现
//! - `FnDialer`: 基于闭包的自定义拨号器
//! - `IoStream`: 统一的异步 IO 流类型别名

use crate::resource_pressure::{error_analysis, global_monitor};
use crate::retry::{retry_conditions, RetryPolicy};
use async_trait::async_trait;
use futures::future::{select_ok, FutureExt};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::debug;

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
    ///
    /// 注意：超时错误应使用 `Other("timeout")` 表示
    #[error("other: {0}")]
    Other(String),
}

/// 异步读写 trait 标记
///
/// 该 trait 是一个标记 trait，用于统一表示同时支持异步读取和写入的类型。
/// 所有满足以下条件的类型都会自动实现该 trait：
// - 实现 `tokio::io::AsyncRead`（异步读取）
// - 实现 `tokio::io::AsyncWrite`（异步写入）
// - 实现 `Unpin`（可安全移动）
// - 实现 `Send`（可在线程间传递）
// - 实现 `Sync`（可在线程间共享）
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// 为所有满足条件的类型自动实现 `AsyncReadWrite`
///
/// 这是一个 blanket implementation，意味着任何同时满足
/// AsyncRead + AsyncWrite + Unpin + Send + Sync 的类型都会自动获得该实现
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// 统一的异步 IO 流类型别名
///
/// 该类型是一个装箱的 trait object，用于在运行时处理不同类型的异步 IO 流。
/// 这种设计允许：
// - 统一处理不同底层实现的网络连接（TCP、TLS、内存管道等）
// - 在编译时擦除具体类型，提供灵活的接口
// - 支持动态分发，便于在不同传输类型之间切换
/// Boxed, thread-safe byte stream with a static lifetime
pub type IoStream = Box<dyn AsyncReadWrite + 'static>;

/// 异步网络拨号器 trait
///
/// 该 trait 定义了统一的网络连接建立接口。所有拨号器实现都必须：
// - 支持线程安全（`Send + Sync`）
// - 提供异步连接方法
// - 返回统一的 IoStream 或 DialError
///
/// ## 设计原则
// - **简单性**: 仅提供必要的连接抽象
// - **可扩展性**: 通过不同实现支持各种传输协议
// - **一致性**: 统一的错误处理和返回类型
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
    // - `host`: 目标主机名或 IP 地址
    // - `port`: 目标端口号
    ///
    /// # 返回值
    // - `Ok(IoStream)`: 成功建立的连接流
    // - `Err(DialError)`: 连接失败的具体错误
    ///
    /// # 错误处理
    /// 该方法可能返回以下错误：
    // - `DialError::Io`: 底层网络 IO 错误
    // - `DialError::Other`: 超时或其他通用错误
    // - `DialError::NotSupported`: 拨号器不支持该操作
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError>;
}

/// Allow using `Box<D>` where `D: Dialer` as a Dialer itself.
#[async_trait]
impl<D> Dialer for Box<D>
where
    D: Dialer + ?Sized,
{
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        (**self).connect(host, port).await
    }
}

/// 基础 TCP 拨号器
///
/// 这是最基本的拨号器实现，直接使用 tokio 的 `TcpStream` 建立 TCP 连接。
/// 该拨号器：
// - 不包含任何状态，因此可以安全地在多个地方复用
// - 直接映射到系统的 TCP 连接能力
// - 适用于大多数基础网络连接需求
///
/// ## 使用场景
// - 直接的 TCP 连接（如 HTTP、原始 TCP 代理）
// - 作为其他拨号器的底层传输（如 TLS 拨号器的内部实现）
// - 测试和开发环境中的简单连接需求
pub struct TcpDialer;

#[async_trait]
impl Dialer for TcpDialer {
    /// 建立 TCP 连接到指定的主机和端口
    ///
    /// 该实现支持 Happy Eyeballs (RFC 8305) 算法：
    // - 同时尝试 IPv6 和 IPv4 连接
    // - 交错发起连接尝试，IPv6 略早于 IPv4
    // - 使用环境变量控制行为：
    ///   - SB_HE_DISABLE=1: 禁用 Happy Eyeballs，回退到原始行为
    ///   - SB_HE_DELAY_MS: 设置 IPv4 延迟启动时间（默认 50ms）
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 检查是否禁用 Happy Eyeballs
        if std::env::var("SB_HE_DISABLE").is_ok_and(|v| v == "1") {
            debug!("Happy Eyeballs disabled, using traditional dial");
            let s = TcpStream::connect((host, port)).await?;
            return Ok(Box::new(s));
        }

        // 获取延迟配置
        let delay_ms = std::env::var("SB_HE_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50);
        let ipv4_delay = Duration::from_millis(delay_ms);

        debug!(
            "Starting Happy Eyeballs connection to {}:{}, IPv4 delay: {:?}",
            host, port, ipv4_delay
        );

        // DNS 解析获取所有地址
        let addrs: Vec<SocketAddr> = match lookup_host((host, port)).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => return Err(DialError::from(e)),
        };

        if addrs.is_empty() {
            return Err(DialError::Other("no addresses found".into()));
        }

        // 分离 IPv6 和 IPv4 地址
        let (ipv6_addrs, ipv4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());

        debug!(
            "Resolved {} IPv6 addresses, {} IPv4 addresses",
            ipv6_addrs.len(),
            ipv4_addrs.len()
        );

        // Happy Eyeballs 算法实现
        self.happy_eyeballs_connect(ipv6_addrs, ipv4_addrs, ipv4_delay)
            .await
    }
}

impl TcpDialer {
    /// Happy Eyeballs 连接算法实现
    ///
    /// 根据 RFC 8305，交错尝试 IPv6 和 IPv4 连接：
    /// 1. 立即开始第一个 IPv6 连接
    /// 2. 延迟后开始第一个 IPv4 连接
    /// 3. 继续交错其余地址
    /// 4. 返回第一个成功的连接，取消其余连接
    async fn happy_eyeballs_connect(
        &self,
        ipv6_addrs: Vec<SocketAddr>,
        ipv4_addrs: Vec<SocketAddr>,
        ipv4_delay: Duration,
    ) -> Result<IoStream, DialError> {
        // 如果没有任何地址，返回错误
        if ipv6_addrs.is_empty() && ipv4_addrs.is_empty() {
            return Err(DialError::Other("no addresses to connect".into()));
        }

        // 如果只有一种类型的地址，直接尝试连接
        if ipv6_addrs.is_empty() {
            debug!("IPv4-only connection attempt");
            return self.try_connect_addrs(&ipv4_addrs).await;
        }
        if ipv4_addrs.is_empty() {
            debug!("IPv6-only connection attempt");
            return self.try_connect_addrs(&ipv6_addrs).await;
        }

        // 双栈 Happy Eyeballs 算法
        debug!("Dual-stack Happy Eyeballs connection attempt");

        let cancel_token = CancellationToken::new();
        let mut connection_futures = Vec::new();

        // 立即启动第一个 IPv6 连接
        if let Some(addr) = ipv6_addrs.first() {
            let cancel_clone = cancel_token.clone();
            connection_futures.push(self.connect_with_cancellation(*addr, cancel_clone).boxed());
        }

        // 延迟启动第一个 IPv4 连接
        if let Some(addr) = ipv4_addrs.first() {
            let cancel_clone = cancel_token.clone();
            connection_futures.push(
                async move {
                    sleep(ipv4_delay).await;
                    self.connect_with_cancellation(*addr, cancel_clone).await
                }
                .boxed(),
            );
        }

        // 交错添加其余地址（简化版本：先 IPv6 后 IPv4）
        for addr in ipv6_addrs.iter().skip(1) {
            let cancel_clone = cancel_token.clone();
            connection_futures.push(self.connect_with_cancellation(*addr, cancel_clone).boxed());
        }

        for addr in ipv4_addrs.iter().skip(1) {
            let cancel_clone = cancel_token.clone();
            connection_futures.push(self.connect_with_cancellation(*addr, cancel_clone).boxed());
        }

        // 等待第一个成功的连接
        match select_ok(connection_futures).await {
            Ok((stream, _)) => {
                // 取消所有其他连接尝试
                cancel_token.cancel();
                debug!("Happy Eyeballs connection succeeded");
                Ok(stream)
            }
            Err(e) => {
                debug!("All Happy Eyeballs connection attempts failed: {}", e);
                Err(e)
            }
        }
    }

    /// 尝试连接地址列表中的第一个可用地址
    async fn try_connect_addrs(&self, addrs: &[SocketAddr]) -> Result<IoStream, DialError> {
        let mut last_error = DialError::Other("no addresses provided".into());

        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    debug!("Successfully connected to {}", addr);
                    return Ok(Box::new(stream));
                }
                Err(e) => {
                    debug!("Failed to connect to {}: {}", addr, e);
                    last_error = DialError::from(e);
                }
            }
        }

        Err(last_error)
    }

    /// 带取消支持的连接方法
    async fn connect_with_cancellation(
        &self,
        addr: SocketAddr,
        cancel_token: CancellationToken,
    ) -> Result<IoStream, DialError> {
        let connect_future = TcpStream::connect(addr);

        tokio::select! {
            result = connect_future => {
                match result {
                    Ok(stream) => {
                        debug!("Connection to {} succeeded", addr);
                        Ok(Box::new(stream))
                    }
                    Err(e) => {
                        debug!("Connection to {} failed: {}", addr, e);
                        Err(DialError::from(e))
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                debug!("Connection to {} cancelled", addr);
                Err(std::io::Error::new(std::io::ErrorKind::Interrupted, format!("connection to {}", addr)).into())
            }
        }
    }
}

/// TCP 拨号器，支持重试策略
///
/// 这是对 `TcpDialer` 的包装，添加了可配置的重试机制。
/// 对于幂等的连接操作（如初始TCP握手），可以通过环境变量启用重试。
pub struct RetryableTcpDialer {
    inner: TcpDialer,
    retry_policy: RetryPolicy,
}

impl Default for RetryableTcpDialer {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryableTcpDialer {
    /// 创建新的可重试TCP拨号器，从环境变量读取重试配置
    pub fn new() -> Self {
        Self {
            inner: TcpDialer,
            retry_policy: RetryPolicy::from_env(),
        }
    }

    /// 创建带指定重试策略的TCP拨号器
    pub fn with_policy(policy: RetryPolicy) -> Self {
        Self {
            inner: TcpDialer,
            retry_policy: policy,
        }
    }
}

#[async_trait]
impl Dialer for RetryableTcpDialer {
    /// 建立 TCP 连接，支持重试机制
    ///
    /// 对于连接建立这类幂等操作，如果启用了重试策略，
    /// 将在遇到临时网络错误时进行重试。
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        let host = host.to_string(); // Clone for closure

        self.retry_policy
            .execute(
                "tcp_connect",
                || {
                    let inner = &self.inner;
                    let host = host.as_str();
                    async move { inner.connect(host, port).await }
                },
                retry_conditions::is_retriable_error,
            )
            .await
    }
}

/// 资源压力感知的拨号器包装器
///
/// 此拨号器会检测资源压力（如文件描述符耗尽、内存不足）并采取相应的回退策略：
// - 自动检测资源压力相关错误
// - 在压力情况下应用节流延迟
// - 向管理界面暴露压力指标
pub struct ResourceAwareDialer<D: Dialer> {
    inner: D,
}

impl<D: Dialer + Clone> Clone for ResourceAwareDialer<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<D: Dialer> ResourceAwareDialer<D> {
    /// 创建新的资源感知拨号器
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync> Dialer for ResourceAwareDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 预先检查是否需要节流
        global_monitor()
            .throttle_if_needed(crate::resource_pressure::ResourceType::FileDescriptors)
            .await;

        let result = self.inner.connect(host, port).await;

        // 分析结果中的资源压力指示
        if let Err(ref error) = result {
            error_analysis::record_if_pressure_error(error).await;
        }

        result
    }
}

/// 基于闭包的自定义拨号器
///
/// 该拨号器允许通过闭包注入自定义的连接逻辑，非常适用于：
// - 单元测试中模拟各种网络行为
// - 开发环境中的连接调试和监控
// - 特殊场景下的连接定制（如连接池、负载均衡等）
// - admin 端点的只读示例构造
///
/// ## 类型参数
// - `F`: 闭包类型，必须满足复杂的约束以支持异步操作
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
pub struct FnDialer<F> {
    inner: std::sync::Arc<F>,
}

impl<F> Clone for FnDialer<F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[async_trait]
impl<F> Dialer for FnDialer<F>
where
    F: Send
        + Sync
        + Fn(
            &str,
            u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<IoStream, DialError>> + Send + 'static>,
        >,
{
    /// 调用内部闭包执行自定义连接逻辑
    ///
    /// 该方法简单地将调用委托给内部的闭包函数，
    /// 允许完全自定义的连接行为。
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 调用闭包并等待其返回的 Future 完成
        (self.inner)(host, port).await
    }
}

impl<F> FnDialer<F> {
    /// 创建新的函数拨号器
    ///
    /// R69: 便于 admin 端点构造只读示例
    ///
    /// # 参数
    // - `f`: 实现拨号逻辑的闭包函数
    ///
    /// # 返回值
    /// 包装了给定闭包的 `FnDialer` 实例
    ///
    /// ## 使用场景
    // - 测试中注入模拟连接行为
    // - 特殊网络环境的连接定制
    // - 连接监控和调试
    pub fn new(f: F) -> Self {
        Self {
            inner: std::sync::Arc::new(f),
        }
    }
}

/// 兼容性转换：将 tokio 超时错误统一映射为 DialError
///
/// 这个实现确保了整个传输层对超时错误的一致处理：
// - 将 `tokio::time::error::Elapsed` 转换为 `DialError::Other("timeout")`
// - 避免使用已弃用的 `DialError::Timeout`
// - 与 util 模块的超时处理策略保持一致
///
/// ## 设计理由
/// 使用字符串 "timeout" 而不是专门的枚举变体：
// - 保持错误类型的简洁性
// - 便于日志记录和调试
// - 与现有的错误处理模式一致
impl From<tokio::time::error::Elapsed> for DialError {
    /// 将 tokio 超时错误转换为标准化的拨号错误
    ///
    /// # 参数
    // - `_`: tokio 的超时错误（具体内容被忽略）
    ///
    /// # 返回值
    /// 标准化的 `DialError::Other("timeout")` 错误
    fn from(_: tokio::time::error::Elapsed) -> Self {
        DialError::Other("timeout".into())
    }
}

// Note: Mapping to sb-core's SbError is intentionally removed to avoid
// circular dependencies. sb-core can provide its own `From<DialError>`
// implementation in its crate if needed.

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
    // - 内存中的双向通信管道
    // - 测试中模拟网络连接
    // - 进程间或任务间的数据传递
    ///
    /// 注意：该类型当前未被使用，但保留以备将来扩展
    #[allow(dead_code)]
    pub type DuplexStream = tokio::io::DuplexStream;

    /// 编译时类型约束检查函数
    ///
    /// 该函数用于在编译时验证类型是否满足 AsyncReadWrite 的要求，
    /// 包括：
    // - `AsyncRead`: 支持异步读取
    // - `AsyncWrite`: 支持异步写入
    // - `Unpin`: 可以安全地在内存中移动
    // - `Send`: 可以在线程间传递
    // - `'static`: 具有静态生命周期
    ///
    /// # 参数
    // - `_`: 要检查的类型的引用（参数被忽略，仅用于类型推断）
    ///
    /// # 用途
    // - 编译时类型验证
    // - 确保类型满足 IoStream 的要求
    // - 测试和开发中的类型检查
    #[allow(dead_code)]
    pub fn is_async_read_write<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(_: &T) {}
}
