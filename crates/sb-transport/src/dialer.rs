//! # Network Dialer Abstraction Module / 网络拨号器抽象模块
//!
//! This module defines the core abstractions for network connections, including:
//! 该模块定义了网络连接的核心抽象，包括：
//! - `DialError`: Errors that may occur during dialing / 拨号过程中可能出现的错误类型
//! - `Dialer` trait: Asynchronous network connection dialer interface / 异步网络连接拨号器接口
//! - `TcpDialer`: Basic TCP connection dialer implementation / 基础 TCP 连接拨号器实现
//! - `FnDialer`: Closure-based custom dialer / 基于闭包的自定义拨号器
//! - `IoStream`: Unified asynchronous IO stream type alias / 统一的异步 IO 流类型别名
//!
//! ## Strategic Relevance / 战略关联
//! - **Polymorphism**: The `Dialer` trait allows switching between different transport implementations
//!   (TCP, TLS, WebSocket, etc.) at runtime without changing the upper-layer logic.
//!   **多态性**：`Dialer` trait 允许在运行时在不同的传输实现（TCP, TLS, WebSocket 等）之间切换，
//!   而无需更改上层逻辑。
//! - **Type Erasure**: `IoStream` uses `Box<dyn AsyncReadWrite>` to erase the specific type of the
//!   underlying connection, simplifying the type signature of the entire system.
//!   **类型擦除**：`IoStream` 使用 `Box<dyn AsyncReadWrite>` 擦除底层连接的具体类型，
//!   简化了整个系统的类型签名。

use crate::resource_pressure::{error_analysis, global_monitor};
use crate::retry::{retry_conditions, RetryPolicy};
use async_trait::async_trait;
use futures::future::{select_ok, FutureExt};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::{lookup_host, TcpStream};
#[cfg(target_os = "android")]
use tokio::net::TcpSocket;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Errors that may occur during dialing
/// 拨号过程中可能出现的错误类型
///
/// This enum unifies all error conditions that may be encountered during dialing,
/// providing clear error classification and conversion mechanisms.
/// 该枚举统一了所有拨号操作可能遇到的错误情况，
/// 提供清晰的错误分类和转换机制
#[derive(Debug, Error)]
pub enum DialError {
    /// IO Error: Underlying network IO operation failed
    /// IO 错误：底层网络 IO 操作失败
    /// Automatically converted from `std::io::Error`
    /// 自动从 `std::io::Error` 转换而来
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// TLS Error: TLS handshake or configuration error
    /// TLS 错误：TLS 握手或配置错误
    /// Contains specific error description
    /// 包含具体的错误描述信息
    #[error("tls: {0}")]
    Tls(String),

    /// Operation not supported: The current dialer does not support the requested operation
    /// 不支持的操作：当前拨号器不支持请求的操作
    #[error("not supported")]
    NotSupported,

    /// Other Error: Generic error type containing specific description
    /// 其他错误：通用错误类型，包含具体错误描述
    /// Used for handling error conditions not belonging to the above categories
    /// 用于处理不属于上述分类的错误情况
    ///
    /// Note: Timeout errors should be represented using `Other("timeout")`
    /// 注意：超时错误应使用 `Other("timeout")` 表示
    #[error("other: {0}")]
    Other(String),
}

/// Async Read/Write Trait Marker
/// 异步读写 trait 标记
///
/// This trait is a marker trait used to unify types that support both asynchronous reading and writing.
/// 该 trait 是一个标记 trait，用于统一表示同时支持异步读取和写入的类型。
/// All types meeting the following conditions automatically implement this trait:
/// 所有满足以下条件的类型都会自动实现该 trait：
// - Implement `tokio::io::AsyncRead` (Async Read) / 实现 `tokio::io::AsyncRead`（异步读取）
// - Implement `tokio::io::AsyncWrite` (Async Write) / 实现 `tokio::io::AsyncWrite`（异步写入）
// - Implement `Unpin` (Safe to move) / 实现 `Unpin`（可安全移动）
// - Implement `Send` (Transferable across threads) / 实现 `Send`（可在线程间传递）
// - Implement `Sync` (Shareable across threads) / 实现 `Sync`（可在线程间共享）
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Automatically implement `AsyncReadWrite` for all types meeting the conditions
/// 为所有满足条件的类型自动实现 `AsyncReadWrite`
///
/// This is a blanket implementation, meaning any type that satisfies
/// AsyncRead + AsyncWrite + Unpin + Send + Sync will automatically receive this implementation.
/// 这是一个 blanket implementation，意味着任何同时满足
/// AsyncRead + AsyncWrite + Unpin + Send + Sync 的类型都会自动获得该实现
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Unified Async IO Stream Type Alias
/// 统一的异步 IO 流类型别名
///
/// This type is a boxed trait object used to handle different types of async IO streams at runtime.
/// 该类型是一个装箱的 trait object，用于在运行时处理不同类型的异步 IO 流。
/// This design allows:
/// 这种设计允许：
// - Unified handling of network connections with different underlying implementations (TCP, TLS, memory pipes, etc.)
//   统一处理不同底层实现的网络连接（TCP、TLS、内存管道等）
// - Type erasure at compile time, providing a flexible interface
//   在编译时擦除具体类型，提供灵活的接口
// - Dynamic dispatch, facilitating switching between different transport types
//   支持动态分发，便于在不同传输类型之间切换
/// Boxed, thread-safe byte stream with a static lifetime
pub type IoStream = Box<dyn AsyncReadWrite + 'static>;

/// Async Network Dialer Trait
/// 异步网络拨号器 trait
///
/// This trait defines a unified interface for establishing network connections. All dialer implementations must:
/// 该 trait 定义了统一的网络连接建立接口。所有拨号器实现都必须：
// - Be thread-safe (`Send + Sync`) / 支持线程安全（`Send + Sync`）
// - Provide an async connect method / 提供异步连接方法
// - Return a unified IoStream or DialError / 返回统一的 IoStream 或 DialError
///
/// ## Design Principles / 设计原则
// - **Simplicity**: Provide only necessary connection abstractions / **简单性**: 仅提供必要的连接抽象
// - **Extensibility**: Support various transport protocols through different implementations / **可扩展性**: 通过不同实现支持各种传输协议
// - **Consistency**: Unified error handling and return types / **一致性**: 统一的错误处理和返回类型
///
/// ## Usage Example / 使用示例
/// ```rust,no_run
/// use sb_transport::{Dialer, TcpDialer};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let dialer = TcpDialer::default();
///     let stream = dialer.connect("example.com", 80).await?;
///     // Use stream for communication... / 使用 stream 进行通信...
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait Dialer: Send + Sync {
    /// Establish a connection to the specified host and port
    /// 建立到指定主机和端口的连接
    ///
    /// # Parameters / 参数
    // - `host`: Target hostname or IP address / 目标主机名或 IP 地址
    // - `port`: Target port number / 目标端口号
    ///
    /// # Returns / 返回值
    // - `Ok(IoStream)`: Successfully established connection stream / 成功建立的连接流
    // - `Err(DialError)`: Specific error for connection failure / 连接失败的具体错误
    ///
    /// # Error Handling / 错误处理
    /// This method may return the following errors:
    /// 该方法可能返回以下错误：
    // - `DialError::Io`: Underlying network IO error / 底层网络 IO 错误
    // - `DialError::Other`: Timeout or other generic errors / 超时或其他通用错误
    // - `DialError::NotSupported`: Dialer does not support this operation / 拨号器不支持该操作
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError>;

    /// Downcast to Any to allow modifying specific dialer implementations
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
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

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        (**self).as_any_mut()
    }
}

/// Basic TCP Dialer / 基础 TCP 拨号器
///
/// This is the most basic dialer implementation, directly using tokio's `TcpStream` to establish TCP connections.
/// 这是最基本的拨号器实现，直接使用 tokio 的 `TcpStream` 建立 TCP 连接。
/// This dialer:
/// 该拨号器：
// - Has no state, so it can be safely reused in multiple places / 不包含任何状态，因此可以安全地在多个地方复用
// - Maps directly to the system's TCP connection capabilities / 直接映射到系统的 TCP 连接能力
// - Suitable for most basic network connection needs / 适用于大多数基础网络连接需求
///
/// ## Usage Scenarios / 使用场景
// - Direct TCP connections (e.g., HTTP, raw TCP proxies) / 直接的 TCP 连接（如 HTTP、原始 TCP 代理）
// - As underlying transport for other dialers (e.g., internal implementation of TLS dialer) / 作为其他拨号器的底层传输（如 TLS 拨号器的内部实现）
// - Simple connection needs in test and development environments / 测试和开发环境中的简单连接需求
#[derive(Default)]
pub struct TcpDialer {
    pub bind_interface: Option<String>,
    pub bind_v4: Option<std::net::Ipv4Addr>,
    pub bind_v6: Option<std::net::Ipv6Addr>,
    pub routing_mark: Option<u32>,
    pub reuse_addr: bool,
    pub connect_timeout: Option<Duration>,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub udp_fragment: bool,
}

#[async_trait]
impl Dialer for TcpDialer {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    /// Establish a TCP connection to the specified host and port
    /// 建立 TCP 连接到指定的主机和端口
    ///
    /// This implementation supports the Happy Eyeballs (RFC 8305) algorithm:
    /// 该实现支持 Happy Eyeballs (RFC 8305) 算法：
    // - Attempt IPv6 and IPv4 connections simultaneously / 同时尝试 IPv6 和 IPv4 连接
    // - Stagger connection attempts, IPv6 slightly earlier than IPv4 / 交错发起连接尝试，IPv6 略早于 IPv4
    // - Control behavior using environment variables: / 使用环境变量控制行为：
    ///   - SB_HE_DISABLE=1: Disable Happy Eyeballs, fall back to original behavior / 禁用 Happy Eyeballs，回退到原始行为
    ///   - SB_HE_DELAY_MS: Set IPv4 delay start time (default 50ms) / 设置 IPv4 延迟启动时间（默认 50ms）
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // Note: Configuration fields are currently ignored in this basic implementation
        // except for potential future use or if we plumb them into socket setup.
        // For now, we just keep the existing logic but allow fields to be set.
        // TODO: Plumb bind_interface, etc. into socket creation.

        // 检查是否禁用 Happy Eyeballs
        if std::env::var("SB_HE_DISABLE").is_ok_and(|v| v == "1") {
            debug!("Happy Eyeballs disabled, using traditional dial");
            let addrs = lookup_host((host, port)).await?.collect::<Vec<_>>();
            return self.try_connect_addrs(&addrs).await;
        }

        // 获取延迟配置
        let delay_ms = std::env::var("SB_HE_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50);
        let mut ipv4_delay = Duration::from_millis(delay_ms);

        // Apply optional network strategy (prefer ipv4/ipv6 or only one stack)
        let strategy = std::env::var("SB_NETWORK_STRATEGY")
            .unwrap_or_default()
            .to_ascii_lowercase();

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
        let (mut ipv6_addrs, mut ipv4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());

        match strategy.as_str() {
            "ipv4_only" => {
                ipv6_addrs.clear();
                ipv4_delay = Duration::from_millis(0);
            }
            "ipv6_only" => {
                ipv4_addrs.clear();
            }
            "prefer_ipv4" => {
                // Swap lists so IPv4 is treated as the preferred family
                std::mem::swap(&mut ipv6_addrs, &mut ipv4_addrs);
                ipv4_delay = Duration::from_millis(0);
            }
            // prefer_ipv6 or empty => keep defaults
            _ => {}
        }

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
    /// Happy Eyeballs connection algorithm implementation
    /// Happy Eyeballs 连接算法实现
    ///
    /// According to RFC 8305, stagger attempts for IPv6 and IPv4 connections:
    /// 根据 RFC 8305，交错尝试 IPv6 和 IPv4 连接：
    /// 1. Start the first IPv6 connection immediately / 立即开始第一个 IPv6 连接
    /// 2. Start the first IPv4 connection after a delay / 延迟后开始第一个 IPv4 连接
    /// 3. Continue staggering the remaining addresses / 继续交错其余地址
    /// 4. Return the first successful connection, cancel the rest / 返回第一个成功的连接，取消其余连接
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

    /// Try to connect to the first available address in the list
    /// 尝试连接地址列表中的第一个可用地址
    async fn try_connect_addrs(&self, addrs: &[SocketAddr]) -> Result<IoStream, DialError> {
        let mut last_error = DialError::Other("no addresses provided".into());

        for addr in addrs {
            match Self::connect_tcp_stream(*addr).await {
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

    /// Connection method with cancellation support
    /// 带取消支持的连接方法
    async fn connect_with_cancellation(
        &self,
        addr: SocketAddr,
        cancel_token: CancellationToken,
    ) -> Result<IoStream, DialError> {
        let connect_future = Self::connect_tcp_stream(addr);

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

    /// Helper to connect a TCP stream with platform-specific protection
    async fn connect_tcp_stream(addr: SocketAddr) -> std::io::Result<TcpStream> {
        #[cfg(target_os = "android")]
        {
            let socket = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            
            if let Err(e) = sb_platform::android_protect::protect_tcp_socket(&socket) {
                tracing::warn!("Failed to protect TCP socket: {}", e);
            }
            
            socket.connect(addr).await
        }
        #[cfg(not(target_os = "android"))]
        {
            TcpStream::connect(addr).await
        }
    }
}

/// TCP Dialer with Retry Policy / 支持重试策略的 TCP 拨号器
///
/// This is a wrapper around `TcpDialer` that adds a configurable retry mechanism.
/// 这是对 `TcpDialer` 的包装，添加了可配置的重试机制。
/// For idempotent connection operations (such as initial TCP handshake), retries can be enabled via environment variables.
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
    /// Create a new retryable TCP dialer, reading retry configuration from environment variables
    /// 创建新的可重试TCP拨号器，从环境变量读取重试配置
    pub fn new() -> Self {
        Self {
            inner: TcpDialer {
                bind_interface: None,
                bind_v4: None,
                bind_v6: None,
                routing_mark: None,
                reuse_addr: false,
                connect_timeout: None,
                tcp_fast_open: false,
                tcp_multi_path: false,
                udp_fragment: false,
            },
            retry_policy: RetryPolicy::from_env(),
        }
    }

    /// Create a TCP dialer with a specified retry policy
    /// 创建带指定重试策略的TCP拨号器
    pub fn with_policy(policy: RetryPolicy) -> Self {
        Self {
            inner: TcpDialer {
                bind_interface: None,
                bind_v4: None,
                bind_v6: None,
                routing_mark: None,
                reuse_addr: false,
                connect_timeout: None,
                tcp_fast_open: false,
                tcp_multi_path: false,
                udp_fragment: false,
            },
            retry_policy: policy,
        }
    }
}

#[async_trait]
impl Dialer for RetryableTcpDialer {
    /// Establish a TCP connection with retry mechanism
    /// 建立 TCP 连接，支持重试机制
    ///
    /// For idempotent operations like connection establishment, if a retry policy is enabled,
    /// retries will be performed when temporary network errors are encountered.
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

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Resource Pressure Aware Dialer Wrapper / 资源压力感知的拨号器包装器
///
/// This dialer detects resource pressure (such as file descriptor exhaustion, out of memory) and applies appropriate fallback strategies:
/// 此拨号器会检测资源压力（如文件描述符耗尽、内存不足）并采取相应的回退策略：
// - Automatically detect resource pressure related errors / 自动检测资源压力相关错误
// - Apply throttling delay under pressure / 在压力情况下应用节流延迟
// - Expose pressure metrics to the management interface / 向管理界面暴露压力指标
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
    /// Create a new resource-aware dialer
    /// 创建新的资源感知拨号器
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync + 'static> Dialer for ResourceAwareDialer<D> {
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

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Closure-based Custom Dialer / 基于闭包的自定义拨号器
///
/// This dialer allows injecting custom connection logic via a closure, which is very suitable for:
/// 该拨号器允许通过闭包注入自定义的连接逻辑，非常适用于：
// - Simulating various network behaviors in unit tests / 单元测试中模拟各种网络行为
// - Connection debugging and monitoring in development environments / 开发环境中的连接调试和监控
// - Connection customization in special scenarios (e.g., connection pools, load balancing) / 特殊场景下的连接定制（如连接池、负载均衡等）
// - Constructing read-only examples for admin endpoints / admin 端点的只读示例构造
///
/// ## Type Parameters / 类型参数
// - `F`: Closure type, must satisfy complex bounds to support async operations / 闭包类型，必须满足复杂的约束以支持异步操作
///
/// ## Design Considerations / 设计考虑
/// This dialer uses a type-erased design where the closure returns a boxed Future.
/// Although this adds some runtime overhead, it provides maximum flexibility.
/// 该拨号器使用了类型擦除的设计，闭包返回装箱的 Future，
/// 这虽然增加了一些运行时开销，但提供了最大的灵活性。
///
/// ## 使用示例
/// ```rust,no_run
/// use sb_transport::{FnDialer, IoStream, DialError};
/// use std::pin::Pin;
/// use std::future::Future;
///
/// let mock_dialer = FnDialer::new(|host: &str, port: u16| {
///     let host = host.to_string();
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
        > + 'static,
{
    /// Invoke the internal closure to execute custom connection logic
    /// 调用内部闭包执行自定义连接逻辑
    ///
    /// This method simply delegates the call to the internal closure function,
    /// allowing fully customized connection behavior.
    /// 该方法简单地将调用委托给内部的闭包函数，
    /// 允许完全自定义的连接行为。
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 调用闭包并等待其返回的 Future 完成
        (self.inner)(host, port).await
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl<F> FnDialer<F> {
    /// Create a new function dialer
    /// 创建新的函数拨号器
    ///
    /// R69: Facilitates constructing read-only examples for admin endpoints
    /// R69: 便于 admin 端点构造只读示例
    ///
    /// # Parameters / 参数
    // - `f`: Closure function implementing dialing logic / 实现拨号逻辑的闭包函数
    ///
    /// # Returns / 返回值
    /// `FnDialer` instance wrapping the given closure / 包装了给定闭包的 `FnDialer` 实例
    ///
    /// ## Usage Scenarios / 使用场景
    // - Injecting mock connection behavior in tests / 测试中注入模拟连接行为
    // - Connection customization for special network environments / 特殊网络环境的连接定制
    // - Connection monitoring and debugging / 连接监控和调试
    pub fn new(f: F) -> Self {
        Self {
            inner: std::sync::Arc::new(f),
        }
    }
}

/// Compatibility Conversion: Map tokio timeout errors to DialError
/// 兼容性转换：将 tokio 超时错误统一映射为 DialError
///
/// This implementation ensures consistent handling of timeout errors across the transport layer:
/// 这个实现确保了整个传输层对超时错误的一致处理：
// - Convert `tokio::time::error::Elapsed` to `DialError::Other("timeout")` / 将 `tokio::time::error::Elapsed` 转换为 `DialError::Other("timeout")`
// - Avoid using deprecated `DialError::Timeout` / 避免使用已弃用的 `DialError::Timeout`
// - Maintain consistency with timeout handling strategies in the util module / 与 util 模块的超时处理策略保持一致
///
/// ## Design Rationale / 设计理由
/// Use the string "timeout" instead of a dedicated enum variant:
/// 使用字符串 "timeout" 而不是专门的枚举变体：
// - Keep error types simple / 保持错误类型的简洁性
// - Facilitate logging and debugging / 便于日志记录和调试
// - Consistent with existing error handling patterns / 与现有的错误处理模式一致
impl From<tokio::time::error::Elapsed> for DialError {
    /// Convert tokio timeout error to standardized dial error
    /// 将 tokio 超时错误转换为标准化的拨号错误
    ///
    /// # Parameters / 参数
    // - `_`: tokio timeout error (content ignored) / tokio 的超时错误（具体内容被忽略）
    ///
    /// # Returns / 返回值
    /// Standardized `DialError::Other("timeout")` error / 标准化的 `DialError::Other("timeout")` 错误
    fn from(_: tokio::time::error::Elapsed) -> Self {
        DialError::Other("timeout".into())
    }
}

// Note: Mapping to sb-core's SbError is intentionally removed to avoid
// circular dependencies. sb-core can provide its own `From<DialError>`
// implementation in its crate if needed.

/// Private IO Utility Module / 私有 IO 工具模块
///
/// This module contains IO-related types and utility functions used internally,
/// mainly for type checking and internal testing.
/// 该模块包含一些内部使用的 IO 相关类型和工具函数，
/// 主要用于类型检查和内部测试。
pub(crate) mod priv_io {
    // use tokio::io::{AsyncRead, AsyncWrite};

    /// Type alias for tokio DuplexStream / tokio DuplexStream 的类型别名
    ///
    /// This type alias exposes tokio's duplex stream type as an implementer of IoStream,
    /// mainly used for:
    /// 该类型别名将 tokio 的双工流类型暴露为 IoStream 的实现者，
    /// 主要用于：
    // - In-memory bidirectional communication pipes / 内存中的双向通信管道
    // - Simulating network connections in tests / 测试中模拟网络连接
    // - Inter-process or inter-task data transfer / 进程间或任务间的数据传递
    ///
    /// Note: This type is currently unused but reserved for future extensions
    /// 注意：该类型当前未被使用，但保留以备将来扩展
    #[allow(dead_code)]
    pub type DuplexStream = tokio::io::DuplexStream;
}
