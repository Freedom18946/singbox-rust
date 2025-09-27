//! # 传输层工具函数模块
//!
//! 该模块提供了传输层的通用工具函数，主要包括：
//! - 超时控制的拨号功能
//! - 兼容性修复和统一的错误处理
//! - 灵活的 Future 超时包装器
//!
//! R84: 传输超时工具，带有兼容性修复
//!
//! ## 设计原则
//! - **安全的超时范围**: 自动限制超时值在合理范围内
//! - **统一错误处理**: 所有超时都转换为一致的 DialError 格式
//! - **组合性**: 可以与任意拨号器实现组合使用
//!
//! ## 性能考虑
//! - 使用 tokio 的底层超时机制，开销最小
//! - 支持零拷贝的 Future 包装
//! - 自动范围检查避免无效配置

use crate::dialer::{DialError, Dialer, IoStream};
use tokio::time::{timeout, Duration};

/// 带超时控制的拨号函数
///
/// 该函数为任意的拨号器添加超时控制能力，确保网络连接不会
/// 无限期等待。它是最常用的超时工具函数。
///
/// ## 功能特性
        // - **自动范围限制**: 超时值被限制在10ms到60秒之间
        // - **统一错误处理**: 所有错误都转换为标准的 DialError
        // - **安全默认**: 使用合理的超时范围防止故障配置
///
/// ## 超时范围说明
        // - **最小值**: 10ms - 防止过小的超时导致连接失败
        // - **最大值**: 60秒 - 防止过长的超时导致资源浪费
        // - **推荐值**: 5-30秒适用于大多数场景
///
/// # 参数
        // - `d`: 实现了 `Dialer` trait 的拨号器引用
        // - `host`: 目标主机名或 IP 地址
        // - `port`: 目标端口号
        // - `ms`: 超时时间（毫秒），会被自动调整到合理范围
///
/// # 返回值
        // - `Ok(IoStream)`: 成功建立的连接流
        // - `Err(DialError)`: 连接失败或超时的具体错误
///
/// # 错误类型
        // - `DialError::Other("timeout")`: 连接超时
        // - `DialError::Io(_)`: 底层网络 IO 错误
        // - 其他: 由底层拨号器返回的错误
///
/// # 使用示例
/// ```rust,no_run
/// use sb_transport::{dial_with_timeout, TcpDialer};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let dialer = TcpDialer;
///
///     // 10秒超时连接
///     let stream = dial_with_timeout(&dialer, "example.com", 80, 10_000).await?;
///
///     // 使用 stream 进行通信...
///     Ok(())
/// }
/// ```
///
/// # 性能考虑
        // - 该函数使用 tokio::time::timeout，开销最小
        // - 超时控制精确到毫秒级别
        // - 不会产生额外的堆内存分配
pub async fn dial_with_timeout<D: Dialer + Send + Sync>(
    d: &D,
    host: &str,
    port: u16,
    ms: u64,
) -> Result<IoStream, DialError> {
    // 将超时值限制在合理范围内
    // - 最小 10ms: 防止过小的超时导致正常连接失败
    // - 最大 60s: 防止过长的超时导致资源不及时释放
    let to = Duration::from_millis(ms.clamp(10, 60_000));

    // 创建拨号操作的 Future
    let fut = d.connect(host, port);

    // 执行带超时的拨号操作
    match timeout(to, fut).await {
        // 拨号成功或失败（在超时之前完成）
        Ok(r) => r,

        // 超时错误：转换为标准的 DialError 格式
        // 这个转换是通过 From trait 自动进行的
        Err(e) => Err(DialError::from(e)),
    }
}

/// 便捷的地址元组拨号函数
///
/// 该函数是 `dial_with_timeout` 的便捷包装，接受地址元组作为参数。
/// 与 `dial_with_timeout` 完全一致的行为和超时处理。
///
/// ## 使用场景
        // - 当你已经有一个 `(host, port)` 元组时
        // - 需要与现有的地址解析代码集成时
        // - 传递网络地址作为参数时
///
/// # 参数
        // - `d`: 实现了 `Dialer` trait 的拨号器引用
        // - `addr`: 目标地址元组 `(host, port)`
///   - `addr.0`: 主机名或 IP 地址
///   - `addr.1`: 端口号
        // - `ms`: 超时时间（毫秒）
///
/// # 返回值
/// 与 `dial_with_timeout` 完全相同的返回值和错误类型
///
/// # 使用示例
/// ```rust,no_run
/// use sb_transport::{connect_with_timeout, TcpDialer};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let dialer = TcpDialer;
///     let address = ("example.com", 80);
///
///     // 使用地址元组进行超时连接
///     let stream = connect_with_timeout(&dialer, address, 5_000).await?;
///
///     // 使用 stream...
///     Ok(())
/// }
/// ```
///
/// # 实现细节
/// 该函数是一个零成本的内联包装，直接委托给 `dial_with_timeout`，
/// 不会产生任何额外的性能开销。
pub async fn connect_with_timeout<D: Dialer + Send + Sync>(
    d: &D,
    addr: (&str, u16),
    ms: u64,
) -> Result<IoStream, DialError> {
    // 直接委托给 dial_with_timeout，将元组拆解为单独的参数
    dial_with_timeout(d, addr.0, addr.1, ms).await
}

/// 通用 Future 超时包装器
///
/// 该函数为任意返回 `Result` 的 Future 添加超时控制，
/// 是一个更通用的超时工具函数。它不仅限于拨号操作，
/// 还可以用于其他各种异步操作。
///
/// ## 设计理念
        // - **类型安全**: 通过 `Into<DialError>` 约束保证错误转换的正确性
        // - **通用性**: 可以包装任意的异步操作，不仅限于网络连接
        // - **一致性**: 与其他超时函数保持相同的超时范围和错误处理
///
/// ## 适用场景
        // - DNS 查询操作
        // - TLS 握手过程
        // - 数据库连接建立
        // - HTTP 请求操作
        // - 任何需要超时控制的异步操作
///
/// # 类型参数
        // - `F`: 异步 Future 类型，返回 `Result<T, E>`
        // - `T`: 成功时的返回值类型
        // - `E`: 错误类型，必须实现 `Into<DialError>`
///
/// # 参数
        // - `fut`: 要执行的异步 Future
        // - `ms`: 超时时间（毫秒），会被自动限制在 10ms-60s 范围内
///
/// # 返回值
        // - `Ok(T)`: Future 成功完成的结果
        // - `Err(DialError)`: Future 失败或超时的错误
///
/// # 错误处理流程
/// ```text
/// Future 执行 -> 成功 -> Ok(T)
///              |
///              -> 失败 -> E -> Into<DialError> -> Err(DialError)
///              |
///              -> 超时 -> Elapsed -> From<Elapsed> -> Err(DialError::Other("timeout"))
/// ```
///
/// # 使用示例
/// ```rust,no_run
/// use sb_transport::{dial_with_timeout_future, DialError};
/// use std::io;
///
/// // 为 DNS 查询添加超时
/// async fn lookup_with_timeout(hostname: &str) -> Result<std::net::IpAddr, DialError> {
///     let dns_query = async {
///         // 模拟 DNS 查询
///         tokio::time::sleep(std::time::Duration::from_millis(100)).await;
///         Ok("127.0.0.1".parse().unwrap())
///     };
///
///     dial_with_timeout_future(dns_query, 5_000).await
/// }
/// ```
///
/// # 性能特性
        // - 零拷贝的 Future 包装
        // - 与 `dial_with_timeout` 相同的低开销超时机制
        // - 编译时类型检查保证错误转换的安全性
pub async fn dial_with_timeout_future<F, T, E>(fut: F, ms: u64) -> Result<T, DialError>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: Into<DialError>,
{
    // 使用与其他函数相同的超时范围限制
    let to = Duration::from_millis(ms.clamp(10, 60_000));

    // 执行带超时的 Future
    match timeout(to, fut).await {
        // Future 成功完成并返回 Ok 结果
        Ok(Ok(v)) => Ok(v),

        // Future 成功完成但返回 Err 结果
        // 使用 Into trait 将原始错误转换为 DialError
        Ok(Err(e)) => Err(e.into()),

        // 超时发生：使用 From trait 转换为 DialError::Other("timeout")
        Err(e) => Err(DialError::from(e)),
    }
}
