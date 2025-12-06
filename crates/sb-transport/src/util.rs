//! # Transport Utility Module / 传输层工具函数模块
//!
//! This module provides general utility functions for the transport layer, including:
//! 该模块提供了传输层的通用工具函数，主要包括：
//! - Timeout-controlled dialing
//!   超时控制的拨号功能
//! - Compatibility fixes and unified error handling
//!   兼容性修复和统一的错误处理
//! - Flexible Future timeout wrappers
//!   灵活的 Future 超时包装器
//!
//! ## Design Principles / 设计原则
//! - **Safe Timeout Range**: Automatically limits timeout values to a reasonable range.
//!   **安全的超时范围**: 自动限制超时值在合理范围内。
//! - **Unified Error Handling**: Converts all timeouts to a consistent `DialError` format.
//!   **统一错误处理**: 所有超时都转换为一致的 DialError 格式。
//! - **Composability**: Can be combined with any `Dialer` implementation.
//!   **组合性**: 可以与任意拨号器实现组合使用。
//!
//! ## Performance Considerations / 性能考虑
//! - Uses `tokio`'s underlying timeout mechanism for minimal overhead.
//!   使用 tokio 的底层超时机制，开销最小。
//! - Supports zero-copy Future wrapping.
//!   支持零拷贝的 Future 包装。
//! - Automatic range checking avoids invalid configurations.
//!   自动范围检查避免无效配置。

use crate::dialer::{DialError, Dialer, IoStream};
use tokio::time::{timeout, Duration};

/// Dial with timeout control / 带超时控制的拨号函数
///
/// This function adds timeout control capabilities to any dialer, ensuring that network connections
/// do not wait indefinitely. It is the most commonly used timeout utility function.
/// 该函数为任意的拨号器添加超时控制能力，确保网络连接不会
/// 无限期等待。它是最常用的超时工具函数。
///
/// ## Features / 功能特性
/// - **Automatic Range Limiting**: Timeout values are limited between 10ms and 60s.
///   **自动范围限制**: 超时值被限制在10ms到60秒之间。
/// - **Unified Error Handling**: All errors are converted to standard `DialError`.
///   **统一错误处理**: 所有错误都转换为标准的 DialError。
/// - **Safe Defaults**: Uses reasonable timeout ranges to prevent misconfiguration.
///   **安全默认**: 使用合理的超时范围防止故障配置。
///
/// ## Timeout Range / 超时范围说明
/// - **Minimum**: 10ms - Prevents connection failures due to excessively small timeouts.
///   **最小值**: 10ms - 防止过小的超时导致连接失败。
/// - **Maximum**: 60s - Prevents resource waste due to excessively long timeouts.
///   **最大值**: 60秒 - 防止过长的超时导致资源浪费。
/// - **Recommended**: 5-30s is suitable for most scenarios.
///   **推荐值**: 5-30秒适用于大多数场景。
///
/// # Parameters / 参数
/// - `d`: Reference to a dialer implementing the `Dialer` trait.
///   `d`: 实现了 `Dialer` trait 的拨号器引用。
/// - `host`: Target hostname or IP address.
///   `host`: 目标主机名或 IP 地址。
/// - `port`: Target port number.
///   `port`: 目标端口号。
/// - `ms`: Timeout in milliseconds, automatically adjusted to a reasonable range.
///   `ms`: 超时时间（毫秒），会被自动调整到合理范围。
///
/// # Returns / 返回值
/// - `Ok(IoStream)`: Successfully established connection stream.
///   `Ok(IoStream)`: 成功建立的连接流。
/// - `Err(DialError)`: Specific error for connection failure or timeout.
///   `Err(DialError)`: 连接失败或超时的具体错误。
///
/// # Error Types / 错误类型
/// - `DialError::Other("timeout")`: Connection timed out.
///   `DialError::Other("timeout")`: 连接超时。
/// - `DialError::Io(_)`: Underlying network I/O error.
///   `DialError::Io(_)`: 底层网络 IO 错误。
/// - Others: Errors returned by the underlying dialer.
///   其他: 由底层拨号器返回的错误。
///
/// # Example / 使用示例
/// ```rust,no_run
/// use sb_transport::{dial_with_timeout, TcpDialer};
/// use sb_transport::Dialer;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let dialer = TcpDialer::default();
///
///     // Connect with 10s timeout
///     // 10秒超时连接
///     let stream = dial_with_timeout(&dialer, "example.com", 80, 10_000).await?;
///
///     // Use stream for communication...
///     // 使用 stream 进行通信...
///     Ok(())
/// }
/// ```
///
/// # Performance Considerations / 性能考虑
/// - Uses `tokio::time::timeout` for minimal overhead.
///   该函数使用 `tokio::time::timeout`，开销最小。
/// - Timeout control is precise to the millisecond level.
///   超时控制精确到毫秒级别。
/// - No additional heap allocation.
///   不会产生额外的堆内存分配。
pub async fn dial_with_timeout<D: Dialer + Send + Sync>(
    d: &D,
    host: &str,
    port: u16,
    ms: u64,
) -> Result<IoStream, DialError> {
    // Limit timeout to reasonable range
    // 将超时值限制在合理范围内
    // - Min 10ms: Prevent failures from too small timeouts
    // - Max 60s: Prevent resource leaks from too long timeouts
    // - 最小 10ms: 防止过小的超时导致正常连接失败
    // - 最大 60s: 防止过长的超时导致资源不及时释放
    let to = Duration::from_millis(ms.clamp(10, 60_000));

    // Create dial future
    // 创建拨号操作的 Future
    let fut = d.connect(host, port);

    // Execute dial with timeout
    // 执行带超时的拨号操作
    match timeout(to, fut).await {
        // Dial success or failure (completed before timeout)
        // 拨号成功或失败（在超时之前完成）
        Ok(r) => r,

        // Timeout error: Convert to standard DialError format
        // This conversion is automatic via From trait
        // 超时错误：转换为标准的 DialError 格式
        // 这个转换是通过 From trait 自动进行的
        Err(e) => Err(DialError::from(e)),
    }
}

/// Convenience function for address tuple dialing / 便捷的地址元组拨号函数
///
/// This function is a convenience wrapper for `dial_with_timeout`, accepting an address tuple as an argument.
/// It behaves exactly the same as `dial_with_timeout` regarding timeout handling.
/// 该函数是 `dial_with_timeout` 的便捷包装，接受地址元组作为参数。
/// 与 `dial_with_timeout` 完全一致的行为和超时处理。
///
/// ## Use Cases / 使用场景
/// - When you already have a `(host, port)` tuple.
///   当你已经有一个 `(host, port)` 元组时。
/// - When integrating with existing address resolution code.
///   需要与现有的地址解析代码集成时。
/// - When passing network addresses as parameters.
///   传递网络地址作为参数时。
///
/// # Parameters / 参数
/// - `d`: Reference to a dialer implementing the `Dialer` trait.
///   `d`: 实现了 `Dialer` trait 的拨号器引用。
/// - `addr`: Target address tuple `(host, port)`.
///   `addr`: 目标地址元组 `(host, port)`。
///   - `addr.0`: Hostname or IP address.
///     `addr.0`: 主机名或 IP 地址。
///   - `addr.1`: Port number.
///     `addr.1`: 端口号。
/// - `ms`: Timeout in milliseconds.
///   `ms`: 超时时间（毫秒）。
///
/// # Returns / 返回值
/// Same return values and error types as `dial_with_timeout`.
/// 与 `dial_with_timeout` 完全相同的返回值和错误类型。
///
/// # Example / 使用示例
/// ```rust,no_run
/// use sb_transport::{connect_with_timeout, TcpDialer};
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let dialer = TcpDialer::default();
///     let address = ("example.com", 80);
///
///     // Connect with timeout using address tuple
///     // 使用地址元组进行超时连接
///     let stream = connect_with_timeout(&dialer, address, 5_000).await?;
///
///     // Use stream...
///     // 使用 stream...
///     Ok(())
/// }
/// ```
///
/// # Implementation Details / 实现细节
/// This function is a zero-cost inline wrapper that delegates directly to `dial_with_timeout`,
/// incurring no additional performance overhead.
/// 该函数是一个零成本的内联包装，直接委托给 `dial_with_timeout`，
/// 不会产生任何额外的性能开销。
pub async fn connect_with_timeout<D: Dialer + Send + Sync>(
    d: &D,
    addr: (&str, u16),
    ms: u64,
) -> Result<IoStream, DialError> {
    // Delegate directly to dial_with_timeout, unpacking the tuple
    // 直接委托给 dial_with_timeout，将元组拆解为单独的参数
    dial_with_timeout(d, addr.0, addr.1, ms).await
}

/// General Future Timeout Wrapper / 通用 Future 超时包装器
///
/// This function adds timeout control to any Future that returns a `Result`.
/// It is a more general timeout utility function, not limited to dialing operations,
/// and can be used for various asynchronous operations.
/// 该函数为任意返回 `Result` 的 Future 添加超时控制，
/// 是一个更通用的超时工具函数。它不仅限于拨号操作，
/// 还可以用于其他各种异步操作。
///
/// ## Design Philosophy / 设计理念
/// - **Type Safety**: Ensures correctness of error conversion via `Into<DialError>` constraint.
///   **类型安全**: 通过 `Into<DialError>` 约束保证错误转换的正确性。
/// - **Generality**: Can wrap any asynchronous operation, not just network connections.
///   **通用性**: 可以包装任意的异步操作，不仅限于网络连接。
/// - **Consistency**: Maintains the same timeout range and error handling as other timeout functions.
///   **一致性**: 与其他超时函数保持相同的超时范围和错误处理。
///
/// ## Applicable Scenarios / 适用场景
/// - DNS query operations / DNS 查询操作
/// - TLS handshake process / TLS 握手过程
/// - Database connection establishment / 数据库连接建立
/// - HTTP request operations / HTTP 请求操作
/// - Any asynchronous operation requiring timeout control / 任何需要超时控制的异步操作
///
/// # Type Parameters / 类型参数
/// - `F`: Asynchronous Future type, returning `Result<T, E>`.
///   `F`: 异步 Future 类型，返回 `Result<T, E>`。
/// - `T`: Return value type on success.
///   `T`: 成功时的返回值类型。
/// - `E`: Error type, must implement `Into<DialError>`.
///   `E`: 错误类型，必须实现 `Into<DialError>`。
///
/// # Parameters / 参数
/// - `fut`: The asynchronous Future to execute.
///   `fut`: 要执行的异步 Future。
/// - `ms`: Timeout in milliseconds, automatically limited to 10ms-60s range.
///   `ms`: 超时时间（毫秒），会被自动限制在 10ms-60s 范围内。
///
/// # Returns / 返回值
/// - `Ok(T)`: Result of successful Future completion.
///   `Ok(T)`: Future 成功完成的结果。
/// - `Err(DialError)`: Error from Future failure or timeout.
///   `Err(DialError)`: Future 失败或超时的错误。
///
/// # Error Handling Flow / 错误处理流程
/// ```text
/// Future Execution -> Success -> Ok(T)
///                  |
///                  -> Failure -> E -> Into<DialError> -> Err(DialError)
///                  |
///                  -> Timeout -> Elapsed -> From<Elapsed> -> Err(DialError::Other("timeout"))
/// ```
///
/// # Example / 使用示例
/// ```rust,no_run
/// use sb_transport::{dial_with_timeout_future, DialError};
/// use std::io;
///
/// // Add timeout to DNS query
/// // 为 DNS 查询添加超时
/// async fn lookup_with_timeout(hostname: &str) -> Result<std::net::IpAddr, DialError> {
///     let dns_query = async {
///         // Mock DNS query
///         // 模拟 DNS 查询
///         tokio::time::sleep(std::time::Duration::from_millis(100)).await;
///         Ok::<_, DialError>("127.0.0.1".parse().unwrap())
///     };
///
///     dial_with_timeout_future(dns_query, 5_000).await
/// }
/// ```
///
/// # Performance Characteristics / 性能特性
/// - Zero-copy Future wrapping.
///   零拷贝的 Future 包装。
/// - Same low-overhead timeout mechanism as `dial_with_timeout`.
///   与 `dial_with_timeout` 相同的低开销超时机制。
/// - Compile-time type checking ensures safety of error conversion.
///   编译时类型检查保证错误转换的安全性。
pub async fn dial_with_timeout_future<F, T, E>(fut: F, ms: u64) -> Result<T, DialError>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: Into<DialError>,
{
    // Use same timeout range limits as other functions
    // 使用与其他函数相同的超时范围限制
    let to = Duration::from_millis(ms.clamp(10, 60_000));

    // Execute future with timeout
    // 执行带超时的 Future
    match timeout(to, fut).await {
        // Future completed successfully with Ok result
        // Future 成功完成并返回 Ok 结果
        Ok(Ok(v)) => Ok(v),

        // Future completed successfully but returned Err result
        // Use Into trait to convert original error to DialError
        // Future 成功完成但返回 Err 结果
        // 使用 Into trait 将原始错误转换为 DialError
        Ok(Err(e)) => Err(e.into()),

        // Timeout occurred: Convert to DialError::Other("timeout") via From trait
        // 超时发生：使用 From trait 转换为 DialError::Other("timeout")
        Err(e) => Err(DialError::from(e)),
    }
}
