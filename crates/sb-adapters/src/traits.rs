//! Unified traits and interfaces for all adapters.
//! 所有适配器的统一 trait 和接口。
//!
//! This module defines the core abstractions used throughout the adapter layer:
//! 本模块定义了整个适配器层使用的核心抽象：
//!
//! - [`sb_types::Outbound`]: Canonical outbound adapter contract
//! - [`sb_types::PacketConn`]: Canonical UDP association contract
//! - [`sb_types::Session`]: Canonical target and connection options

use crate::error::Result;
use std::time::Duration;

/// The one session-based outbound contract used by adapters and core.
pub use sb_types::{ConnectOptions, Outbound, ResolveMode, RetryPolicy, Session, TargetAddr};

/// Boxed async stream for connections.
/// 用于连接的装箱异步流。
///
/// Temporary abstraction over `AsyncRead + AsyncWrite` traits.
/// `AsyncRead + AsyncWrite` trait 的临时抽象。
pub type BoxedStream = Box<dyn AsyncStream>;

/// Combined trait for async read + write + unpin + send + sync.
/// 异步读 + 写 + Unpin + Send + Sync 的组合 trait。
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Blanket implementation for any type that implements the required traits.
/// 为实现所需 trait 的任何类型提供的覆盖实现。
impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Converts a transport `IoStream` to `BoxedStream`.
/// 将传输层 `IoStream` 转换为 `BoxedStream`。
///
/// This function bridges `sb-transport` (which uses `AsyncReadWrite` trait)
/// and `sb-adapters` (which uses `AsyncStream` trait). Both traits have identical
/// bounds, so this is a safe zero-cost conversion via a wrapper struct.
/// 此函数桥接 `sb-transport`（使用 `AsyncReadWrite` trait）和 `sb-adapters`
/// （使用 `AsyncStream` trait）。两个 trait 具有相同的边界，因此这是通过包装结构体
/// 进行的安全零成本转换。
#[cfg(feature = "sb-transport")]
#[must_use]
pub fn from_transport_stream(stream: sb_transport::dialer::IoStream) -> BoxedStream {
    Box::new(TransportStreamAdapter { inner: stream })
}

/// Adapter to convert `sb-transport` streams to `AsyncStream`.
#[cfg(feature = "sb-transport")]
struct TransportStreamAdapter {
    inner: sb_transport::dialer::IoStream,
}

#[cfg(feature = "sb-transport")]
impl tokio::io::AsyncRead for TransportStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "sb-transport")]
impl tokio::io::AsyncWrite for TransportStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Checks if an error is retryable.
/// 检查错误是否可重试。
///
/// Network and I/O errors are generally retryable, while protocol and
/// authentication errors are not.
/// 网络和 I/O 错误通常是可重试的，而协议和认证错误则不可重试。
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::error::AdapterError;
/// use sb_adapters::traits::is_retryable_error;
/// use std::time::Duration;
///
/// let timeout_err = AdapterError::Timeout(Duration::from_secs(5));
/// assert!(is_retryable_error(&timeout_err));
///
/// let auth_err = AdapterError::AuthenticationFailed;
/// assert!(!is_retryable_error(&auth_err));
/// ```
#[inline]
#[must_use]
pub fn is_retryable_error(error: &crate::error::AdapterError) -> bool {
    use crate::error::AdapterError;

    match error {
        // Network/IO errors are generally retryable
        AdapterError::Io(io_err) => {
            use std::io::ErrorKind;
            matches!(
                io_err.kind(),
                ErrorKind::TimedOut
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::AddrInUse
                    | ErrorKind::AddrNotAvailable
                    | ErrorKind::Interrupted
                    | ErrorKind::WouldBlock
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::BrokenPipe
            )
        }
        // Timeout errors are retryable
        AdapterError::Timeout(_) => true,

        // Network errors might be retryable depending on context
        AdapterError::Network(_) => true,

        // Protocol errors usually aren't retryable (authentication, handshake failures)
        AdapterError::InvalidConfig(_)
        | AdapterError::UnsupportedProtocol(_)
        | AdapterError::AuthenticationFailed
        | AdapterError::Protocol(_)
        | AdapterError::Other(_)
        | AdapterError::NotImplemented { .. } => false,
    }
}

/// Retries a future with exponential backoff and jitter.
/// 使用指数退避和抖动重试 future。
///
/// # Errors
///
/// Returns the last error encountered if all retry attempts fail.
/// 如果所有重试尝试都失败，则返回最后遇到的错误。
pub async fn with_retry<F, Fut, T>(
    retry_policy: &sb_types::RetryPolicy,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=(retry_policy.max_retries) {
        // Add delay before retry (but not before first attempt)
        if attempt > 0 {
            let delay = retry_policy.calculate_delay_with_sample(attempt, rand::random());
            if delay > Duration::from_millis(0) {
                tokio::time::sleep(delay).await;
            }
        }

        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                last_error = Some(error.clone());

                // Don't retry if this is the last attempt or error is not retryable
                if attempt >= retry_policy.max_retries || !is_retryable_error(&error) {
                    break;
                }

                tracing::debug!(
                    "Retry attempt {} after error: {} (will retry in {:?})",
                    attempt + 1,
                    error,
                    retry_policy.calculate_delay_with_sample(attempt + 1, rand::random())
                );
            }
        }
    }

    // Return last error (should always be Some after loop executes at least once)
    Err(last_error.unwrap_or_else(|| {
        crate::error::AdapterError::other("retry loop completed without executing operation")
    }))
}

/// Retries a future with exponential backoff, jitter, and adapter metrics.
/// 使用指数退避、抖动和适配器指标重试 future。
///
/// # Errors
///
/// Returns the last error encountered if all retry attempts fail.
/// 如果所有重试尝试都失败，则返回最后遇到的错误。
pub async fn with_adapter_retry<F, Fut, T>(
    retry_policy: &sb_types::RetryPolicy,
    adapter_name: &'static str,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=(retry_policy.max_retries) {
        // Add delay before retry (but not before first attempt)
        if attempt > 0 {
            let delay = retry_policy.calculate_delay_with_sample(attempt, rand::random());
            if delay > Duration::from_millis(0) {
                tokio::time::sleep(delay).await;
            }

            // Record retry attempt
            #[cfg(feature = "metrics")]
            sb_metrics::inc_adapter_retries_total(adapter_name);
        }

        match operation().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                last_error = Some(error.clone());

                // Don't retry if this is the last attempt or error is not retryable
                if attempt >= retry_policy.max_retries || !is_retryable_error(&error) {
                    break;
                }

                tracing::debug!(
                    adapter = adapter_name,
                    "Retry attempt {} after error: {} (will retry in {:?})",
                    attempt + 1,
                    error,
                    retry_policy.calculate_delay_with_sample(attempt + 1, rand::random())
                );
            }
        }
    }

    // Return last error (should always be Some after loop executes at least once)
    Err(last_error.unwrap_or_else(|| {
        crate::error::AdapterError::other("retry loop completed without executing operation")
    }))
}
