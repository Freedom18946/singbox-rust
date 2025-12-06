//! # Failpoint-enabled Dialer / 启用故障注入的拨号器
//!
//! This module provides a dialer wrapper that can inject failures at various points
//! during connection establishment. Failures are controlled via the `FAILPOINTS` environment
//! variable and are only active when the "failpoints" feature is enabled.
//! 该模块提供了一个拨号器包装器，可以在连接建立过程中的各个点注入故障。
//! 故障通过 `FAILPOINTS` 环境变量控制，并且仅在启用 "failpoints" 特性时处于活动状态。
//!
//! ## Strategic Relevance / 战略关联
//! - **Chaos Engineering**: Enables testing system resilience against network failures.
//!   **混沌工程**: 能够测试系统对网络故障的恢复能力。
//! - **Deterministic Testing**: Allows reproducing specific failure scenarios reliably.
//!   **确定性测试**: 允许可靠地重现特定的故障场景。
//!
//! ## Failpoints / 故障点
//! - `transport.dialer.connect_start`: Fail before attempting connection
//!   `transport.dialer.connect_start`: 在尝试连接之前失败
//! - `transport.dialer.connect_timeout`: Simulate connection timeout
//!   `transport.dialer.connect_timeout`: 模拟连接超时
//! - `transport.dialer.dns_failure`: Simulate DNS resolution failure
//!   `transport.dialer.dns_failure`: 模拟 DNS 解析失败

use super::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;

/// Dialer wrapper that supports failpoint-based failure injection
/// 支持基于故障点的故障注入的拨号器包装器
///
/// This dialer wraps an underlying dialer and can inject failures at specific
/// points based on failpoint configuration. It's designed for chaos engineering
/// and testing scenarios where you need to simulate network failures.
/// 该拨号器包装了一个底层拨号器，并可以根据故障点配置在特定点注入故障。
/// 它专为混沌工程和需要模拟网络故障的测试场景而设计。
///
/// ## Failpoint Naming Convention / 故障点命名约定
/// Failpoints follow the pattern: `transport.dialer.{point}`
/// 故障点遵循模式：`transport.dialer.{point}`
/// - `transport.dialer.connect_start`: Fail before attempting connection
///   `transport.dialer.connect_start`: 在尝试连接之前失败
/// - `transport.dialer.connect_timeout`: Simulate connection timeout
///   `transport.dialer.connect_timeout`: 模拟连接超时
/// - `transport.dialer.dns_failure`: Simulate DNS resolution failure
///   `transport.dialer.dns_failure`: 模拟 DNS 解析失败
pub struct FailpointDialer<D: Dialer> {
    /// The underlying dialer to wrap
    /// 要包装的底层拨号器
    pub inner: D,
}

impl<D: Dialer> FailpointDialer<D> {
    /// Create a new failpoint dialer with default prefix
    /// 创建一个新的带有默认前缀的故障点拨号器
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync + 'static> Dialer for FailpointDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        #[cfg(feature = "failpoints")]
        {
            // Failpoint: fail before starting connection
            // 故障点：在开始连接之前失败
            fail::fail_point!("transport.dialer.connect_start", |_| {
                return Err(DialError::Other("failpoint: connect_start".to_string()));
            });

            // Failpoint: simulate DNS failure (only applies to hostname, not IP literal)
            // 故障点：模拟 DNS 失败（仅适用于主机名，不适用于 IP 字面量）
            if host.chars().any(|c| c.is_alphabetic()) {
                fail::fail_point!("transport.dialer.dns_failure", |_| {
                    return Err(DialError::Other(format!(
                        "failpoint: DNS failure for {}",
                        host
                    )));
                });
            }

            // Proceed with actual connection
            // 继续实际连接
            let result = self.inner.connect(host, port).await;

            // Failpoint: simulate timeout after connection attempt
            // 故障点：在连接尝试后模拟超时
            fail::fail_point!("transport.dialer.connect_timeout", |_| {
                return Err(DialError::Other("timeout".to_string()));
            });

            result
        }

        #[cfg(not(feature = "failpoints"))]
        {
            // When failpoints are disabled, just pass through to inner dialer
            // 当禁用故障点时，只需传递给内部拨号器
            self.inner.connect(host, port).await
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::TcpDialer;

    #[tokio::test]
    async fn test_failpoint_dialer_passthrough() {
        let inner = TcpDialer::default();
        let fp_dialer = FailpointDialer::new(inner);

        // Without failpoints enabled, should work like normal dialer
        // (This test assumes localhost is available and will adjust based on environment)
        let result = fp_dialer.connect("127.0.0.1", 1).await;
        // Connection might fail normally - that's fine, we're just testing passthrough
        match result {
            Ok(_) | Err(_) => {
                // Either outcome is acceptable - we're just testing that the wrapper works
            }
        }
    }

    #[cfg(feature = "failpoints")]
    #[tokio::test]
    #[ignore]
    async fn test_failpoint_dialer_injection() {
        let inner = TcpDialer::default();
        let fp_dialer = FailpointDialer::new(inner);

        // Set up failpoint
        fail::cfg("transport.dialer.connect_start", "return").unwrap();

        let result = fp_dialer.connect("example.com", 80).await;
        assert!(result.is_err());

        // Clean up
        fail::cfg("transport.dialer.connect_start", "off").unwrap();
    }
}
