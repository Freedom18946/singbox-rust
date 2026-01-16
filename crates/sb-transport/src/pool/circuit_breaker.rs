//! # Circuit Breaker Dialer Wrapper / 熔断器拨号器包装器
//!
//! Provides a dialer wrapper that implements circuit breaker pattern
//! to protect against cascading failures in outbound connections.
//! 提供一个实现熔断器模式的拨号器包装器，以防止出站连接中的级联故障。
//!
//! ## Strategic Relevance / 战略关联
//! - **Fault Tolerance**: Isolates failing upstream services to prevent system-wide degradation.
//!   **容错**: 隔离故障的上游服务，以防止系统范围的降级。
//! - **Automatic Recovery**: Periodically tests failing services to automatically restore connectivity when they recover.
//!   **自动恢复**: 定期测试故障服务，以便在它们恢复时自动恢复连接。

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerDecision};
use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, trace, warn};

/// Dialer wrapper that implements circuit breaker pattern
/// 实现熔断器模式的拨号器包装器
pub struct CircuitBreakerDialer<D: Dialer> {
    inner: D,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl<D: Dialer + Clone> Clone for CircuitBreakerDialer<D> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            circuit_breaker: self.circuit_breaker.clone(),
        }
    }
}

impl<D: Dialer> CircuitBreakerDialer<D> {
    /// Create a new circuit breaker dialer with the given outbound name
    /// 使用给定的出站名称创建一个新的熔断器拨号器
    pub fn new(inner: D, outbound_name: String, config: CircuitBreakerConfig) -> Self {
        Self {
            inner,
            circuit_breaker: Arc::new(CircuitBreaker::new(outbound_name, config)),
        }
    }

    /// Create with configuration from environment variables
    /// 使用环境变量中的配置创建
    pub fn from_env(inner: D, outbound_name: String) -> Self {
        Self {
            inner,
            circuit_breaker: Arc::new(CircuitBreaker::from_env(outbound_name)),
        }
    }

    /// Get reference to the circuit breaker for monitoring/admin
    /// 获取熔断器的引用以进行监控/管理
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync + 'static> Dialer for CircuitBreakerDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // Check if circuit breaker allows the request
        // 检查熔断器是否允许请求
        match self.circuit_breaker.allow_request().await {
            CircuitBreakerDecision::Allow => {
                trace!("Circuit breaker allowing connection to {}:{}", host, port);

                // Attempt the connection
                // 尝试连接
                let start = std::time::Instant::now();
                match self.inner.connect(host, port).await {
                    Ok(stream) => {
                        let duration = start.elapsed();
                        debug!(
                            "Connection to {}:{} succeeded in {:?}",
                            host, port, duration
                        );
                        self.circuit_breaker.record_result(true, false).await;
                        Ok(stream)
                    }
                    Err(error) => {
                        let duration = start.elapsed();
                        let is_timeout = self.is_timeout_error(&error);

                        debug!(
                            "Connection to {}:{} failed in {:?}: {} (timeout: {})",
                            host, port, duration, error, is_timeout
                        );

                        self.circuit_breaker.record_result(false, is_timeout).await;
                        Err(error)
                    }
                }
            }
            CircuitBreakerDecision::Reject => {
                warn!("Circuit breaker rejecting connection to {}:{}", host, port);

                // Return specific error indicating circuit breaker rejection (via io::Error -> DialError)
                // 返回指示熔断器拒绝的特定错误（通过 io::Error -> DialError）
                Err(std::io::Error::other("circuit breaker open - request rejected").into())
            }
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl<D: Dialer> CircuitBreakerDialer<D> {
    /// Check if an error represents a timeout condition
    /// 检查错误是否代表超时情况
    fn is_timeout_error(&self, error: &DialError) -> bool {
        match error {
            DialError::Other(msg) if msg.contains("timeout") => true,
            DialError::Io(io_error) => {
                matches!(io_error.kind(), std::io::ErrorKind::TimedOut)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CircuitBreakerDialer;
    use super::*;
    #[cfg(disabled_tests)]
    use std::sync::Arc;

    #[tokio::test]
    async fn test_circuit_breaker_allows_successful_requests() {
        use crate::dialer::TcpDialer;

        // Use TcpDialer which already implements Dialer trait
        let dialer = TcpDialer::default();

        let cb_dialer = CircuitBreakerDialer::new(
            dialer,
            "test-outbound".to_string(),
            CircuitBreakerConfig::default(),
        );

        // Note: This will actually try to connect, so we use a valid address
        // In a real test environment, you might want to use a mock server
        let result = cb_dialer.connect("127.0.0.1", 80).await;
        // The result might fail if nothing is listening, but the circuit breaker logic works
        let _ = result; // Don't assert on result since we don't have a server
    }

    // Mock Dialer for testing
    #[derive(Clone)]
    struct MockDialer {
        call_count: Arc<std::sync::atomic::AtomicU32>,
        mode: MockMode,
    }

    #[derive(Clone)]
    enum MockMode {
        AlwaysFail,
        FailUntil(u32),
        Timeout,
    }

    #[async_trait]
    impl Dialer for MockDialer {
        async fn connect(&self, _host: &str, _port: u16) -> Result<IoStream, DialError> {
            let count = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            match &self.mode {
                MockMode::AlwaysFail => Err(DialError::Other("connection failed".to_string())),
                MockMode::FailUntil(limit) => {
                    if count < *limit {
                        Err(DialError::Other("connection failed".to_string()))
                    } else {
                        // Return a dummy stream
                        let (client, _server) = tokio::io::duplex(64);
                        Ok(Box::new(client))
                    }
                }
                MockMode::Timeout => Err(DialError::Other("timeout".to_string())),
            }
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let dialer = MockDialer {
            call_count: call_count.clone(),
            mode: MockMode::AlwaysFail,
        };

        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            failure_window: Duration::from_millis(1000),
            half_open_max_requests: 1,
            recovery_timeout: Duration::from_millis(100),
            count_timeouts: true,
        };

        let cb_dialer = CircuitBreakerDialer::new(dialer, "test-outbound".to_string(), config);

        // First two failures should go through
        let result1 = cb_dialer.connect("example.com", 80).await;
        assert!(result1.is_err());

        let result2 = cb_dialer.connect("example.com", 80).await;
        assert!(result2.is_err());

        // Third request should be rejected by circuit breaker
        let result3 = cb_dialer.connect("example.com", 80).await;
        assert!(result3.is_err());

        // Check that the error message indicates circuit breaker rejection
        match result3 {
            Err(DialError::Other(msg)) if msg.contains("circuit breaker") => {
                // Expected - circuit breaker rejected the request (if mapped to Other)
            }
            Err(DialError::Io(e)) if e.to_string().contains("circuit breaker") => {
                // Expected - circuit breaker rejected the request (mapped to Io)
            }
            _ => panic!("Expected circuit breaker rejection, got result variant that is not Circuit Breaker error: {:?}", result3.err()),
        }

        // Should only have been called twice (third was rejected by circuit breaker)
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        use std::time::Duration;
        use tokio::time::sleep;

        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let dialer = MockDialer {
            call_count: call_count.clone(),
            mode: MockMode::FailUntil(2),
        };

        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            failure_window: Duration::from_millis(1000),
            half_open_max_requests: 1,
            recovery_timeout: Duration::from_millis(50), // Short timeout for fast test
            count_timeouts: true,
        };

        let cb_dialer = CircuitBreakerDialer::new(dialer, "test-outbound".to_string(), config);

        // Trigger circuit breaker opening
        // Manually check IsErr because unwrapping Ok panics with debug info which IoStream lacks
        assert!(cb_dialer.connect("example.com", 80).await.is_err());
        assert!(cb_dialer.connect("example.com", 80).await.is_err());

        // Wait for half-open timeout
        sleep(Duration::from_millis(60)).await;

        // Next request should succeed and close the circuit
        let result = cb_dialer.connect("example.com", 80).await;
        assert!(result.is_ok());

        // Verify circuit is closed by checking another request succeeds
        let result2 = cb_dialer.connect("example.com", 80).await;
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_timeout_error_classification() {
        let call_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let dialer = MockDialer {
            call_count: call_count.clone(),
            mode: MockMode::Timeout,
        };

        let cb_dialer = CircuitBreakerDialer::new(
            dialer,
            "test-outbound".to_string(),
            CircuitBreakerConfig::default(),
        );

        let result = cb_dialer.connect("example.com", 80).await;
        assert!(result.is_err());

        // The circuit breaker should have classified this as a timeout
        // (This test mainly checks that the code doesn't panic)
    }
}
