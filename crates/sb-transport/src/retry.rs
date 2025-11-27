//! Unified retry and backoff strategy for idempotent I/O operations / 幂等 I/O 操作的统一重试和退避策略
//!
//! This module provides configurable retry policies with exponential backoff and jitter
//! for improving reliability of network operations while avoiding thundering herd problems.
//! 该模块提供可配置的重试策略，支持指数退避和抖动，
//! 以提高网络操作的可靠性，同时避免惊群问题。
//!
//! ## Features / 特性
//! - **Exponential Backoff**: Delay increases exponentially with each attempt / **指数退避**: 延迟随每次尝试呈指数增长
//! - **Jitter**: Randomness added to delays to prevent synchronization / **抖动**: 在延迟中添加随机性以防止同步
//! - **Configurable**: Max retries, base delay, max delay configurable via env / **可配置**: 最大重试次数、基础延迟、最大延迟可通过环境变量配置
//! - **Idempotency Awareness**: Only safe to use with idempotent operations / **幂等性感知**: 仅安全用于幂等操作
//!
//! ## Strategic Relevance / 战略关联
//! - **Resilience**: Crucial for handling transient network failures in distributed systems.
//!   **弹性**: 对于处理分布式系统中的瞬态网络故障至关重要。
//! - **System Stability**: Prevents overwhelming downstream services during outages.
//!   **系统稳定性**: 防止在中断期间压垮下游服务。
//!
//! ## Configuration / 配置
//! - `SB_RETRY_MAX`: Max retry attempts (default: 0/disabled) / 最大重试次数（默认：0/禁用）
//! - `SB_RETRY_BASE_MS`: Base delay in ms (default: 100) / 基础延迟（毫秒）（默认：100）
//! - `SB_RETRY_MAX_MS`: Max delay in ms (default: 2000) / 最大延迟（毫秒）（默认：2000）
//!
//! ## Safety Warning / 安全警告
//! Only apply retries to idempotent operations (e.g., connection establishment, read-only requests).
//! Retrying non-idempotent operations (e.g., sending data) can lead to data duplication or corruption.
//! 仅对幂等操作（如连接建立、只读请求）应用重试。
//! 重试非幂等操作（如发送数据）可能导致数据重复或损坏。
//!
//! Non-idempotent operations are disabled by default.
//! 非幂等操作默认禁用。

use rand::Rng;
use std::time::Duration;
use tracing::{debug, warn};

/// Retry policy configuration / 重试策略配置
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retries (0 = disabled)
    /// 最大重试次数（0 = 禁用）
    pub max_retries: u32,
    /// Base delay for backoff calculation
    /// 退避计算的基础延迟
    pub base_delay: Duration,
    /// Maximum delay cap
    /// 最大延迟上限
    pub max_delay: Duration,
    /// Jitter factor (0.0 - 1.0)
    /// 抖动因子 (0.0 - 1.0)
    pub jitter_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 0, // Default: no retries
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(2000),
            jitter_factor: 0.2, // 20% jitter by default
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy from environment variables
    /// 从环境变量创建新的重试策略
    ///
    /// Returns disabled policy if SB_RETRY_MAX is not set or is 0
    /// 如果未设置 SB_RETRY_MAX 或为 0，则返回禁用策略
    pub fn from_env() -> Self {
        let max_retries = std::env::var("SB_RETRY_MAX")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        if max_retries == 0 {
            debug!("Retry policy disabled (SB_RETRY_MAX not set or 0)");
            return Self::default();
        }

        let base_delay_ms = std::env::var("SB_RETRY_BASE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(100);

        let max_delay_ms = std::env::var("SB_RETRY_MAX_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2000);

        let jitter_factor = std::env::var("SB_RETRY_JITTER")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.2) // Default to 20% jitter
            .clamp(0.0, 1.0);

        debug!(
            "Retry policy enabled: max_retries={}, base_delay_ms={}, max_delay_ms={}, jitter_factor={}",
            max_retries, base_delay_ms, max_delay_ms, jitter_factor
        );

        Self {
            max_retries,
            base_delay: Duration::from_millis(base_delay_ms),
            max_delay: Duration::from_millis(max_delay_ms),
            jitter_factor,
        }
    }

    /// Check if retries are enabled
    /// 检查是否启用了重试
    pub fn is_enabled(&self) -> bool {
        self.max_retries > 0
    }

    /// Calculate delay for the given attempt number (1-based)
    /// 计算给定尝试次数（从 1 开始）的延迟
    ///
    /// Uses exponential backoff with jitter to prevent thundering herd
    /// 使用带抖动的指数退避以防止惊群效应
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        // Exponential backoff: base * 2^(attempt-1)
        // 指数退避: base * 2^(attempt-1)
        let exponential_factor = 2u32.saturating_pow(attempt - 1);
        let delay_ms = self.base_delay.as_millis() as u64 * exponential_factor as u64;

        // Cap at max delay
        // 限制在最大延迟
        let delay_ms = delay_ms.min(self.max_delay.as_millis() as u64);

        // Add jitter
        // 添加抖动
        let jitter_range = (delay_ms as f64 * self.jitter_factor) as u64;
        let jitter = if jitter_range > 0 {
            rand::thread_rng().gen_range(0..=jitter_range)
        } else {
            0
        };

        // Randomly add or subtract jitter
        // 随机增加或减少抖动
        let final_delay_ms = if rand::thread_rng().gen_bool(0.5) {
            delay_ms.saturating_add(jitter)
        } else {
            delay_ms.saturating_sub(jitter)
        };

        Duration::from_millis(final_delay_ms)
    }

    /// Execute an operation with retry logic
    /// 执行带重试逻辑的操作
    ///
    /// Only retries on specific error conditions (configurable via should_retry)
    /// 仅在特定错误条件下重试（可通过 should_retry 配置）
    pub async fn execute<T, E, F, Fut>(
        &self,
        operation_kind: &str,
        operation: F,
        should_retry: impl Fn(&E) -> bool,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        if !self.is_enabled() {
            return operation().await;
        }

        let mut attempt = 1;
        loop {
            match operation().await {
                Ok(result) => {
                    if attempt > 1 {
                        debug!(
                            "Operation '{}' succeeded after {} retries",
                            operation_kind,
                            attempt - 1
                        );
                        #[cfg(feature = "metrics")]
                        {
                            use crate::metrics_ext::get_or_register_counter_vec;
                            let ctr = get_or_register_counter_vec(
                                "retry_attempts_total",
                                "Total retry attempts",
                                &["kind", "result"],
                            );
                            ctr.with_label_values(&[operation_kind, "success"]).inc();
                        }
                    }
                    return Ok(result);
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    {
                        use crate::metrics_ext::get_or_register_counter_vec;
                        let ctr = get_or_register_counter_vec(
                            "retry_attempts_total",
                            "Total retry attempts",
                            &["kind", "error"],
                        );
                        ctr.with_label_values(&[operation_kind, "error"]).inc();
                    }

                    if attempt > self.max_retries {
                        warn!(
                            "Operation '{}' failed after {} attempts: {}",
                            operation_kind, attempt, e
                        );
                        return Err(e);
                    }

                    if !should_retry(&e) {
                        debug!(
                            "Operation '{}' failed with non-retriable error: {}",
                            operation_kind, e
                        );
                        return Err(e);
                    }

                    let delay = self.calculate_delay(attempt);
                    debug!(
                        "Operation '{}' failed (attempt {}/{}), retrying in {:?}: {}",
                        operation_kind, attempt, self.max_retries, delay, e
                    );

                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }
}

/// Helper for common retry conditions / 常见重试条件的助手
pub mod retry_conditions {
    use crate::dialer::DialError;
    use std::io::ErrorKind;

    /// Should retry on common transient network errors
    /// 是否应在常见的瞬态网络错误上重试
    pub fn is_transient_network_error(error: &DialError) -> bool {
        match error {
            DialError::Io(e) => matches!(
                e.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::TimedOut
                    | ErrorKind::Interrupted
            ),
            DialError::Other(msg) if msg == "timeout" => true,
            _ => false,
        }
    }

    /// Should retry on DNS resolution failures (often transient)
    /// 是否应在 DNS 解析失败（通常是瞬态的）上重试
    pub fn is_transient_dns_error(error: &DialError) -> bool {
        // Simple heuristic: if it's an IO error related to "not found" or "temporary failure"
        // 简单的启发式方法：如果是与“未找到”或“临时失败”相关的 IO 错误
        // In a real implementation, we might inspect the error message or inner error type
        // 在实际实现中，我们可能会检查错误消息或内部错误类型
        false // Placeholder / 占位符
    }

    /// Combined transient error detector for network operations
    /// 用于网络操作的组合瞬态错误检测器
    pub fn is_retriable_error(error: &DialError) -> bool {
        is_transient_network_error(error) || is_transient_dns_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_policy_default_disabled() {
        let policy = RetryPolicy::default();
        assert!(!policy.is_enabled());
        assert_eq!(policy.max_attempts, 0);
    }

    #[test]
    fn test_retry_policy_from_env_disabled() {
        std::env::remove_var("SB_RETRY_MAX");
        let policy = RetryPolicy::from_env();
        assert!(!policy.is_enabled());
    }

    #[test]
    fn test_retry_policy_from_env_enabled() {
        std::env::set_var("SB_RETRY_MAX", "3");
        std::env::set_var("SB_RETRY_BASE_MS", "200");
        std::env::set_var("SB_RETRY_JITTER", "0.2");

        let policy = RetryPolicy::from_env();
        assert!(policy.is_enabled());
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.base_delay_ms, 200);
        assert_eq!(policy.jitter, 0.2);

        // Cleanup
        std::env::remove_var("SB_RETRY_MAX");
        std::env::remove_var("SB_RETRY_BASE_MS");
        std::env::remove_var("SB_RETRY_JITTER");
    }

    #[test]
    fn test_calculate_delay_exponential_backoff() {
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 100,
            jitter: 0.0, // No jitter for predictable testing
        };

        // Attempt 0 should have no delay
        assert_eq!(policy.calculate_delay(0), Duration::ZERO);

        // Exponential backoff: 100ms, 200ms, 400ms, 800ms...
        let delay1 = policy.calculate_delay(1);
        let delay2 = policy.calculate_delay(2);
        let delay3 = policy.calculate_delay(3);

        assert!(delay1 >= Duration::from_millis(100) && delay1 < Duration::from_millis(110));
        assert!(delay2 >= Duration::from_millis(200) && delay2 < Duration::from_millis(220));
        assert!(delay3 >= Duration::from_millis(400) && delay3 < Duration::from_millis(440));
    }

    #[test]
    fn test_calculate_delay_with_jitter() {
        let policy = RetryPolicy {
            max_attempts: 1,
            base_delay_ms: 100,
            jitter: 0.5, // 50% jitter
        };

        // With 50% jitter, delay should be in range [50ms, 150ms]
        let delays: Vec<Duration> = (0..100).map(|_| policy.calculate_delay(1)).collect();

        // Check that all delays are within expected range
        for delay in &delays {
            assert!(
                *delay >= Duration::from_millis(50) && *delay <= Duration::from_millis(150),
                "Delay {:?} outside expected range [50ms, 150ms]",
                delay
            );
        }

        // Check that there's actually some variation (not all the same)
        let min_delay = delays.iter().min().unwrap();
        let max_delay = delays.iter().max().unwrap();
        assert!(
            *max_delay > *min_delay,
            "Expected variation in delays with jitter"
        );
    }

    #[tokio::test]
    async fn test_execute_success_first_attempt() {
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 10,
            jitter: 0.0,
        };

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let result = policy
            .execute(
                "test_op",
                || {
                    let count = call_count_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        Ok::<i32, &'static str>(42)
                    }
                },
                |_| true,
            )
            .await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_execute_success_after_retries() {
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 1, // Very short delay for fast test
            jitter: 0.0,
        };

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let result = policy
            .execute(
                "test_op",
                || {
                    let count = call_count_clone.clone();
                    async move {
                        let current_count = count.fetch_add(1, Ordering::Relaxed);
                        if current_count < 2 {
                            Err("transient error")
                        } else {
                            Ok::<i32, &'static str>(42)
                        }
                    }
                },
                |_| true, // Always retry
            )
            .await;

        assert_eq!(result, Ok(42));
        assert_eq!(call_count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_execute_max_retries_reached() {
        let policy = RetryPolicy {
            max_attempts: 2,
            base_delay_ms: 1,
            jitter: 0.0,
        };

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let result = policy
            .execute(
                "test_op",
                || {
                    let count = call_count_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        Err::<i32, &'static str>("permanent error")
                    }
                },
                |_| true,
            )
            .await;

        assert_eq!(result, Err("permanent error"));
        // Should try: initial + 2 retries = 3 total attempts
        assert_eq!(call_count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_execute_non_retriable_error() {
        let policy = RetryPolicy {
            max_attempts: 3,
            base_delay_ms: 1,
            jitter: 0.0,
        };

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let result = policy
            .execute(
                "test_op",
                || {
                    let count = call_count_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        Err::<i32, &'static str>("non-retriable error")
                    }
                },
                |_| false, // Never retry
            )
            .await;

        assert_eq!(result, Err("non-retriable error"));
        // Should only try once since error is not retriable
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_execute_disabled_policy() {
        let policy = RetryPolicy::default(); // Disabled by default

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let result = policy
            .execute(
                "test_op",
                || {
                    let count = call_count_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        Err::<i32, &'static str>("error")
                    }
                },
                |_| true,
            )
            .await;

        assert_eq!(result, Err("error"));
        // Should only try once since retries are disabled
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_retry_conditions() {
        use super::retry_conditions::*;
        use crate::dialer::DialError;
        use std::io::{Error, ErrorKind};

        // Test transient network errors
        let timeout_error = DialError::Io(Error::new(ErrorKind::TimedOut, "timeout"));
        assert!(is_transient_network_error(&timeout_error));

        let connection_refused = DialError::Io(Error::new(ErrorKind::ConnectionRefused, "refused"));
        assert!(is_transient_network_error(&connection_refused));

        let other_error = DialError::NotSupported;
        assert!(!is_transient_network_error(&other_error));

        // Test DNS errors
        let dns_error = DialError::Io(Error::other("failed to lookup address"));
        assert!(is_transient_dns_error(&dns_error));

        let dns_other = DialError::Other("dns resolution failed".to_string());
        assert!(is_transient_dns_error(&dns_other));
    }
}
