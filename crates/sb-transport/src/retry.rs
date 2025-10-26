//! Unified retry and backoff strategy for idempotent I/O operations
//!
//! This module provides configurable retry policies with exponential backoff and jitter
//! for improving reliability of network operations while avoiding thundering herd problems.
//!
//! ## Configuration
//! - `SB_RETRY_MAX`: Maximum number of retry attempts (default: disabled)
//! - `SB_RETRY_BASE_MS`: Base delay in milliseconds (default: 100ms)
//! - `SB_RETRY_JITTER`: Jitter percentage 0.0-1.0 (default: 0.1 = 10%)
//!
//! ## Safety
//! Only use for idempotent operations (GET requests, connection establishment, etc.)
//! Non-idempotent operations are disabled by default.

use rand::Rng;
use std::time::Duration;
use tracing::{debug, warn};

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries)
    pub max_attempts: u32,
    /// Base delay between retries in milliseconds
    pub base_delay_ms: u64,
    /// Jitter factor (0.0 - 1.0) to randomize delays
    pub jitter: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 0, // Default: no retries
            base_delay_ms: 100,
            jitter: 0.1, // 10% jitter
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy from environment variables
    /// Returns disabled policy if SB_RETRY_MAX is not set or is 0
    pub fn from_env() -> Self {
        let max_attempts = std::env::var("SB_RETRY_MAX")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        if max_attempts == 0 {
            debug!("Retry policy disabled (SB_RETRY_MAX not set or 0)");
            return Self::default();
        }

        let base_delay_ms = std::env::var("SB_RETRY_BASE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100);

        let jitter = std::env::var("SB_RETRY_JITTER")
            .ok()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.1)
            .clamp(0.0, 1.0);

        debug!(
            "Retry policy enabled: max_attempts={}, base_delay_ms={}, jitter={}",
            max_attempts, base_delay_ms, jitter
        );

        Self {
            max_attempts,
            base_delay_ms,
            jitter,
        }
    }

    /// Check if retries are enabled
    pub fn is_enabled(&self) -> bool {
        self.max_attempts > 0
    }

    /// Calculate delay for the given attempt number (1-based)
    /// Uses exponential backoff with jitter to prevent thundering herd
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        // Exponential backoff: base_delay * 2^(attempt-1)
        let base_delay =
            self.base_delay_ms as f64 * (1u64 << (attempt.saturating_sub(1).min(10))) as f64;

        // Add jitter: ±jitter% of the base delay
        let mut rng = rand::thread_rng();
        let jitter_range = base_delay * self.jitter;
        let jitter_offset = rng.gen_range(-jitter_range..=jitter_range);
        let final_delay = (base_delay + jitter_offset).max(0.0);

        Duration::from_millis(final_delay as u64)
    }

    /// Execute an operation with retry logic
    /// Only retries on specific error conditions (configurable via should_retry)
    pub async fn execute<F, Fut, T, E>(
        &self,
        operation_kind: &str,
        operation: F,
        should_retry: impl Fn(&E) -> bool,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        if !self.is_enabled() {
            return operation().await;
        }

        // Track is not needed as we return on final attempt

        for attempt in 0..=self.max_attempts {
            match operation().await {
                Ok(result) => {
                    if attempt > 0 {
                        debug!(
                            "Operation '{}' succeeded after {} retries",
                            operation_kind, attempt
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
                Err(error) => {
                    // Record the attempt
                    #[cfg(feature = "metrics")]
                    {
                        use crate::metrics_ext::get_or_register_counter_vec;
                        let ctr = get_or_register_counter_vec(
                            "retry_attempts_total",
                            "Total retry attempts",
                            &["kind", "result"],
                        );
                        ctr.with_label_values(&[operation_kind, "error"]).inc();
                    }

                    // Check if we should retry
                    if attempt >= self.max_attempts || !should_retry(&error) {
                        warn!(
                            "Operation '{}' failed after {} attempts, giving up",
                            operation_kind,
                            attempt + 1
                        );
                        return Err(error);
                    }

                    debug!(
                        "Operation '{}' failed on attempt {}, will retry",
                        operation_kind,
                        attempt + 1
                    );

                    // remember last error only if needed (not required)

                    // Wait before retry (skip delay on first attempt)
                    if attempt < self.max_attempts {
                        let delay = self.calculate_delay(attempt + 1);
                        debug!("Waiting {:?} before retry {}", delay, attempt + 2);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        // This should never be reached; as a safe fallback, perform one more attempt
        // and return its result to avoid constructing a generic error.
        operation().await
    }
}

/// Helper for common retry conditions
pub mod retry_conditions {
    use crate::dialer::DialError;
    use std::io::ErrorKind;

    /// Should retry on common transient network errors
    pub fn is_transient_network_error(error: &DialError) -> bool {
        match error {
            DialError::Io(io_error) => {
                matches!(
                    io_error.kind(),
                    ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::TimedOut
                        | ErrorKind::Interrupted
                        | ErrorKind::UnexpectedEof
                )
            }
            DialError::Other(msg) if msg.contains("timeout") => true,
            _ => false,
        }
    }

    /// Should retry on DNS resolution failures (often transient)
    pub fn is_transient_dns_error(error: &DialError) -> bool {
        match error {
            DialError::Io(io_error) => {
                // DNS resolution errors often appear as "failed to lookup address information"
                io_error.to_string().contains("failed to lookup address")
            }
            DialError::Other(msg) => msg.contains("dns") || msg.contains("resolve"),
            _ => false,
        }
    }

    /// Combined transient error detector for network operations
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
