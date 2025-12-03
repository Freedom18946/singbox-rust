//! Circuit breaker pattern implementation for outbound connections
//!
//! Provides lightweight circuit breaker protection to prevent cascading failures
//! by temporarily blocking requests to failing upstream services.
//!
//! 提供轻量级的熔断器保护，通过暂时阻止对故障上游服务的请求来防止级联故障。
//!
//! ## States / 状态
//! - **Closed**: Normal operation, requests allowed / **关闭**: 正常运行，允许请求
//! - **Open**: Failing, requests blocked / **打开**: 故障中，请求被阻止
//! - **HalfOpen**: Testing recovery, limited requests allowed / **半开**: 测试恢复，允许有限请求
//!
//! ## Configuration
//! - `SB_CB_FAILS`: Failure threshold to trip circuit (default: 5)
//! - `SB_CB_WINDOW_MS`: Sliding window duration in milliseconds (default: 30000)
//! - `SB_CB_HALFOPEN_MAX`: Maximum concurrent half-open probes (default: 1)
//!
//! ## Strategic Relevance / 战略关联
//! - **Reliability**: Prevents system resource exhaustion when upstreams are down.
//!   **可靠性**：当上游服务宕机时，防止系统资源耗尽。
//! - **Fault Tolerance**: Allows the system to fail fast and recover automatically.
//!   **容错性**：允许系统快速失败并自动恢复。
//! - **Global Protection**: Applied globally to outbound connections to ensure stability.
//!   **全局保护**：全局应用于出站连接以确保稳定性。

use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

/// Circuit breaker state enum / 熔断器状态枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    /// 正常运行 - 请求通过
    Closed,
    /// Circuit is open - requests are rejected
    /// 熔断器打开 - 请求被拒绝
    Open,
    /// Limited requests allowed to test recovery
    /// 允许有限的请求以测试恢复
    HalfOpen,
}

impl CircuitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half-open",
        }
    }
}

/// Configuration for circuit breaker behavior / 熔断器行为配置
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to trip the breaker (count)
    /// 触发熔断的失败阈值（次数）
    pub failure_threshold: u32,
    /// Duration to keep the breaker open before testing recovery
    /// 在测试恢复之前保持熔断器打开的持续时间
    pub recovery_timeout: Duration,
    /// Time window for counting failures
    /// 统计失败的时间窗口
    pub failure_window: Duration,
    /// Max concurrent requests in HalfOpen state
    /// 半开状态下的最大并发请求数
    pub half_open_max_requests: u32,
    /// Whether to count timeouts as failures
    /// 是否将超时计为失败
    pub count_timeouts: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60), // 1 minute
            failure_window: Duration::from_secs(30),   // 30 seconds
            half_open_max_requests: 1,
            count_timeouts: true,
        }
    }
}

impl CircuitBreakerConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let failure_threshold = std::env::var("SB_CB_FAILS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let window_duration_ms = std::env::var("SB_CB_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30_000);

        let half_open_max_calls = std::env::var("SB_CB_HALFOPEN_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        // Open timeout is calculated as 2x window duration by default
        let open_timeout_ms = std::env::var("SB_CB_OPEN_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(window_duration_ms * 2);

        debug!(
            "Circuit breaker config: failures={}, window_ms={}, half_open_max={}, open_timeout_ms={}",
            failure_threshold, window_duration_ms, half_open_max_calls, open_timeout_ms
        );

        let count_timeouts = std::env::var("SB_CB_COUNT_TIMEOUTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true);

        Self {
            failure_threshold,
            failure_window: Duration::from_millis(window_duration_ms),
            half_open_max_requests: half_open_max_calls,
            recovery_timeout: Duration::from_millis(open_timeout_ms),
            count_timeouts,
        }
    }
}

/// Sliding window for tracking recent failures
#[derive(Debug)]
pub struct SlidingWindow {
    failures: VecDeque<Instant>,
    window_duration: Duration,
}

impl SlidingWindow {
    fn new(window_duration: Duration) -> Self {
        Self {
            failures: VecDeque::new(),
            window_duration,
        }
    }

    /// Add a failure timestamp
    fn add_failure(&mut self) {
        let now = Instant::now();
        self.failures.push_back(now);
        self.cleanup_old(now);
    }

    /// Add a success (doesn't affect failure count but triggers cleanup)
    fn add_success(&mut self) {
        self.cleanup_old(Instant::now());
    }

    /// Get current failure count in window
    fn failure_count(&mut self) -> u32 {
        self.cleanup_old(Instant::now());
        self.failures.len() as u32
    }

    /// Remove failures outside the window
    fn cleanup_old(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window_duration).unwrap_or(now);
        while let Some(&front) = self.failures.front() {
            if front < cutoff {
                self.failures.pop_front();
            } else {
                break;
            }
        }
    }

    /// Reset all failure history
    fn reset(&mut self) {
        self.failures.clear();
    }
}

/// Internal circuit breaker state / 熔断器内部状态
#[derive(Debug)]
pub struct CircuitBreakerState {
    /// Current state of the circuit
    /// 当前熔断器状态
    pub state: CircuitState,
    /// Timestamp of the last state change
    /// 上次状态变更的时间戳
    pub last_state_change: Instant,
    /// Sliding window for tracking failures
    /// 用于跟踪失败的滑动窗口
    pub failures: SlidingWindow,
    /// Number of concurrent requests in HalfOpen state
    /// 半开状态下的并发请求数
    pub half_open_requests: u32,
    /// Timestamp of the last metrics update
    /// 上次指标更新的时间戳
    pub last_metrics_update: Instant,
}

impl CircuitBreakerState {
    fn new(config: &CircuitBreakerConfig) -> Self {
        let now = Instant::now();
        Self {
            state: CircuitState::Closed,
            last_state_change: now,
            failures: SlidingWindow::new(config.failure_window),
            half_open_requests: 0,
            last_metrics_update: now,
        }
    }
}

/// Circuit breaker for protecting outbound connections / 用于保护出站连接的熔断器
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Name of the outbound/service being protected (for logging)
    /// 受保护的出站/服务名称（用于日志记录）
    pub outbound_name: String,
    /// Configuration
    /// 配置
    pub config: CircuitBreakerConfig,
    /// Shared state protected by mutex
    /// 由互斥锁保护的共享状态
    pub state: Mutex<CircuitBreakerState>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for the given outbound
    pub fn new(outbound_name: String, config: CircuitBreakerConfig) -> Self {
        let circuit_breaker = Self {
            outbound_name: outbound_name.clone(),
            config: config.clone(),
            state: Mutex::new(CircuitBreakerState::new(&config)),
        };

        // Initialize metrics
        circuit_breaker.update_metrics(CircuitState::Closed);

        circuit_breaker
    }

    /// Create with configuration from environment variables
    pub fn from_env(outbound_name: String) -> Self {
        Self::new(outbound_name, CircuitBreakerConfig::from_env())
    }

    /// Check if a request should be allowed through
    /// 检查是否允许请求通过
    pub async fn allow_request(&self) -> CircuitBreakerDecision {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        // Check if we should transition from Open to HalfOpen
        // 检查是否应从 Open 状态转换为 HalfOpen 状态
        if state.state == CircuitState::Open {
            let time_in_open = now.duration_since(state.last_state_change);
            if time_in_open >= self.config.recovery_timeout {
                debug!(
                    "Circuit breaker for {} transitioning from Open to HalfOpen",
                    self.outbound_name
                );
                state.state = CircuitState::HalfOpen;
                state.last_state_change = now;
                state.half_open_requests = 0; // Reset half-open count for new phase
                self.update_metrics_locked(&mut state, CircuitState::HalfOpen);
            }
        }

        match state.state {
            CircuitState::Closed => {
                trace!(
                    "Circuit breaker {} closed - allowing request",
                    self.outbound_name
                );
                CircuitBreakerDecision::Allow
            }
            CircuitState::Open => {
                trace!(
                    "Circuit breaker {} open - rejecting request",
                    self.outbound_name
                );
                CircuitBreakerDecision::Reject
            }
            CircuitState::HalfOpen => {
                if state.half_open_requests < self.config.half_open_max_requests {
                    state.half_open_requests += 1;
                    trace!(
                        "Circuit breaker {} half-open - allowing probe request ({} of {})",
                        self.outbound_name,
                        state.half_open_requests,
                        self.config.half_open_max_requests
                    );
                    CircuitBreakerDecision::Allow
                } else {
                    trace!(
                        "Circuit breaker {} half-open - rejecting request (max probes reached)",
                        self.outbound_name
                    );
                    CircuitBreakerDecision::Reject
                }
            }
        }
    }

    /// Record the result of a request
    pub async fn record_result(&self, success: bool, is_timeout: bool) {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        if success {
            self.on_success(&mut state, now);
        } else {
            self.on_failure(&mut state, now, is_timeout);
        }
    }

    /// Handle successful request
    /// 处理成功的请求
    fn on_success(&self, state: &mut CircuitBreakerState, now: Instant) {
        match state.state {
            CircuitState::Closed => {
                // Just record success to clean up old failures
                // 仅记录成功以清理旧的失败记录
                state.failures.add_success();
                trace!(
                    "Circuit breaker {} success in closed state",
                    self.outbound_name
                );
            }
            CircuitState::HalfOpen => {
                // Success in HalfOpen -> Close the circuit
                // HalfOpen 状态下成功 -> 关闭熔断器
                debug!(
                    "Circuit breaker for {} recovering: HalfOpen -> Closed",
                    self.outbound_name
                );
                state.state = CircuitState::Closed;
                state.last_state_change = now;
                state.half_open_requests = 0;
                // Reset failure history on recovery
                // 恢复时重置失败历史
                state.failures.reset();
                self.update_metrics_locked(state, CircuitState::Closed);
            }
            CircuitState::Open => {
                // Should not happen, but if it does, maybe we should close?
                // 不应发生，但如果发生，也许我们应该关闭？
                warn!(
                    "Circuit breaker for {} received success while Open",
                    self.outbound_name
                );
            }
        }
    }

    /// Handle failed request
    fn on_failure(&self, state: &mut CircuitBreakerState, now: Instant, is_timeout: bool) {
        // Check if this failure should count towards circuit breaker
        // Timeouts and cancellations can be configurable
        if !self.should_count_failure(is_timeout) {
            return;
        }

        match state.state {
            CircuitState::Closed => {
                state.failures.add_failure();
                if state.failures.failure_count() >= self.config.failure_threshold {
                    // Trip the breaker
                    // 触发熔断
                    debug!(
                        "Circuit breaker for {} tripped: Closed -> Open (failures: {})",
                        self.outbound_name,
                        state.failures.failure_count()
                    );
                    state.state = CircuitState::Open;
                    state.last_state_change = now;
                    self.update_metrics_locked(state, CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Failure in HalfOpen -> Reopen the circuit
                // HalfOpen 状态下失败 -> 重新打开熔断器
                debug!(
                    "Circuit breaker for {} probe failed: HalfOpen -> Open",
                    self.outbound_name
                );
                state.state = CircuitState::Open;
                state.last_state_change = now;
                state.half_open_requests -= 1;
                self.update_metrics_locked(state, CircuitState::Open);
            }
            CircuitState::Open => {
                // Already open, just update timestamp to extend timeout?
                // Usually we don't extend timeout on blocked requests
                // 已经打开，是否更新时间戳以延长超时？
                // 通常我们不会在被阻止的请求上延长超时
            }
        }
    }

    /// Determine if a failure should count towards circuit breaker
    /// 确定失败是否应计入熔断器
    ///
    /// Can be made configurable via environment variables
    /// 可通过环境变量进行配置
    fn should_count_failure(&self, is_timeout: bool) -> bool {
        // By default, count all failures including timeouts
        if is_timeout {
            self.config.count_timeouts
        } else {
            true
        }
    }

    /// Get current circuit state
    pub async fn state(&self) -> CircuitState {
        self.state.lock().await.state
    }

    /// Get current failure count in window
    pub async fn failure_count(&self) -> u32 {
        self.state.lock().await.failures.failure_count()
    }

    /// Update metrics
    fn update_metrics(&self, _state: CircuitState) {
        #[cfg(feature = "metrics")]
        {
            use crate::metrics_ext::get_or_register_gauge_vec_f64;
            let gauge = get_or_register_gauge_vec_f64(
                "circuit_state",
                "Circuit breaker state",
                &["outbound", "state"],
            );
            gauge
                .with_label_values(&[self.outbound_name.as_str(), _state.as_str()])
                .set(1.0);
        }
    }

    /// Update metrics with lock already held
    fn update_metrics_locked(&self, state: &mut CircuitBreakerState, circuit_state: CircuitState) {
        let now = Instant::now();
        // Throttle metrics updates to avoid excessive overhead
        if now.duration_since(state.last_metrics_update) >= Duration::from_millis(1000) {
            self.update_metrics(circuit_state);
            state.last_metrics_update = now;
        }
    }

    /// Force reset circuit to closed state (for testing/admin)
    pub async fn reset(&self) {
        let mut state = self.state.lock().await;
        debug!(
            "Circuit breaker {} reset to closed state",
            self.outbound_name
        );
        state.state = CircuitState::Closed;
        state.last_state_change = Instant::now();
        state.half_open_requests = 0;
        state.failures.reset();
        self.update_metrics(CircuitState::Closed);
    }
}

/// Decision from circuit breaker
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerDecision {
    /// Request should be allowed through
    Allow,
    /// Request should be rejected
    Reject,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 3,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 1,
                recovery_timeout: Duration::from_millis(2000),
                count_timeouts: true,
            },
        );

        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(matches!(
            cb.allow_request().await,
            CircuitBreakerDecision::Allow
        ));
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 2,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 1,
                recovery_timeout: Duration::from_millis(100),
                count_timeouts: true,
            },
        );

        // Initially closed
        assert_eq!(cb.state().await, CircuitState::Closed);

        // First failure - should remain closed
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        // Second failure - should open
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Requests should be rejected
        assert!(matches!(
            cb.allow_request().await,
            CircuitBreakerDecision::Reject
        ));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_transition() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 2,
                recovery_timeout: Duration::from_millis(50), // Short timeout for test
                count_timeouts: true,
            },
        );

        // Force open state
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Next request should transition to half-open
        assert!(matches!(
            cb.allow_request().await,
            CircuitBreakerDecision::Allow
        ));
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Should allow up to max calls in half-open
        assert!(matches!(
            cb.allow_request().await,
            CircuitBreakerDecision::Allow
        ));
        assert!(matches!(
            cb.allow_request().await,
            CircuitBreakerDecision::Reject
        ));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_success_closes() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 1,
                recovery_timeout: Duration::from_millis(50),
                count_timeouts: true,
            },
        );

        // Force to half-open via failure then timeout
        cb.record_result(false, false).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        cb.allow_request().await; // Transition to half-open

        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Success in half-open should close circuit
        cb.record_result(true, false).await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_failure_reopens() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 1,
                recovery_timeout: Duration::from_millis(50),
                count_timeouts: true,
            },
        );

        // Force to half-open
        cb.record_result(false, false).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        cb.allow_request().await;

        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Failure in half-open should reopen circuit
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_sliding_window_cleanup() {
        let mut window = SlidingWindow::new(Duration::from_millis(100));

        // Add some failures
        window.add_failure();
        window.add_failure();
        assert_eq!(window.failure_count(), 2);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(120)).await;

        // Should be cleaned up
        assert_eq!(window.failure_count(), 0);
    }

    #[tokio::test]
    async fn test_timeout_failure_handling() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 2,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 1,
                recovery_timeout: Duration::from_millis(100),
                count_timeouts: false,
            },
        );

        // Timeout failures shouldn't count
        cb.record_result(false, true).await; // timeout
        cb.record_result(false, true).await; // timeout
        assert_eq!(cb.state().await, CircuitState::Closed);

        // Regular failures should count
        cb.record_result(false, false).await;
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("SB_CB_FAILS", "10");
        std::env::set_var("SB_CB_WINDOW_MS", "5000");
        std::env::set_var("SB_CB_HALFOPEN_MAX", "3");

        let config = CircuitBreakerConfig::from_env();
        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.failure_window, Duration::from_millis(5000));
        assert_eq!(config.half_open_max_requests, 3);

        // Clean up
        std::env::remove_var("SB_CB_FAILS");
        std::env::remove_var("SB_CB_WINDOW_MS");
        std::env::remove_var("SB_CB_HALFOPEN_MAX");
    }

    #[tokio::test]
    async fn test_reset_functionality() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                failure_window: Duration::from_millis(1000),
                half_open_max_requests: 1,
                recovery_timeout: Duration::from_millis(100),
                count_timeouts: true,
            },
        );

        // Force open
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Reset should close
        cb.reset().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert_eq!(cb.failure_count().await, 0);
    }
}
