//! Circuit breaker pattern implementation for outbound connections
//!
//! Provides lightweight circuit breaker protection to prevent cascading failures
//! by temporarily blocking requests to failing upstream services.
//!
//! ## States
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Circuit is open, most requests are rejected
//! - **Half-Open**: Limited requests allowed to test if service recovered
//!
//! ## Configuration
//! - `SB_CB_FAILS`: Failure threshold to trip circuit (default: 5)
//! - `SB_CB_WINDOW_MS`: Sliding window duration in milliseconds (default: 30000)
//! - `SB_CB_HALFOPEN_MAX`: Maximum concurrent half-open probes (default: 1)

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Circuit is open - requests are rejected
    Open,
    /// Limited requests allowed to test recovery
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

/// Configuration for circuit breaker behavior
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures in window to trigger open state
    pub failure_threshold: u32,
    /// Time window for counting failures (milliseconds)
    pub window_duration_ms: u64,
    /// Maximum concurrent half-open probe requests
    pub half_open_max_calls: u32,
    /// Time to wait before transitioning from open to half-open
    pub open_timeout_ms: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            window_duration_ms: 30_000, // 30 seconds
            half_open_max_calls: 1,
            open_timeout_ms: 60_000, // 1 minute
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

        Self {
            failure_threshold,
            window_duration_ms,
            half_open_max_calls,
            open_timeout_ms,
        }
    }
}

/// Sliding window for tracking recent failures
#[derive(Debug)]
struct SlidingWindow {
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

/// Internal circuit breaker state
#[derive(Debug)]
struct CircuitBreakerState {
    state: CircuitState,
    failure_window: SlidingWindow,
    state_changed_at: Instant,
    half_open_calls: u32,
    last_metrics_update: Instant,
}

impl CircuitBreakerState {
    fn new(config: &CircuitBreakerConfig) -> Self {
        let now = Instant::now();
        Self {
            state: CircuitState::Closed,
            failure_window: SlidingWindow::new(Duration::from_millis(config.window_duration_ms)),
            state_changed_at: now,
            half_open_calls: 0,
            last_metrics_update: now,
        }
    }
}

/// Circuit breaker for protecting outbound connections
#[derive(Debug)]
pub struct CircuitBreaker {
    outbound_name: String,
    config: CircuitBreakerConfig,
    state: Arc<Mutex<CircuitBreakerState>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for the given outbound
    pub fn new(outbound_name: String, config: CircuitBreakerConfig) -> Self {
        let cfg = config.clone(); // 用于 state 初始化的只读快照
        let circuit_breaker = Self {
            outbound_name: outbound_name.clone(),
            config,
            state: Arc::new(Mutex::new(CircuitBreakerState::new(&cfg))),
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
    pub async fn allow_request(&self) -> CircuitBreakerDecision {
        let mut state = self.state.lock().await;
        let now = Instant::now();

        match state.state {
            CircuitState::Closed => {
                trace!(
                    "Circuit breaker {} closed - allowing request",
                    self.outbound_name
                );
                CircuitBreakerDecision::Allow
            }
            CircuitState::Open => {
                // Check if we should transition to half-open
                let time_in_open = now.duration_since(state.state_changed_at);
                if time_in_open >= Duration::from_millis(self.config.open_timeout_ms) {
                    debug!(
                        "Circuit breaker {} transitioning from open to half-open",
                        self.outbound_name
                    );
                    state.state = CircuitState::HalfOpen;
                    state.state_changed_at = now;
                    state.half_open_calls = 1;
                    self.update_metrics_locked(&mut state, CircuitState::HalfOpen);
                    CircuitBreakerDecision::Allow
                } else {
                    trace!(
                        "Circuit breaker {} open - rejecting request",
                        self.outbound_name
                    );
                    CircuitBreakerDecision::Reject
                }
            }
            CircuitState::HalfOpen => {
                if state.half_open_calls < self.config.half_open_max_calls {
                    state.half_open_calls += 1;
                    trace!(
                        "Circuit breaker {} half-open - allowing probe request",
                        self.outbound_name
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
    fn on_success(&self, state: &mut CircuitBreakerState, now: Instant) {
        state.failure_window.add_success();

        match state.state {
            CircuitState::HalfOpen => {
                // Success in half-open means we can close the circuit
                debug!(
                    "Circuit breaker {} half-open success - closing circuit",
                    self.outbound_name
                );
                state.state = CircuitState::Closed;
                state.state_changed_at = now;
                state.half_open_calls = 0;
                state.failure_window.reset(); // Reset failure history on recovery
                self.update_metrics_locked(state, CircuitState::Closed);
            }
            CircuitState::Closed => {
                // Normal success in closed state
                trace!(
                    "Circuit breaker {} success in closed state",
                    self.outbound_name
                );
            }
            CircuitState::Open => {
                // This shouldn't happen if allow_request is used correctly
                warn!(
                    "Circuit breaker {} received success in open state",
                    self.outbound_name
                );
            }
        }
    }

    /// Handle failed request
    fn on_failure(&self, state: &mut CircuitBreakerState, now: Instant, is_timeout: bool) {
        // Check if this failure should count towards circuit breaker
        // Timeouts and cancellations can be configurable
        let should_count = self.should_count_failure(is_timeout);

        if should_count {
            state.failure_window.add_failure();
            trace!("Circuit breaker {} recorded failure", self.outbound_name);
        } else {
            trace!(
                "Circuit breaker {} ignoring failure (timeout/cancel)",
                self.outbound_name
            );
        }

        match state.state {
            CircuitState::Closed => {
                if should_count {
                    let failure_count = state.failure_window.failure_count();
                    if failure_count >= self.config.failure_threshold {
                        // Trip the circuit
                        warn!(
                            "Circuit breaker {} opening due to {} failures in window",
                            self.outbound_name, failure_count
                        );
                        state.state = CircuitState::Open;
                        state.state_changed_at = now;
                        self.update_metrics_locked(state, CircuitState::Open);
                    }
                }
            }
            CircuitState::HalfOpen => {
                if should_count {
                    // Failure in half-open means we go back to open
                    debug!(
                        "Circuit breaker {} half-open failure - returning to open",
                        self.outbound_name
                    );
                    state.state = CircuitState::Open;
                    state.state_changed_at = now;
                    state.half_open_calls = 0;
                    self.update_metrics_locked(state, CircuitState::Open);
                }
            }
            CircuitState::Open => {
                // Additional failure in open state
                trace!(
                    "Circuit breaker {} additional failure in open state",
                    self.outbound_name
                );
            }
        }
    }

    /// Determine if a failure should count towards circuit breaker
    /// Can be made configurable via environment variables
    fn should_count_failure(&self, is_timeout: bool) -> bool {
        // By default, count all failures including timeouts
        // This can be made configurable with SB_CB_COUNT_TIMEOUTS=false
        if is_timeout {
            std::env::var("SB_CB_COUNT_TIMEOUTS")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true)
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
        self.state.lock().await.failure_window.failure_count()
    }

    /// Update metrics
    fn update_metrics(&self, _state: CircuitState) {
        #[cfg(feature = "metrics")]
        {
            use sb_core::metrics::registry_ext::get_or_register_gauge_vec_f64;
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
        state.state_changed_at = Instant::now();
        state.half_open_calls = 0;
        state.failure_window.reset();
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
    use std::thread;

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 3,
                window_duration_ms: 1000,
                half_open_max_calls: 1,
                open_timeout_ms: 2000,
            },
        );

        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(matches!(cb.allow_request().await, CircuitBreakerDecision::Allow));
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 2,
                window_duration_ms: 1000,
                half_open_max_calls: 1,
                open_timeout_ms: 100,
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
        assert!(matches!(cb.allow_request().await, CircuitBreakerDecision::Reject));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_transition() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                window_duration_ms: 1000,
                half_open_max_calls: 2,
                open_timeout_ms: 50, // Short timeout for test
            },
        );

        // Force open state
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for timeout
        thread::sleep(Duration::from_millis(60));

        // Next request should transition to half-open
        assert!(matches!(cb.allow_request().await, CircuitBreakerDecision::Allow));
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Should allow up to max calls in half-open
        assert!(matches!(cb.allow_request().await, CircuitBreakerDecision::Allow));
        assert!(matches!(cb.allow_request().await, CircuitBreakerDecision::Reject));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_success_closes() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                window_duration_ms: 1000,
                half_open_max_calls: 1,
                open_timeout_ms: 50,
            },
        );

        // Force to half-open via failure then timeout
        cb.record_result(false, false).await;
        thread::sleep(Duration::from_millis(60));
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
                window_duration_ms: 1000,
                half_open_max_calls: 1,
                open_timeout_ms: 50,
            },
        );

        // Force to half-open
        cb.record_result(false, false).await;
        thread::sleep(Duration::from_millis(60));
        cb.allow_request().await;

        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Failure in half-open should reopen circuit
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);
    }

    #[test]
    fn test_sliding_window_cleanup() {
        let mut window = SlidingWindow::new(Duration::from_millis(100));

        // Add some failures
        window.add_failure();
        window.add_failure();
        assert_eq!(window.failure_count(), 2);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(120));

        // Should be cleaned up
        assert_eq!(window.failure_count(), 0);
    }

    #[tokio::test]
    async fn test_timeout_failure_handling() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 2,
                window_duration_ms: 1000,
                half_open_max_calls: 1,
                open_timeout_ms: 100,
            },
        );

        // Set environment to not count timeouts
        std::env::set_var("SB_CB_COUNT_TIMEOUTS", "false");

        // Timeout failures shouldn't count
        cb.record_result(false, true).await; // timeout
        cb.record_result(false, true).await; // timeout
        assert_eq!(cb.state().await, CircuitState::Closed);

        // Regular failures should count
        cb.record_result(false, false).await;
        cb.record_result(false, false).await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Clean up
        std::env::remove_var("SB_CB_COUNT_TIMEOUTS");
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("SB_CB_FAILS", "10");
        std::env::set_var("SB_CB_WINDOW_MS", "5000");
        std::env::set_var("SB_CB_HALFOPEN_MAX", "3");

        let config = CircuitBreakerConfig::from_env();
        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.window_duration_ms, 5000);
        assert_eq!(config.half_open_max_calls, 3);

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
                window_duration_ms: 1000,
                half_open_max_calls: 1,
                open_timeout_ms: 100,
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
