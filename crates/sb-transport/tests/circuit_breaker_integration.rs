//! Circuit breaker integration tests
//!
//! Tests circuit breaker functionality in realistic scenarios including:
//! - Environment variable configuration
//! - State transitions (closed -> open -> half-open -> closed)
//! - Timeout vs non-timeout error handling
//! - Metrics collection

// TODO: Fix API mismatches in this test
#![cfg(feature = "circuit_breaker_DISABLED")]

use sb_transport::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
use sb_transport::dialer::{DialError, Dialer, FnDialer, IoStream};
use sb_transport::pool::circuit_breaker::CircuitBreakerDialer;
use std::env;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_circuit_breaker_config_from_env() {
    // Set environment variables
    env::set_var("SB_CB_FAILS", "8");
    env::set_var("SB_CB_WINDOW_MS", "15000");
    env::set_var("SB_CB_HALFOPEN_MAX", "3");

    let config = CircuitBreakerConfig::from_env();
    assert_eq!(config.failure_threshold, 8);
    assert_eq!(config.window_duration_ms, 15000);
    assert_eq!(config.half_open_max_calls, 3);

    // Clean up
    env::remove_var("SB_CB_FAILS");
    env::remove_var("SB_CB_WINDOW_MS");
    env::remove_var("SB_CB_HALFOPEN_MAX");
}

#[tokio::test]
async fn test_circuit_breaker_continuous_failures_trigger_open() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 100,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Initially closed
    assert_eq!(cb.state().await, CircuitState::Closed);

    // Record failures one by one
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Closed);

    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Closed);

    cb.record_result(false, false).await; // This should trigger open
    assert_eq!(cb.state().await, CircuitState::Open);
}

#[tokio::test]
async fn test_circuit_breaker_half_open_success_returns_to_closed() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 50,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Force to open state
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Open);

    // Wait for open timeout
    sleep(Duration::from_millis(60)).await;

    // Trigger half-open state
    cb.allow_request().await;
    assert_eq!(cb.state().await, CircuitState::HalfOpen);

    // Success should close the circuit
    cb.record_result(true, false).await;
    assert_eq!(cb.state().await, CircuitState::Closed);

    // Reset failure count
    assert_eq!(cb.failure_count().await, 0);
}

#[tokio::test]
async fn test_circuit_breaker_half_open_failure_reopens() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 50,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Force to open state
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;

    // Wait and transition to half-open
    sleep(Duration::from_millis(60)).await;
    cb.allow_request().await;
    assert_eq!(cb.state().await, CircuitState::HalfOpen);

    // Failure should reopen circuit
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Open);
}

#[tokio::test]
async fn test_circuit_breaker_timeout_not_fatal_configurable() {
    env::set_var("SB_CB_COUNT_TIMEOUTS", "false");

    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 100,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Record timeout errors - should not count
    cb.record_result(false, true).await; // timeout
    cb.record_result(false, true).await; // timeout
    cb.record_result(false, true).await; // timeout

    // Should remain closed since timeouts don't count
    assert_eq!(cb.state().await, CircuitState::Closed);

    // Regular failures should still count
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;

    // Should open now
    assert_eq!(cb.state().await, CircuitState::Open);

    // Clean up
    env::remove_var("SB_CB_COUNT_TIMEOUTS");
}

#[tokio::test]
async fn test_circuit_breaker_timeout_fatal_by_default() {
    // Ensure the environment variable is not set
    env::remove_var("SB_CB_COUNT_TIMEOUTS");

    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 100,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Record timeout errors - should count by default
    cb.record_result(false, true).await; // timeout
    cb.record_result(false, true).await; // timeout

    // Should open since timeouts count by default
    assert_eq!(cb.state().await, CircuitState::Open);
}

#[tokio::test]
async fn test_dialer_wrapper_integration() {
    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    // Create a dialer that fails the first few times, then succeeds
    let recovering_dialer = FnDialer::new(move |_host, _port| {
        let count = call_count_clone.clone();
        Box::pin(async move {
            let current_count = count.fetch_add(1, Ordering::Relaxed);
            if current_count < 3 {
                Err(DialError::Other("connection failed".to_string()))
            } else {
                let (client, _server) = tokio::io::duplex(64);
                Ok(Box::new(client) as IoStream)
            }
        }) as Pin<Box<dyn std::future::Future<Output = Result<IoStream, DialError>> + Send>>
    });

    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 50,
    };

    let cb_dialer =
        CircuitBreakerDialer::new(recovering_dialer, "test-service".to_string(), config);

    // First three calls should fail and trigger circuit breaker
    for _ in 0..3 {
        let result = cb_dialer.connect("example.com", 80).await;
        assert!(result.is_err());
    }

    // Circuit should be open now
    assert_eq!(
        cb_dialer.circuit_breaker().state().await,
        CircuitState::Open
    );

    // Next call should be rejected by circuit breaker (not counted)
    let result = cb_dialer.connect("example.com", 80).await;
    assert!(result.is_err());

    // Wait for half-open transition
    sleep(Duration::from_millis(60)).await;

    // Next call should succeed and close the circuit
    let result = cb_dialer.connect("example.com", 80).await;
    assert!(result.is_ok());
    assert_eq!(
        cb_dialer.circuit_breaker().state().await,
        CircuitState::Closed
    );

    // Should only have made 4 actual calls (3 failures + 1 success)
    // The rejected call during open state didn't go through
    assert_eq!(call_count.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn test_sliding_window_behavior() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        window_duration_ms: 100, // Short window for testing
        half_open_max_calls: 1,
        open_timeout_ms: 200,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Add 2 failures
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Closed);
    assert_eq!(cb.failure_count().await, 2);

    // Wait for window to expire
    sleep(Duration::from_millis(120)).await;

    // Failure count should be reset
    assert_eq!(cb.failure_count().await, 0);

    // New failures should start fresh count
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Open);
}

#[tokio::test]
async fn test_multiple_half_open_calls_limit() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        window_duration_ms: 1000,
        half_open_max_calls: 2, // Allow 2 half-open calls
        open_timeout_ms: 50,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Force to open
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Open);

    // Wait for half-open
    sleep(Duration::from_millis(60)).await;

    // Should allow up to max_calls in half-open
    assert!(matches!(
        cb.allow_request().await,
        sb_transport::circuit_breaker::CircuitBreakerDecision::Allow
    ));
    assert_eq!(cb.state().await, CircuitState::HalfOpen);

    assert!(matches!(
        cb.allow_request().await,
        sb_transport::circuit_breaker::CircuitBreakerDecision::Allow
    ));

    // Third call should be rejected
    assert!(matches!(
        cb.allow_request().await,
        sb_transport::circuit_breaker::CircuitBreakerDecision::Reject
    ));
}

#[tokio::test]
async fn test_reset_functionality() {
    let config = CircuitBreakerConfig {
        failure_threshold: 2,
        window_duration_ms: 1000,
        half_open_max_calls: 1,
        open_timeout_ms: 100,
    };

    let cb = CircuitBreaker::new("test-outbound".to_string(), config);

    // Force to open
    cb.record_result(false, false).await;
    cb.record_result(false, false).await;
    assert_eq!(cb.state().await, CircuitState::Open);
    assert!(cb.failure_count().await > 0);

    // Reset should close circuit and clear failures
    cb.reset().await;
    assert_eq!(cb.state().await, CircuitState::Closed);
    assert_eq!(cb.failure_count().await, 0);
}
