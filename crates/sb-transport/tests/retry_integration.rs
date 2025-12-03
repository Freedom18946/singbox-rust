//! Integration tests for retry/backoff strategy
//!
//! Tests the retry functionality in realistic scenarios including:
//! - Environment variable configuration
//! - Integration with dialers
//! - Metrics collection
//! - Enable/disable switch behavior

use once_cell::sync::Lazy;
use sb_transport::dialer::{Dialer, RetryableTcpDialer};
use sb_transport::retry::{retry_conditions, RetryPolicy};
use std::env;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use tokio::time::timeout;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[tokio::test]
async fn test_retry_policy_env_disabled_by_default() {
    let _lock = ENV_LOCK.lock().await;
    // Clear all retry environment variables
    env::remove_var("SB_RETRY_MAX");
    env::remove_var("SB_RETRY_BASE_MS");
    env::remove_var("SB_RETRY_JITTER");

    let policy = RetryPolicy::from_env();
    assert!(!policy.is_enabled());
}

#[tokio::test]
async fn test_retry_policy_env_configuration() {
    let _lock = ENV_LOCK.lock().await;
    // Set environment variables
    env::set_var("SB_RETRY_MAX", "5");
    env::set_var("SB_RETRY_BASE_MS", "50");
    env::set_var("SB_RETRY_JITTER", "0.3");

    let policy = RetryPolicy::from_env();
    assert!(policy.is_enabled());
    assert_eq!(policy.max_retries, 5);
    assert_eq!(policy.base_delay, Duration::from_millis(50));
    assert_eq!(policy.jitter_factor, 0.3);

    // Clean up
    env::remove_var("SB_RETRY_MAX");
    env::remove_var("SB_RETRY_BASE_MS");
    env::remove_var("SB_RETRY_JITTER");
}

#[tokio::test]
async fn test_retry_policy_env_jitter_clamping() {
    let _lock = ENV_LOCK.lock().await;
    // Test jitter is properly clamped to [0.0, 1.0]
    env::set_var("SB_RETRY_MAX", "1");
    env::set_var("SB_RETRY_JITTER", "2.5"); // Should be clamped to 1.0

    let policy = RetryPolicy::from_env();
    assert_eq!(policy.jitter_factor, 1.0);

    env::set_var("SB_RETRY_JITTER", "-0.5"); // Should be clamped to 0.0
    let policy2 = RetryPolicy::from_env();
    assert_eq!(policy2.jitter_factor, 0.0);

    // Clean up
    env::remove_var("SB_RETRY_MAX");
    env::remove_var("SB_RETRY_JITTER");
}

#[tokio::test]
async fn test_retryable_dialer_success_no_retry() {
    let _lock = ENV_LOCK.lock().await;
    // Set up a working server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let accept_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream);
        }
    });

    // Configure retries but they shouldn't be used for successful connection
    env::set_var("SB_RETRY_MAX", "3");
    let dialer = RetryableTcpDialer::new();

    let result = timeout(Duration::from_secs(5), dialer.connect("127.0.0.1", port)).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());

    // Clean up
    env::remove_var("SB_RETRY_MAX");
    accept_task.await.ok();
}

#[tokio::test]
async fn test_retryable_dialer_disabled_retry() {
    let _lock = ENV_LOCK.lock().await;
    // Ensure retries are disabled
    env::remove_var("SB_RETRY_MAX");

    let dialer = RetryableTcpDialer::new();

    // Try to connect to a non-existent port - should fail quickly without retry
    let start = std::time::Instant::now();
    let result = dialer.connect("127.0.0.1", 1).await; // Port 1 should be closed
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Without retries, this should fail relatively quickly
    assert!(elapsed < Duration::from_secs(1));
}

#[tokio::test]
async fn test_retryable_dialer_with_retry() {
    let _lock = ENV_LOCK.lock().await;
    // Enable retries with short delays for fast test
    env::set_var("SB_RETRY_MAX", "2");
    env::set_var("SB_RETRY_BASE_MS", "10");

    let dialer = RetryableTcpDialer::new();

    let start = std::time::Instant::now();
    let result = dialer.connect("127.0.0.1", 1).await; // Port 1 should be closed
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // With retries, this should take longer due to retry delays
    // 2 retries with 10ms base delay should take at least 30ms (10 + 20)
    assert!(elapsed >= Duration::from_millis(25));

    // Clean up
    env::remove_var("SB_RETRY_MAX");
    env::remove_var("SB_RETRY_BASE_MS");
}

#[tokio::test]
async fn test_retry_conditions() {
    use sb_transport::dialer::DialError;
    use std::io::{Error, ErrorKind};

    // Test various error conditions
    let timeout_error = DialError::Io(Error::new(ErrorKind::TimedOut, "timeout"));
    assert!(retry_conditions::is_retriable_error(&timeout_error));

    let connection_refused = DialError::Io(Error::new(ErrorKind::ConnectionRefused, "refused"));
    assert!(retry_conditions::is_retriable_error(&connection_refused));

    let dns_error = DialError::Io(Error::other("failed to lookup address information"));
    assert!(retry_conditions::is_retriable_error(&dns_error));

    let tls_error = DialError::Tls("certificate error".to_string());
    assert!(!retry_conditions::is_retriable_error(&tls_error));

    let not_supported = DialError::NotSupported;
    assert!(!retry_conditions::is_retriable_error(&not_supported));
}

#[tokio::test]
async fn test_custom_retry_policy() {
    let custom_policy = RetryPolicy {
        max_retries: 1,
        base_delay: Duration::from_millis(20),
        max_delay: Duration::from_secs(2),
        jitter_factor: 0.1,
    };

    let dialer = RetryableTcpDialer::with_policy(custom_policy);

    let start = std::time::Instant::now();
    let result = dialer.connect("127.0.0.1", 1).await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Should have at least one retry with ~20ms delay
    assert!(elapsed >= Duration::from_millis(15));
}

#[tokio::test]
async fn test_jitter_distribution_basic() {
    let policy = RetryPolicy {
        max_retries: 1,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(2),
        jitter_factor: 0.5, // 50% jitter
    };

    // Collect multiple delay calculations
    let delays: Vec<Duration> = (0..50).map(|_| policy.calculate_delay(1)).collect();

    // All delays should be within [50ms, 150ms] range
    for delay in &delays {
        assert!(
            *delay >= Duration::from_millis(50) && *delay <= Duration::from_millis(150),
            "Delay {:?} outside expected range",
            delay
        );
    }

    // Check for reasonable distribution (not all the same value)
    let min_delay = delays.iter().min().unwrap();
    let max_delay = delays.iter().max().unwrap();
    let range = max_delay.saturating_sub(*min_delay);

    // Expect at least 20ms of variation in a 100ms range with 50% jitter
    assert!(
        range >= Duration::from_millis(20),
        "Insufficient jitter variation: {:?}",
        range
    );
}

#[tokio::test]
async fn test_max_retry_attempts_reached() {
    // Create custom policy with specific retry count
    let policy = RetryPolicy {
        max_retries: 3,
        base_delay: Duration::from_millis(1), // Very short delay for fast test
        max_delay: Duration::from_secs(2),
        jitter_factor: 0.0,
    };

    let call_count = Arc::new(AtomicU32::new(0));
    let call_count_clone = call_count.clone();

    let result = policy
        .execute(
            "test_operation",
            || {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    Err::<(), &str>("persistent failure")
                }
            },
            |_| true, // Always retry
        )
        .await;

    assert!(result.is_err());
    // Should try initial + 3 retries = 4 total attempts
    assert_eq!(call_count.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn test_retry_switch_on_off() {
    let _lock = ENV_LOCK.lock().await;
    // Test with retries enabled
    env::set_var("SB_RETRY_MAX", "2");
    let policy_enabled = RetryPolicy::from_env();
    assert!(policy_enabled.is_enabled());

    // Test with retries disabled
    env::set_var("SB_RETRY_MAX", "0");
    let policy_disabled = RetryPolicy::from_env();
    assert!(!policy_disabled.is_enabled());

    // Test with retries completely unset
    env::remove_var("SB_RETRY_MAX");
    let policy_unset = RetryPolicy::from_env();
    assert!(!policy_unset.is_enabled());

    // Clean up
    env::remove_var("SB_RETRY_MAX");
}
