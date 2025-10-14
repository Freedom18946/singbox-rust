#![cfg(feature = "adapter-socks")]
//! E2E tests for retry functionality and backoff behavior
//!
//! This module tests the retry mechanisms in adapters to ensure
//! proper backoff timing and retry counting.

use sb_adapters::{
    outbound::socks5::Socks5Connector,
    traits::{DialOpts, OutboundConnector, ResolveMode, RetryPolicy, Target},
    Result,
};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Mock SOCKS5 server that fails N times before succeeding
struct FailingMockServer {
    listener: TcpListener,
    failure_count: Arc<Mutex<usize>>,
    max_failures: usize,
}

impl FailingMockServer {
    async fn new(max_failures: usize) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self {
            listener,
            failure_count: Arc::new(Mutex::new(0)),
            max_failures,
        })
    }

    fn addr(&self) -> String {
        self.listener.local_addr().unwrap().to_string()
    }

    fn get_failure_count(&self) -> usize {
        *self.failure_count.lock().unwrap()
    }

    /// Handle connections, failing the first N attempts
    async fn handle_connections(&self) -> Result<()> {
        loop {
            let (mut stream, _) = self.listener.accept().await?;

            let current_failures = {
                let mut count = self.failure_count.lock().unwrap();
                let current = *count;
                if current < self.max_failures {
                    *count += 1;
                }
                current
            };

            if current_failures < self.max_failures {
                // Simulate failure by closing connection immediately
                drop(stream);
                continue;
            }

            // Simulate successful SOCKS5 handshake
            let mut buf = [0u8; 2];
            if stream.read_exact(&mut buf).await.is_err() {
                continue;
            }

            if buf[0] != 0x05 {
                continue;
            }

            let n_methods = buf[1] as usize;
            let mut methods = vec![0u8; n_methods];
            if stream.read_exact(&mut methods).await.is_err() {
                continue;
            }

            // Send success response
            if stream.write_all(&[0x05, 0x00]).await.is_err() {
                continue;
            }

            // Read CONNECT request
            let mut req = [0u8; 4];
            if stream.read_exact(&mut req).await.is_err() {
                continue;
            }

            // Skip address and port reading for simplicity
            let mut addr_buf = [0u8; 256];
            let _ = stream.read(&mut addr_buf).await;

            // Send success response
            let response = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            let _ = stream.write_all(&response).await;

            // Keep connection alive briefly
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[cfg(feature = "adapter-socks")]
#[tokio::test]
async fn test_retry_backoff_timing() -> Result<()> {
    use serial_test::serial;

    #[serial]
    async fn run_test() -> Result<()> {
        // Create a server that doesn't respond (causes timeout)
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?.to_string();

        // Don't actually accept connections to cause timeouts
        drop(listener);

        let connector = Socks5Connector::no_auth(addr);
        let target = Target::tcp("example.com", 80);

        let retry_policy = RetryPolicy::new()
            .with_max_retries(2)
            .with_base_delay(100) // 100ms base delay
            .with_jitter(0.0); // No jitter for predictable timing

        let opts = DialOpts {
            connect_timeout: Duration::from_millis(50), // Short timeout to fail fast
            read_timeout: Duration::from_secs(1),
            retry_policy,
            resolve_mode: ResolveMode::Remote,
        };

        let start = Instant::now();
        let result = connector.dial(target, opts).await;
        let elapsed = start.elapsed();

        // Should fail after retries
        assert!(result.is_err());

        // Should take at least: 50ms (first attempt) + 100ms (delay) + 50ms (second attempt) + 200ms (delay) + 50ms (third attempt)
        // Total: ~450ms minimum, but with some tolerance for system timing
        assert!(elapsed >= Duration::from_millis(300));
        assert!(elapsed < Duration::from_millis(1000)); // Reasonable upper bound

        Ok(())
    }

    run_test().await
}

#[cfg(feature = "adapter-socks")]
#[tokio::test]
async fn test_retry_success_after_failures() -> Result<()> {
    use serial_test::serial;

    #[serial]
    async fn run_test() -> Result<()> {
        let server = Arc::new(FailingMockServer::new(2).await?); // Fail 2 times, then succeed
        let server_addr = server.addr();

        // Start server
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let _ = server_clone.handle_connections().await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let connector = Socks5Connector::no_auth(server_addr);
        let target = Target::tcp("example.com", 80);

        let retry_policy = RetryPolicy::new()
            .with_max_retries(3)
            .with_base_delay(50)
            .with_jitter(0.0);

        let opts = DialOpts {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            retry_policy,
            resolve_mode: ResolveMode::Remote,
        };

        let result = connector.dial(target, opts).await;

        // Should succeed after retries
        assert!(result.is_ok());

        // Should have attempted 3 times (2 failures + 1 success)
        assert_eq!(server.get_failure_count(), 2);

        server_task.abort();

        Ok(())
    }

    run_test().await
}

#[cfg(feature = "adapter-socks")]
#[tokio::test]
async fn test_retry_exhaustion() -> Result<()> {
    use serial_test::serial;

    #[serial]
    async fn run_test() -> Result<()> {
        let server = Arc::new(FailingMockServer::new(5).await?); // Fail 5 times
        let server_addr = server.addr();

        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let _ = server_clone.handle_connections().await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let connector = Socks5Connector::no_auth(server_addr);
        let target = Target::tcp("example.com", 80);

        let retry_policy = RetryPolicy::new()
            .with_max_retries(2) // Only retry 2 times
            .with_base_delay(10)
            .with_jitter(0.0);

        let opts = DialOpts {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            retry_policy,
            resolve_mode: ResolveMode::Remote,
        };

        let result = connector.dial(target, opts).await;

        // Should fail after exhausting retries
        assert!(result.is_err());

        // Should have attempted 3 times total (initial + 2 retries)
        // Since server fails 5 times, all 3 attempts should fail
        assert_eq!(server.get_failure_count(), 3);

        server_task.abort();

        Ok(())
    }

    run_test().await
}

#[tokio::test]
async fn test_retry_policy_configuration() {
    // Test RetryPolicy configuration and delay calculation
    let policy = RetryPolicy::new()
        .with_max_retries(3)
        .with_base_delay(100)
        .with_jitter(0.1)
        .with_max_delay(1000);

    assert_eq!(policy.max_retries, 3);
    assert_eq!(policy.base_delay_ms, 100);
    assert_eq!(policy.jitter, 0.1);
    assert_eq!(policy.max_delay_ms, 1000);

    // Test delay calculation (without jitter for predictability)
    let policy_no_jitter = RetryPolicy::new().with_base_delay(100).with_jitter(0.0);

    assert_eq!(
        policy_no_jitter.calculate_delay(0),
        Duration::from_millis(0)
    ); // No delay for first attempt
    assert_eq!(
        policy_no_jitter.calculate_delay(1),
        Duration::from_millis(100)
    ); // Base delay for first retry
    assert_eq!(
        policy_no_jitter.calculate_delay(2),
        Duration::from_millis(200)
    ); // 2 * base delay for second retry
    assert_eq!(
        policy_no_jitter.calculate_delay(3),
        Duration::from_millis(400)
    ); // 4 * base delay for third retry
}

#[tokio::test]
async fn test_max_delay_cap() {
    // Test that delays are capped at max_delay
    let policy = RetryPolicy::new()
        .with_base_delay(1000)
        .with_max_delay(1500)
        .with_jitter(0.0);

    // After several retries, delay should be capped
    let delay = policy.calculate_delay(10); // Would be 1000 * 2^9 = 512000ms without cap
    assert!(delay <= Duration::from_millis(1500));
}
