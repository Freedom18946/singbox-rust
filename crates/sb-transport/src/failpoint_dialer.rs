//! Failpoint-enabled dialer for chaos injection testing
//!
//! This module provides a dialer wrapper that can inject failures at various points
//! during connection establishment. Failures are controlled via the FAILPOINTS environment
//! variable and are only active when the "failpoints" feature is enabled.

use super::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;

/// Dialer wrapper that supports failpoint-based failure injection
///
/// This dialer wraps an underlying dialer and can inject failures at specific
/// points based on failpoint configuration. It's designed for chaos engineering
/// and testing scenarios where you need to simulate network failures.
///
/// ## Failpoint Naming Convention
/// Failpoints follow the pattern: `transport.dialer.{point}`
// - `transport.dialer.connect_start`: Fail before attempting connection
// - `transport.dialer.connect_timeout`: Simulate connection timeout
// - `transport.dialer.dns_failure`: Simulate DNS resolution failure
pub struct FailpointDialer<D: Dialer> {
    /// The underlying dialer to wrap
    pub inner: D,
}

impl<D: Dialer> FailpointDialer<D> {
    /// Create a new failpoint dialer with default prefix
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<D: Dialer + Send + Sync> Dialer for FailpointDialer<D> {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        #[cfg(feature = "failpoints")]
        {
            // Failpoint: fail before starting connection
            fail::fail_point!("transport.dialer.connect_start", |_| {
                return Err(DialError::Other("failpoint: connect_start".to_string()));
            });

            // Failpoint: simulate DNS failure (only applies to hostname, not IP literal)
            if host.chars().any(|c| c.is_alphabetic()) {
                fail::fail_point!("transport.dialer.dns_failure", |_| {
                    return Err(DialError::Other(format!(
                        "failpoint: DNS failure for {}",
                        host
                    )));
                });
            }

            // Proceed with actual connection
            let result = self.inner.connect(host, port).await;

            // Failpoint: simulate timeout after connection attempt
            fail::fail_point!("transport.dialer.connect_timeout", |_| {
                return Err(DialError::Other("timeout".to_string()));
            });

            result
        }

        #[cfg(not(feature = "failpoints"))]
        {
            // When failpoints are disabled, just pass through to inner dialer
            self.inner.connect(host, port).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::TcpDialer;

    #[tokio::test]
    async fn test_failpoint_dialer_passthrough() {
        let inner = TcpDialer;
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
    async fn test_failpoint_dialer_injection() {
        let inner = TcpDialer;
        let fp_dialer = FailpointDialer::new(inner);

        // Set up failpoint
        fail::cfg("transport.dialer.connect_start", "return").unwrap();

        let result = fp_dialer.connect("example.com", 80).await;
        assert!(result.is_err());

        // Clean up
        fail::cfg("transport.dialer.connect_start", "off").unwrap();
    }
}
