//! Integration tests for failpoints functionality
//!
//! These tests verify that the failpoints system works correctly across
//! different subsystems (DNS, transport, selectors) when the failpoints
//! feature is enabled.

#[cfg(feature = "failpoints")]
mod failpoint_tests {
    use sb_transport::{FailpointDialer, TcpDialer};

    #[tokio::test]
    async fn test_transport_failpoint_injection() {
        // Configure failpoint to trigger connection start failure
        fail::cfg("transport.dialer.connect_start", "return").unwrap();

        let base_dialer = TcpDialer;
        let fp_dialer = FailpointDialer::new(base_dialer);

        let result = fp_dialer.connect("127.0.0.1", 1).await;
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("failpoint: connect_start"));
        }

        // Cleanup
        fail::cfg("transport.dialer.connect_start", "off").unwrap();
    }

    #[tokio::test]
    async fn test_transport_dns_failure_failpoint() {
        // Configure failpoint to trigger DNS failure
        fail::cfg("transport.dialer.dns_failure", "return").unwrap();

        let base_dialer = TcpDialer;
        let fp_dialer = FailpointDialer::new(base_dialer);

        let result = fp_dialer.connect("example.com", 80).await;
        assert!(result.is_err());

        if let Err(e) = result {
            assert!(e.to_string().contains("DNS failure"));
        }

        // Cleanup
        fail::cfg("transport.dialer.dns_failure", "off").unwrap();
    }

    #[tokio::test]
    async fn test_transport_timeout_failpoint() {
        // Configure failpoint to trigger timeout after connection
        fail::cfg("transport.dialer.connect_timeout", "return").unwrap();

        let base_dialer = TcpDialer;
        let fp_dialer = FailpointDialer::new(base_dialer);

        let result = fp_dialer.connect("127.0.0.1", 1).await;
        assert!(result.is_err());

        // Cleanup
        fail::cfg("transport.dialer.connect_timeout", "off").unwrap();
    }
}

#[cfg(not(feature = "failpoints"))]
mod no_failpoint_tests {
    use sb_transport::TcpDialer;

    #[tokio::test]
    async fn test_normal_dialer_without_failpoints() {
        // Without failpoints feature, dialers should work normally
        let dialer = TcpDialer;

        // This might fail normally due to connection issues, but shouldn't panic
        let _result = dialer.connect("127.0.0.1", 1).await;

        // Test passes if we reach here without panicking
    }
}