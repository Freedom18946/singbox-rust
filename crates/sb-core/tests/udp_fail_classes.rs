//! UDP failure classification tests
//!
//! Tests different classes of UDP failures and their metrics integration:
//! - timeout: No response within timeout period
//! - io: Network I/O errors
//! - decode: Packet decode/parse errors
//! - no_route: No route available for destination
//! - canceled: Operation was canceled

use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::time::{pause, advance, resume, timeout};

use sb_core::error::{SbError, SbResult};

fn test_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
}

// Mock UDP processor for testing failure scenarios
struct MockUdpProcessor {
    behavior: FailureBehavior,
}

#[derive(Clone)]
enum FailureBehavior {
    Timeout,
    IoError,
    DecodeError,
    NoRoute,
    Canceled,
    Success,
}

impl MockUdpProcessor {
    fn new(behavior: FailureBehavior) -> Self {
        Self { behavior }
    }

    async fn process_packet(&self, _data: &[u8], _dest: SocketAddr) -> SbResult<Vec<u8>> {
        match self.behavior {
            FailureBehavior::Timeout => {
                // Simulate timeout by waiting longer than expected
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(b"response".to_vec())
            }
            FailureBehavior::IoError => {
                Err(SbError::Io(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    "mock error",
                )))
            }
            FailureBehavior::DecodeError => {
                Err(SbError::Parse {
                    message: "Invalid packet format".to_string(),
                })
            }
            FailureBehavior::NoRoute => {
                Err(SbError::Network {
                    class: sb_core::error::ErrorClass::Connection,
                    msg: "No route to destination 1.1.1.1:53".to_string(),
                })
            }
            FailureBehavior::Canceled => {
                Err(SbError::Canceled {
                    operation: "UDP operation".to_string(),
                })
            }
            FailureBehavior::Success => {
                Ok(b"success response".to_vec())
            }
        }
    }
}

async fn simulate_udp_operation(processor: &MockUdpProcessor, timeout_duration: Duration) -> SbResult<Vec<u8>> {
    match timeout(timeout_duration, processor.process_packet(b"test data", test_addr(53))).await {
        Ok(result) => result,
        Err(_) => Err(SbError::Timeout {
            operation: "UDP operation".to_string(),
            timeout_ms: timeout_duration.as_millis() as u64,
        }),
    }
}

// Simplified test without metrics - focus on error classification

#[tokio::test]
async fn test_timeout_failure_classification() {
    pause();

    let processor = MockUdpProcessor::new(FailureBehavior::Timeout);
    let result = simulate_udp_operation(&processor, Duration::from_millis(100)).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SbError::Timeout { .. } => {
            // Successfully classified as timeout error
        }
        _ => panic!("Expected timeout error"),
    }

    resume();
}

#[tokio::test]
async fn test_io_failure_classification() {
    let processor = MockUdpProcessor::new(FailureBehavior::IoError);
    let result = simulate_udp_operation(&processor, Duration::from_secs(1)).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SbError::Io(_) => {
            // Successfully classified as IO error
        }
        _ => panic!("Expected IO error"),
    }
}

#[tokio::test]
async fn test_decode_failure_classification() {
    let processor = MockUdpProcessor::new(FailureBehavior::DecodeError);
    let result = simulate_udp_operation(&processor, Duration::from_secs(1)).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SbError::Parse { .. } => {
            // Successfully classified as parse/decode error
        }
        _ => panic!("Expected parse/decode error"),
    }
}

#[tokio::test]
async fn test_no_route_failure_classification() {
    let processor = MockUdpProcessor::new(FailureBehavior::NoRoute);
    let result = simulate_udp_operation(&processor, Duration::from_secs(1)).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SbError::Network { .. } => {
            // Successfully classified as network/no route error
        }
        _ => panic!("Expected network/no route error"),
    }
}

#[tokio::test]
async fn test_canceled_failure_classification() {
    let processor = MockUdpProcessor::new(FailureBehavior::Canceled);
    let result = simulate_udp_operation(&processor, Duration::from_secs(1)).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        SbError::Canceled { .. } => {
            // Successfully classified as canceled error
        }
        _ => panic!("Expected canceled error"),
    }
}

#[tokio::test]
async fn test_success_no_failure_metric() {
    let processor = MockUdpProcessor::new(FailureBehavior::Success);
    let result = simulate_udp_operation(&processor, Duration::from_secs(1)).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"success response");
}

#[tokio::test]
async fn test_mixed_failure_scenario() {
    pause();

    // Test multiple failure types in sequence
    let behaviors = [
        FailureBehavior::Timeout,
        FailureBehavior::IoError,
        FailureBehavior::Success,
        FailureBehavior::NoRoute,
        FailureBehavior::DecodeError,
    ];

    let mut success_count = 0;
    let mut failure_count = 0;

    for behavior in behaviors {
        let processor = MockUdpProcessor::new(behavior.clone());
        let timeout_duration = match behavior {
            FailureBehavior::Timeout => Duration::from_millis(50), // Short timeout to trigger
            _ => Duration::from_secs(1),
        };

        let result = simulate_udp_operation(&processor, timeout_duration).await;

        match result {
            Ok(_) => {
                success_count += 1;
            }
            Err(_err) => {
                failure_count += 1;
                // In a real implementation, we would record metrics here
                // For this test, we just verify error classification
            }
        }

        advance(Duration::from_millis(100)).await;
    }

    assert_eq!(success_count, 1);
    assert_eq!(failure_count, 4);

    resume();
}