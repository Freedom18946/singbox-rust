//! End-to-end tests for Resolved DNS service.
//!
//! These tests verify the Resolved service can:
//! - Start and bind to a configured UDP port
//! - Receive and respond to DNS queries
//! - Integrate with DNS resolution system
//! - Gracefully handle lifecycle (start/stop)

use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::{Service, ServiceContext, StartStage};

#[test]
fn test_resolved_service_creation() {
    let ir = ServiceIR {
        ty: ServiceType::Resolved,
        tag: Some("test-resolved".to_string()),
        resolved_listen: Some("127.0.0.1".to_string()),
        resolved_listen_port: Some(5353), // Use non-privileged port for testing
        ssmapi_listen: None,
        ssmapi_listen_port: None,
        ssmapi_servers: None,
        ssmapi_cache_path: None,
        ssmapi_tls_cert_path: None,
        ssmapi_tls_key_path: None,
        derp_listen: None,
        derp_listen_port: None,
        derp_config_path: None,
        derp_verify_client_endpoint: None,
        derp_verify_client_url: None,
        derp_home: None,
        derp_mesh_with: None,
        derp_mesh_psk: None,
        derp_mesh_psk_file: None,
        derp_stun_enabled: None,
        derp_stun_listen_port: None,
        derp_tls_cert_path: None,
        derp_tls_key_path: None,
        derp_server_key_path: None,
    };

    let ctx = ServiceContext::default();
    let service = sb_adapters::service_stubs::build_resolved_service(&ir, &ctx);

    assert!(service.is_some(), "Service should be built");
    let service = service.unwrap();
    assert_eq!(service.service_type(), "resolved");
    assert_eq!(service.tag(), "test-resolved");
}

#[cfg(all(target_os = "linux", feature = "service_resolved"))]
#[tokio::test]
async fn test_resolved_service_lifecycle() {
    use tokio::time::{sleep, Duration};

    let ir = ServiceIR {
        ty: ServiceType::Resolved,
        tag: Some("lifecycle-test".to_string()),
        resolved_listen: Some("127.0.0.1".to_string()),
        resolved_listen_port: Some(5354), // Different port to avoid conflicts
        ssmapi_listen: None,
        ssmapi_listen_port: None,
        ssmapi_servers: None,
        ssmapi_cache_path: None,
        ssmapi_tls_cert_path: None,
        ssmapi_tls_key_path: None,
        derp_listen: None,
        derp_listen_port: None,
        derp_config_path: None,
        derp_verify_client_endpoint: None,
        derp_verify_client_url: None,
        derp_home: None,
        derp_mesh_with: None,
        derp_mesh_psk: None,
        derp_mesh_psk_file: None,
        derp_stun_enabled: None,
        derp_stun_listen_port: None,
        derp_tls_cert_path: None,
        derp_tls_key_path: None,
        derp_server_key_path: None,
    };

    let ctx = ServiceContext::default();
    let service = sb_adapters::service_stubs::build_resolved_service(&ir, &ctx);
    assert!(service.is_some());

    let service = service.unwrap();

    // Test lifecycle stages
    let init_result = service.start(StartStage::Initialize);
    if init_result.is_ok() {
        // Continue with lifecycle tests
        assert!(
            service.start(StartStage::Start).is_ok(),
            "Start stage should succeed"
        );

        // Give the DNS server a moment to start
        sleep(Duration::from_millis(100)).await;

        assert!(
            service.start(StartStage::PostStart).is_ok(),
            "PostStart stage should succeed"
        );
        assert!(
            service.start(StartStage::Started).is_ok(),
            "Started stage should succeed"
        );

        // Test clean shutdown
        assert!(service.close().is_ok(), "Close should succeed");
    } else {
        // Expected in environments without systemd-resolved
        println!("Skipping lifecycle test: systemd-resolved not available");
    }
}

#[cfg(all(target_os = "linux", feature = "service_resolved"))]
#[tokio::test]
#[ignore = "requires systemd-resolved and may need elevated permissions"]
async fn test_resolved_dns_query() {
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, timeout, Duration};

    let test_port = 5355; // Use test port to avoid permission issues

    let ir = ServiceIR {
        ty: ServiceType::Resolved,
        tag: Some("dns-test".to_string()),
        resolved_listen: Some("127.0.0.1".to_string()),
        resolved_listen_port: Some(test_port),
        ssmapi_listen: None,
        ssmapi_listen_port: None,
        ssmapi_servers: None,
        ssmapi_cache_path: None,
        ssmapi_tls_cert_path: None,
        ssmapi_tls_key_path: None,
        derp_listen: None,
        derp_listen_port: None,
        derp_config_path: None,
        derp_verify_client_endpoint: None,
        derp_verify_client_url: None,
        derp_home: None,
        derp_mesh_with: None,
        derp_mesh_psk: None,
        derp_mesh_psk_file: None,
        derp_stun_enabled: None,
        derp_stun_listen_port: None,
        derp_tls_cert_path: None,
        derp_tls_key_path: None,
        derp_server_key_path: None,
    };

    let ctx = ServiceContext::default();
    let service = sb_adapters::service_stubs::build_resolved_service(&ir, &ctx);
    assert!(service.is_some());

    let service = service.unwrap();

    // Start the service
    if service.start(StartStage::Initialize).is_err() {
        println!("Skipping DNS query test: systemd-resolved not available");
        return;
    }

    assert!(service.start(StartStage::Start).is_ok());

    // Give the DNS server time to start
    sleep(Duration::from_millis(200)).await;

    // Build a simple DNS query for google.com A record
    let query_packet = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // QNAME: google.com
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // End of QNAME
        0x00, 0x01, // QTYPE: A (IPv4)
        0x00, 0x01, // QCLASS: IN
    ];

    // Send DNS query to the service
    let client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind client socket");
    let server_addr = format!("127.0.0.1:{}", test_port);

    client
        .send_to(&query_packet, &server_addr)
        .await
        .expect("Failed to send query");

    // Receive response
    let mut response_buf = vec![0u8; 4096];
    let recv_future = client.recv_from(&mut response_buf);

    match timeout(Duration::from_secs(2), recv_future).await {
        Ok(Ok((len, _))) => {
            println!("Received DNS response ({} bytes)", len);

            // Verify response header
            assert!(len >= 12, "Response should have at least a DNS header");

            // Check transaction ID matches
            assert_eq!(response_buf[0], 0x12);
            assert_eq!(response_buf[1], 0x34);

            // Check it's a response (QR bit set)
            assert!(response_buf[2] & 0x80 != 0, "Should be a response");

            println!("DNS query/response test passed");
        }
        Ok(Err(e)) => {
            panic!("DNS query failed: {}", e);
        }
        Err(_) => {
            panic!("DNS query timed out");
        }
    }

    // Clean shutdown
    assert!(service.close().is_ok());
}

#[test]
fn test_resolved_service_stub_on_unsupported_platform() {
    // This test verifies that on non-Linux platforms or without service-resolved feature,
    // the service still builds but returns a stub

    let ir = ServiceIR {
        ty: ServiceType::Resolved,
        tag: Some("stub-test".to_string()),
        resolved_listen: Some("127.0.0.1".to_string()),
        resolved_listen_port: Some(5353),
        ssmapi_listen: None,
        ssmapi_listen_port: None,
        ssmapi_servers: None,
        ssmapi_cache_path: None,
        ssmapi_tls_cert_path: None,
        ssmapi_tls_key_path: None,
        derp_listen: None,
        derp_listen_port: None,
        derp_config_path: None,
        derp_verify_client_endpoint: None,
        derp_verify_client_url: None,
        derp_home: None,
        derp_mesh_with: None,
        derp_mesh_psk: None,
        derp_mesh_psk_file: None,
        derp_stun_enabled: None,
        derp_stun_listen_port: None,
        derp_tls_cert_path: None,
        derp_tls_key_path: None,
        derp_server_key_path: None,
    };

    let ctx = ServiceContext::default();
    let service = sb_adapters::service_stubs::build_resolved_service(&ir, &ctx);

    assert!(service.is_some(), "Stub service should always be built");

    #[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
    {
        // On unsupported platforms, starting should fail with helpful error
        let service = service.unwrap();
        let result = service.start(StartStage::Initialize);
        assert!(
            result.is_err(),
            "Stub should fail to start on unsupported platforms"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("not implemented"),
            "Error should mention not implemented: {}",
            error_msg
        );
    }
}
