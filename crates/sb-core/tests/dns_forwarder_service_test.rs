#![cfg(feature = "service_resolved")]

use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::{ServiceContext, StartStage};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_dns_forwarder_service_lifecycle() {
    // Pick a random port to avoid conflicts
    let port = 50000 + (fastrand::u16(0..1000));
    let addr = format!("127.0.0.1:{}", port);

    let ir = ServiceIR {
        ty: ServiceType::Resolved,
        tag: Some("resolved-test".to_string()),
        resolved_listen: Some("127.0.0.1".to_string()),
        resolved_listen_port: Some(port),
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

    let service = sb_core::services::dns_forwarder::build_dns_forwarder_service(
        &ir,
        &ServiceContext::default(),
    );
    assert!(service.is_some());
    let service = service.unwrap();

    assert_eq!(service.service_type(), "resolved");
    assert_eq!(service.tag(), "resolved-test");

    // Start service
    service.start(StartStage::Initialize).unwrap();
    service.start(StartStage::Start).unwrap();

    // Give it a moment to bind
    sleep(Duration::from_millis(100)).await;

    // Verify we can send a packet to it
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"ping", &addr).await.unwrap();

    // Cleanup
    service.close().unwrap();
}
