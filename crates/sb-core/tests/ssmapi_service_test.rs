#![cfg(feature = "service_ssmapi")]
use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::{ServiceContext, StartStage};
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_ssmapi_service_lifecycle() {
    // Pick a random port
    let port = 51000 + (fastrand::u16(0..1000));
    let addr = format!("127.0.0.1:{}", port);

    let ir = ServiceIR {
        ty: ServiceType::Ssmapi,
        tag: Some("ssm-test".to_string()),
        resolved_listen: None,
        resolved_listen_port: None,
        ssmapi_listen: Some("127.0.0.1".to_string()),
        ssmapi_listen_port: Some(port),
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
        derp_server_key_path: None,
        derp_stun_enabled: None,
        derp_stun_listen_port: None,
        derp_tls_cert_path: None,
        derp_tls_key_path: None,
    };

    // We need to manually enable the feature in the test run
    // This test assumes the feature is enabled

    #[cfg(feature = "service_ssmapi")]
    {
        let service =
            sb_core::services::ssmapi::build_ssmapi_service(&ir, &ServiceContext::default());
        assert!(service.is_some());
        let service = service.unwrap();

        assert_eq!(service.service_type(), "ssmapi");
        assert_eq!(service.tag(), "ssm-test");

        // Start service
        service.start(StartStage::Initialize).unwrap();
        service.start(StartStage::Start).unwrap();

        // Give it a moment to bind
        let mut connected = false;
        for _ in 0..10 {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                connected = true;
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        assert!(
            connected,
            "Should be able to connect to SSM API at {}",
            addr
        );

        // Cleanup
        service.close().unwrap();
    }
}
