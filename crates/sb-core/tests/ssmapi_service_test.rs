#![cfg(feature = "service_ssmapi")]
use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::{ServiceContext, StartStage};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_ssmapi_service_lifecycle() {
    // Pick a random port
    let port = 51000 + (fastrand::u16(0..1000));
    let addr = format!("127.0.0.1:{}", port);

    let ir = ServiceIR {
        ty: ServiceType::Ssmapi,
        tag: Some("ssm-test".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        servers: Some(HashMap::from([("/".to_string(), "ss-in".to_string())])),
        ..Default::default()
    };

    // We need to manually enable the feature in the test run
    // This test assumes the feature is enabled

    #[cfg(feature = "service_ssmapi")]
    {
        let service =
            sb_core::services::ssmapi::build_ssmapi_service(&ir, &ServiceContext::default());
        assert!(service.is_some());
        let service = service.unwrap();

        assert_eq!(service.service_type(), "ssm-api");
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
