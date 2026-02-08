#![cfg(feature = "service_ssmapi")]
use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::ServiceContext;
use sb_core::services::ssmapi::{registry, ManagedSSMServer, TrafficTracker};
use std::collections::HashMap;
use std::sync::Arc;

struct DummyManagedServer {
    tag: String,
}

impl ManagedSSMServer for DummyManagedServer {
    fn set_tracker(&self, _tracker: Arc<dyn TrafficTracker>) {}

    fn tag(&self) -> &str {
        &self.tag
    }

    fn inbound_type(&self) -> &str {
        "shadowsocks"
    }

    fn update_users(&self, _users: Vec<String>, _passwords: Vec<String>) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn test_ssmapi_service_builds() {
    // Pick a random port
    let port = 51000 + (fastrand::u16(0..1000));

    let ir = ServiceIR {
        ty: ServiceType::Ssmapi,
        tag: Some("ssm-test".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        servers: Some(HashMap::from([("/".to_string(), "ss-in".to_string())])),
        ..Default::default()
    };

    let managed = Arc::new(DummyManagedServer {
        tag: "ss-in".to_string(),
    });
    let managed_dyn: Arc<dyn ManagedSSMServer> = managed.clone();
    registry::register_managed_ssm_server("ss-in", Arc::downgrade(&managed_dyn));

    let service = sb_core::services::ssmapi::build_ssmapi_service(&ir, &ServiceContext::default());
    assert!(service.is_some());
    let service = service.unwrap();

    assert_eq!(service.service_type(), "ssm-api");
    assert_eq!(service.tag(), "ssm-test");
}
