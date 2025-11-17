//! Service stub implementations for Resolved, DERP, and SSM API.
//!
//! These are placeholder implementations that return helpful errors
//! when the actual service implementations are not available.

use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::{Service, ServiceContext, StartStage};
use std::sync::Arc;

/// Stub service that returns "not implemented" errors.
struct StubService {
    ty_str: &'static str,
    tag: String,
}

impl Service for StubService {
    fn service_type(&self) -> &str {
        self.ty_str
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, _stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err(format!(
            "service '{}' ({}) is not implemented in this build",
            self.tag, self.ty_str
        )
        .into())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(()) // Stub cleanup is no-op
    }
}

/// Build a Resolved service stub.
///
/// Returns `Some` and logs a warning that Resolved is not implemented.
pub fn build_resolved_service(ir: &ServiceIR, _ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    let tag = ir.tag.as_deref().unwrap_or("resolved");
    tracing::warn!(
        service_type = "resolved",
        tag = tag,
        "Resolved DNS service is not implemented; requires systemd-resolved integration"
    );

    // Return stub that will error when start() is called
    Some(Arc::new(StubService {
        ty_str: "resolved",
        tag: tag.to_string(),
    }))
}

/// Build a SSM API service stub.
///
/// Returns `Some` and logs a warning that SSM API is not implemented.
pub fn build_ssmapi_service(ir: &ServiceIR, _ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    let tag = ir.tag.as_deref().unwrap_or("ssmapi");
    tracing::warn!(
        service_type = "ssmapi",
        tag = tag,
        "Shadowsocks Manager API service is not implemented; requires SSM protocol implementation"
    );

    // Return stub that will error when start() is called
    Some(Arc::new(StubService {
        ty_str: "ssmapi",
        tag: tag.to_string(),
    }))
}

/// Build a DERP service stub.
///
/// Returns `Some` and logs a warning that DERP is not implemented.
pub fn build_derp_service(ir: &ServiceIR, _ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    let tag = ir.tag.as_deref().unwrap_or("derp");
    tracing::warn!(
        service_type = "derp",
        tag = tag,
        "DERP relay service is not implemented; requires Tailscale DERP protocol implementation"
    );

    // Return stub that will error when start() is called
    Some(Arc::new(StubService {
        ty_str: "derp",
        tag: tag.to_string(),
    }))
}

/// Register all service stubs.
///
/// This should be called during adapter initialization to register
/// Resolved, SSM API, and DERP service stubs.
pub fn register_service_stubs() {
    sb_core::service::register_service(ServiceType::Resolved, build_resolved_service);
    sb_core::service::register_service(ServiceType::Ssmapi, build_ssmapi_service);
    sb_core::service::register_service(ServiceType::Derp, build_derp_service);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::ServiceType;

    #[test]
    fn test_resolved_stub_registration() {
        let registry = sb_core::service::ServiceRegistry::new();
        assert!(registry.register(ServiceType::Resolved, build_resolved_service));

        let ctx = ServiceContext::default();
        let ir = ServiceIR {
            ty: ServiceType::Resolved,
            tag: Some("resolved-dns".to_string()),
            resolved_listen: Some("127.0.0.53".to_string()),
            resolved_listen_port: Some(53),
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
        };

        let service = registry.build(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "resolved");
        assert_eq!(service.tag(), "resolved-dns");

        // Starting should fail with helpful error
        let result = service.start(StartStage::Initialize);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }

    #[test]
    fn test_ssmapi_stub_registration() {
        let registry = sb_core::service::ServiceRegistry::new();
        assert!(registry.register(ServiceType::Ssmapi, build_ssmapi_service));

        let ctx = ServiceContext::default();
        let ir = ServiceIR {
            ty: ServiceType::Ssmapi,
            tag: Some("ssm".to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: Some("127.0.0.1".to_string()),
            ssmapi_listen_port: Some(6001),
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
        };

        let service = registry.build(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "ssmapi");
        assert_eq!(service.tag(), "ssm");

        // Starting should fail with helpful error
        let result = service.start(StartStage::Initialize);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }

    #[test]
    fn test_derp_stub_registration() {
        let registry = sb_core::service::ServiceRegistry::new();
        assert!(registry.register(ServiceType::Derp, build_derp_service));

        let ctx = ServiceContext::default();
        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-relay".to_string()),
            resolved_listen: None,
            resolved_listen_port: None,
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: Some("0.0.0.0".to_string()),
            derp_listen_port: Some(3478),
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_stun_enabled: Some(true),
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
        };

        let service = registry.build(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "derp");
        assert_eq!(service.tag(), "derp-relay");

        // Starting should fail with helpful error
        let result = service.start(StartStage::Initialize);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }
}
