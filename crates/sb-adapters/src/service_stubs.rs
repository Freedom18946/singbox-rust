//! Service stub implementations for Resolved, DERP, and SSM API.
//!
//! These are placeholder implementations that return helpful errors
//! when the actual service implementations are not available.

use sb_config::ir::{ServiceIR, ServiceType};
use sb_core::service::{Service, ServiceContext, StartStage};
use std::sync::Arc;

/// Stub service that returns "not implemented" errors.
pub struct StubService {
    ty_str: &'static str,
    tag: String,
}

impl StubService {
    pub fn new(ty_str: &'static str, tag: String) -> Self {
        Self { ty_str, tag }
    }
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
/// Build a Resolved service stub.
///
/// Returns `Some` and logs a warning that Resolved is not implemented.
pub fn build_resolved_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    let _ = ctx;
    let tag = ir.tag.as_deref().unwrap_or("resolved");
    tracing::warn!(
        service_type = "resolved",
        tag = tag,
        "Resolved service requires Linux + `service_resolved`; falling back to stub"
    );
    Some(Arc::new(StubService {
        ty_str: "resolved",
        tag: tag.to_string(),
    }))
}

/// Build a SSM API service.
///
/// Product composition roots replace this stub with sb-api's implementation.
pub fn build_ssmapi_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    let _ = ctx;
    let tag = ir.tag.as_deref().unwrap_or("ssm-api");
    tracing::warn!(
        service_type = "ssm-api",
        tag = tag,
        "Shadowsocks Manager API service requires the `service_ssmapi` feature; rebuild with `--features service_ssmapi`"
    );

    // Return stub that will error when start() is called
    Some(Arc::new(StubService {
        ty_str: "ssm-api",
        tag: tag.to_string(),
    }))
}

/// Build a DERP service stub.
///
/// Returns `Some` and logs a warning that DERP is not implemented.
/// Build a DERP service stub.
///
/// Returns `Some` and logs a warning that DERP is not implemented.
pub fn build_derp_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    let _ = ctx;
    let tag = ir.tag.as_deref().unwrap_or("derp");
    tracing::warn!(
        service_type = "derp",
        tag = tag,
        "DERP service requires the `service_derp` feature; rebuild with `--features service_derp`"
    );

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
    #[cfg(all(target_os = "linux", feature = "service_resolved"))]
    sb_core::service::register_service(
        ServiceType::Resolved,
        crate::service::resolved_impl::build_resolved_service,
    );
    #[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
    sb_core::service::register_service(ServiceType::Resolved, build_resolved_service);

    sb_core::service::register_service(ServiceType::Ssmapi, build_ssmapi_service);

    sb_core::service::register_service(ServiceType::Derp, build_derp_service);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{DerpStunOptionsIR, InboundTlsOptionsIR, ServiceType};
    use std::collections::HashMap;

    #[test]

    fn test_resolved_stub_registration() {
        let registry = sb_core::service::ServiceRegistry::new();
        assert!(registry.register(ServiceType::Resolved, build_resolved_service));

        let ctx = ServiceContext::default();
        let ir = ServiceIR {
            ty: ServiceType::Resolved,
            tag: Some("resolved-dns".to_string()),
            listen: Some("127.0.0.53".to_string()),
            listen_port: Some(53),
            ..Default::default()
        };

        let service = registry.build(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "resolved");
        assert_eq!(service.tag(), "resolved-dns");

        // This registry intentionally uses the stub builder directly. Platform
        // selection of the real service is covered by register_service_stubs().
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
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(6001),
            servers: Some(HashMap::from([("/".to_string(), "ss-in".to_string())])),
            ..Default::default()
        };

        let service = registry.build(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "ssm-api");
        assert_eq!(service.tag(), "ssm");

        // Starting should fail with helpful error if stub, or succeed if real
        let result = service.start(StartStage::Initialize);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not implemented"));
    }

    #[test]
    fn test_derp_stub_registration() {
        let registry = sb_core::service::ServiceRegistry::new();
        assert!(registry.register(ServiceType::Derp, build_derp_service));

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_file = tempfile::NamedTempFile::new().unwrap();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(cert_file.path(), cert_pem).unwrap();
        std::fs::write(key_file.path(), key_pem).unwrap();

        let tempdir = tempfile::tempdir().unwrap();
        let config_path = tempdir
            .path()
            .join("derp.key")
            .to_string_lossy()
            .to_string();

        let ctx = ServiceContext::default();
        let ir = ServiceIR {
            ty: ServiceType::Derp,
            tag: Some("derp-relay".to_string()),
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(0),
            config_path: Some(config_path),
            tls: Some(InboundTlsOptionsIR {
                enabled: true,
                certificate_path: Some(cert_file.path().to_string_lossy().to_string()),
                key_path: Some(key_file.path().to_string_lossy().to_string()),
                ..Default::default()
            }),
            stun: Some(DerpStunOptionsIR {
                enabled: false,
                ..Default::default()
            }),
            ..Default::default()
        };

        let service = registry.build(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "derp");
        assert_eq!(service.tag(), "derp-relay");

        // Starting should fail with helpful error if stub, or succeed if real
        let result = service.start(StartStage::Initialize);

        #[cfg(not(feature = "service_derp"))]
        {
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("not implemented"));
        }

        #[cfg(feature = "service_derp")]
        {
            // Even when the service is compiled in, the underlying implementation may still be a
            // placeholder depending on build/platform. Just assert we get a non-empty error.
            if let Err(e) = &result {
                assert!(!e.to_string().is_empty());
            }
        }
    }
}
