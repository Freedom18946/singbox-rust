//! Background services (NTP, Resolved, DERP, SSM, etc.)

pub mod cache_file;
pub mod clash_api;

#[cfg(feature = "service_derp")]
pub mod derp;

#[cfg(feature = "service_ntp")]
pub mod ntp;

#[cfg(feature = "service_resolved")]
pub mod resolved;

#[cfg(feature = "service_ssmapi")]
pub mod ssmapi;

pub mod v2ray_api;

use std::io::Error;
use std::time::Instant;

/// Register built-in services.
pub fn register_builtins() {
    #[cfg(feature = "service_resolved")]
    crate::service::register_service(
        sb_config::ir::ServiceType::Resolved,
        resolved::build_resolved_service,
    );
    #[cfg(feature = "service_derp")]
    crate::service::register_service(sb_config::ir::ServiceType::Derp, derp::build_derp_service);
    #[cfg(feature = "service_ssmapi")]
    crate::service::register_service(
        sb_config::ir::ServiceType::Ssmapi,
        ssmapi::build_ssmapi_service,
    );
}

/// Health check trait for services
#[async_trait::async_trait]
pub trait HealthCheck: Send + Sync {
    /// Check service health status
    async fn health_status(&self) -> Result<ServiceHealth, Error>;
}

/// Service health status
#[derive(Debug, Clone)]
pub struct ServiceHealth {
    /// Whether the service is healthy
    pub healthy: bool,
    /// Optional status message
    pub message: Option<String>,
    /// Last check timestamp
    pub last_check: Instant,
}

impl ServiceHealth {
    /// Create new healthy status
    pub fn healthy(message: impl Into<String>) -> Self {
        Self {
            healthy: true,
            message: Some(message.into()),
            last_check: Instant::now(),
        }
    }

    /// Create new unhealthy status
    pub fn unhealthy(message: impl Into<String>) -> Self {
        Self {
            healthy: false,
            message: Some(message.into()),
            last_check: Instant::now(),
        }
    }
}
