//! Runtime services (optional)

#[cfg(feature = "service_ntp")]
pub mod ntp;

#[cfg(feature = "service_ssmapi")]
pub mod ssmapi;

#[cfg(feature = "service_derp")]
pub mod derp;
#[cfg(feature = "service_resolved")]
pub mod resolved;

use std::io::Error;
use std::time::Instant;

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
