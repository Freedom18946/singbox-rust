//! Runtime health aggregation module

use std::sync::Arc;

use crate::services::{HealthCheck, ServiceHealth};

/// Runtime health aggregator
pub struct RuntimeHealth {
    /// Optional service health checkers
    services: Vec<Arc<dyn HealthCheck>>,
}

impl RuntimeHealth {
    /// Create new runtime health aggregator
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    /// Register a service for health checking
    pub fn register_service(&mut self, service: Arc<dyn HealthCheck>) {
        self.services.push(service);
    }

    /// Get aggregated health status
    pub async fn get_health(&self) -> RuntimeHealthStatus {
        let mut service_healths = Vec::new();
        let mut all_healthy = true;

        for service in &self.services {
            match service.health_status().await {
                Ok(health) => {
                    if !health.healthy {
                        all_healthy = false;
                    }
                    service_healths.push(health);
                }
                Err(e) => {
                    all_healthy = false;
                    service_healths.push(ServiceHealth::unhealthy(format!(
                        "Health check failed: {}",
                        e
                    )));
                }
            }
        }

        RuntimeHealthStatus {
            healthy: all_healthy,
            services: service_healths,
        }
    }
}

impl Default for RuntimeHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime health status
#[derive(Debug)]
pub struct RuntimeHealthStatus {
    /// Overall health
    pub healthy: bool,
    /// Individual service health statuses
    pub services: Vec<ServiceHealth>,
}

impl RuntimeHealthStatus {
    /// Convert to JSON for API responses
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "healthy": self.healthy,
            "services": self.services.iter().map(|s| {
                serde_json::json!({
                    "healthy": s.healthy,
                    "message": s.message,
                    "last_check_elapsed_ms": s.last_check.elapsed().as_millis(),
                })
            }).collect::<Vec<_>>(),
        })
    }
}
