use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct AppRuntimeDeps {
    #[cfg(feature = "observe")]
    metrics_registry: sb_metrics::MetricsRegistryHandle,
    pub redactor: Arc<crate::redact::Redactor>,
    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    pub analyze_registry: Arc<crate::analyze::registry::AnalyzeRegistry>,
    #[cfg(feature = "admin_debug")]
    pub security_metrics: Arc<crate::admin_debug::security_metrics::SecurityMetricsState>,
    pub started_at: Instant,
}

impl AppRuntimeDeps {
    /// Build the explicit runtime dependency container for the current process.
    ///
    /// # Errors
    ///
    /// Returns any startup-time initialization error, currently limited to
    /// `Redactor` construction failures.
    pub fn new() -> Result<Self> {
        let started_at = Instant::now();
        let redactor = Arc::new(crate::redact::Redactor::new()?);
        #[cfg(feature = "admin_debug")]
        let security_metrics = crate::admin_debug::security_metrics::install_default(Arc::new(
            crate::admin_debug::security_metrics::SecurityMetricsState::new(),
        ));

        Ok(Self {
            #[cfg(feature = "observe")]
            metrics_registry: sb_metrics::MetricsRegistryHandle::global(),
            redactor,
            #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
            analyze_registry: Arc::new(crate::analyze::registry::AnalyzeRegistry::new()),
            #[cfg(feature = "admin_debug")]
            security_metrics,
            started_at,
        })
    }

    #[cfg(feature = "observe")]
    #[must_use]
    pub const fn metrics_registry(&self) -> sb_metrics::MetricsRegistryHandle {
        self.metrics_registry
    }

    #[cfg(feature = "admin_debug")]
    #[must_use]
    pub fn admin_state(&self) -> Arc<crate::admin_debug::AdminDebugState> {
        Arc::new(crate::admin_debug::AdminDebugState {
            #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
            analyze_registry: Arc::clone(&self.analyze_registry),
            security_metrics: Arc::clone(&self.security_metrics),
            started_at: self.started_at,
        })
    }
}
