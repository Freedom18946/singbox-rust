use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

/// Build the redactor used by logging and admin surfaces without installing
/// any other runtime compatibility owners.
///
/// # Errors
///
/// Returns any regex compilation or initialization error from `Redactor`.
pub fn build_redactor() -> Result<Arc<crate::redact::Redactor>> {
    Ok(Arc::new(crate::redact::Redactor::new()?))
}

#[derive(Clone)]
pub struct AppRuntimeDeps {
    #[cfg(feature = "observe")]
    metrics_registry: sb_metrics::MetricsRegistryHandle,
    #[cfg(feature = "router")]
    pub http_client: Arc<dyn sb_types::ports::http::HttpClient>,
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
        let redactor = build_redactor()?;
        #[cfg(feature = "router")]
        let http_client = sb_core::http_client::install_default_http_client(Arc::new(
            crate::reqwest_http::ReqwestHttpClient::new(),
        ));
        #[cfg(feature = "admin_debug")]
        let security_metrics = crate::admin_debug::security_metrics::install_default(Arc::new(
            crate::admin_debug::security_metrics::SecurityMetricsState::new(),
        ));

        Ok(Self {
            #[cfg(feature = "observe")]
            metrics_registry: sb_metrics::MetricsRegistryHandle::global(),
            #[cfg(feature = "router")]
            http_client,
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

#[cfg(test)]
mod tests {
    use super::build_redactor;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn build_redactor_avoids_runtime_dependency_side_effects() {
        let redactor = build_redactor().expect("redactor should build without runtime deps");
        assert_eq!(redactor.redact_str("token=secret"), "token=***");

        #[cfg(feature = "admin_debug")]
        assert!(
            crate::admin_debug::security_metrics::snapshot().is_err(),
            "building only the redactor should not install default security metrics"
        );

        #[cfg(feature = "router")]
        {
            let err = sb_core::http_client::http_execute(sb_types::ports::http::HttpRequest::get(
                "https://example.invalid/runtime-deps-side-effect",
                1,
            ))
            .await
            .expect_err("building only the redactor should not install the default HTTP client");
            match err {
                sb_types::CoreError::Internal { message } => {
                    assert!(message.contains("install_default_http_client"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
}
