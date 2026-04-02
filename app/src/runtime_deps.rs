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
    metrics_registry_owner: sb_metrics::MetricsRegistryOwner,
    #[cfg(feature = "router")]
    pub http_client: Arc<dyn sb_types::ports::http::HttpClient>,
    #[cfg(all(feature = "admin_debug", feature = "subs_http"))]
    _prefetcher: Arc<crate::admin_debug::prefetch::Prefetcher>,
    pub redactor: Arc<crate::redact::Redactor>,
    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    pub analyze_registry: Arc<crate::analyze::registry::AnalyzeRegistry>,
    #[cfg(feature = "admin_debug")]
    pub breaker: Arc<crate::admin_debug::breaker::BreakerStore>,
    #[cfg(feature = "admin_debug")]
    pub cache: Arc<crate::admin_debug::cache::CacheStore>,
    #[cfg(feature = "admin_debug")]
    pub reloadable: Arc<crate::admin_debug::reloadable::ReloadableConfigStore>,
    #[cfg(feature = "admin_debug")]
    pub security_metrics: Arc<crate::admin_debug::security_metrics::SecurityMetricsState>,
    #[cfg(feature = "admin_debug")]
    admin_state: Arc<crate::admin_debug::AdminDebugState>,
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
        #[cfg(feature = "observe")]
        let metrics_registry_owner = sb_metrics::install_default_registry_owner();
        #[cfg(feature = "router")]
        let http_client = sb_core::http_client::install_default_http_client(Arc::new(
            crate::reqwest_http::ReqwestHttpClient::new(),
        ));
        #[cfg(feature = "admin_debug")]
        let breaker = crate::admin_debug::breaker::install_default(Arc::new(
            crate::admin_debug::breaker::BreakerStore::from_env(),
        ));
        #[cfg(feature = "admin_debug")]
        let cache = crate::admin_debug::cache::install_default(Arc::new(
            crate::admin_debug::cache::CacheStore::from_env(),
        ));
        #[cfg(feature = "admin_debug")]
        let reloadable = crate::admin_debug::reloadable::install_default(Arc::new(
            crate::admin_debug::reloadable::ReloadableConfigStore::from_env(),
        ));
        #[cfg(feature = "admin_debug")]
        let security_metrics = crate::admin_debug::security_metrics::install_default(Arc::new(
            crate::admin_debug::security_metrics::SecurityMetricsState::new(),
        ));
        #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
        let analyze_registry = Arc::new(crate::analyze::registry::AnalyzeRegistry::new());
        #[cfg(feature = "admin_debug")]
        let admin_state = Arc::new(crate::admin_debug::AdminDebugState::new(
            #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
            Arc::clone(&analyze_registry),
            Arc::clone(&breaker),
            Arc::clone(&cache),
            Arc::clone(&reloadable),
            Arc::clone(&security_metrics),
            started_at,
        ));
        #[cfg(all(feature = "admin_debug", feature = "subs_http"))]
        let prefetcher = crate::admin_debug::prefetch::install_default_prefetcher(Arc::new(
            crate::admin_debug::prefetch::Prefetcher::from_env(),
        ));

        Ok(Self {
            #[cfg(feature = "observe")]
            metrics_registry_owner,
            #[cfg(feature = "router")]
            http_client,
            #[cfg(all(feature = "admin_debug", feature = "subs_http"))]
            _prefetcher: prefetcher,
            redactor,
            #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
            analyze_registry,
            #[cfg(feature = "admin_debug")]
            breaker,
            #[cfg(feature = "admin_debug")]
            cache,
            #[cfg(feature = "admin_debug")]
            reloadable,
            #[cfg(feature = "admin_debug")]
            security_metrics,
            #[cfg(feature = "admin_debug")]
            admin_state,
            started_at,
        })
    }

    #[cfg(feature = "observe")]
    #[must_use]
    pub fn metrics_registry(&self) -> sb_metrics::MetricsRegistryHandle {
        self.metrics_registry_owner.handle()
    }

    #[cfg(feature = "admin_debug")]
    #[must_use]
    pub fn admin_state(&self) -> Arc<crate::admin_debug::AdminDebugState> {
        Arc::clone(&self.admin_state)
    }
}

#[cfg(test)]
mod tests {
    use super::build_redactor;
    use serial_test::serial;
    use std::sync::Arc;

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

    #[test]
    #[serial]
    #[cfg(feature = "observe")]
    fn app_runtime_deps_exposes_owned_metrics_handle() {
        #[cfg(feature = "admin_debug")]
        crate::admin_debug::security_metrics::clear_default_for_test();

        let deps = super::AppRuntimeDeps::new().expect("runtime deps should build");
        assert!(matches!(
            deps.metrics_registry(),
            sb_metrics::MetricsRegistryHandle::Owned(_)
        ));

        drop(deps);

        #[cfg(feature = "admin_debug")]
        crate::admin_debug::security_metrics::clear_default_for_test();
    }

    #[test]
    #[serial]
    #[cfg(feature = "admin_debug")]
    fn app_runtime_deps_reuses_stable_admin_state_handle() {
        crate::admin_debug::security_metrics::clear_default_for_test();

        let deps = super::AppRuntimeDeps::new().expect("runtime deps should build");
        let first = deps.admin_state();
        let second = deps.admin_state();

        assert!(Arc::ptr_eq(&first, &second));

        drop(deps);
        crate::admin_debug::security_metrics::clear_default_for_test();
    }

    #[test]
    #[serial]
    #[cfg(all(
        feature = "admin_debug",
        any(feature = "router", feature = "sbcore_rules_tool")
    ))]
    fn app_runtime_deps_reuses_analyze_registry_owner_for_admin_state() {
        crate::admin_debug::security_metrics::clear_default_for_test();

        let deps = super::AppRuntimeDeps::new().expect("runtime deps should build");
        let admin_state = deps.admin_state();

        assert!(std::ptr::eq(
            deps.analyze_registry.as_ref(),
            admin_state.analyze_registry()
        ));

        drop(deps);
        crate::admin_debug::security_metrics::clear_default_for_test();
    }
}
