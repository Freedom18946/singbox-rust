use anyhow::{Context, Result};
use serde_json::Value;
use std::sync::Arc;

pub struct RuntimeContext {
    runtime_deps: crate::runtime_deps::AppRuntimeDeps,
    reload_state: Arc<
        crate::run_engine_runtime::config_load::TokioMutex<
            crate::run_engine_runtime::config_load::ReloadState,
        >,
    >,
    startup_config_fingerprint: String,
}

impl RuntimeContext {
    /// Build the runtime dependency/context carrier for a loaded startup config.
    ///
    /// # Errors
    ///
    /// Returns any startup dependency initialization error from
    /// [`crate::runtime_deps::AppRuntimeDeps::new`].
    pub fn from_raw(raw: &Value) -> Result<Self> {
        let runtime_deps =
            crate::runtime_deps::AppRuntimeDeps::new().context("failed to build runtime deps")?;
        let reload_state = crate::run_engine_runtime::config_load::ReloadState::from_raw(raw);
        let startup_config_fingerprint = reload_state.fingerprint_hex.clone();

        Ok(Self {
            runtime_deps,
            reload_state: Arc::new(crate::run_engine_runtime::config_load::TokioMutex::new(
                reload_state,
            )),
            startup_config_fingerprint,
        })
    }

    #[must_use]
    pub fn reload_state(
        &self,
    ) -> Arc<
        crate::run_engine_runtime::config_load::TokioMutex<
            crate::run_engine_runtime::config_load::ReloadState,
        >,
    > {
        Arc::clone(&self.reload_state)
    }

    #[must_use]
    pub fn startup_config_fingerprint(&self) -> &str {
        &self.startup_config_fingerprint
    }

    #[cfg(feature = "admin_debug")]
    #[must_use]
    pub fn admin_state(&self) -> Arc<crate::admin_debug::AdminDebugState> {
        self.runtime_deps.admin_state()
    }

    #[cfg(feature = "observe")]
    #[must_use]
    pub fn metrics_registry(&self) -> sb_metrics::MetricsRegistryHandle {
        self.runtime_deps.metrics_registry()
    }

    #[must_use]
    pub fn maybe_start_prom_exporter(
        &self,
        prom_listen: Option<&str>,
    ) -> Option<PromExporterHandle> {
        let addr = prom_listen?;

        #[cfg(feature = "observe")]
        match addr.parse() {
            Ok(socket_addr) => Some(PromExporterHandle::spawn(
                self.metrics_registry(),
                socket_addr,
            )),
            Err(error) => {
                tracing::warn!(addr = %addr, error = %error, "invalid prom exporter listen addr");
                None
            }
        }

        #[cfg(not(feature = "observe"))]
        {
            tracing::warn!(
                addr = %addr,
                "prom exporter requested but observe feature is disabled; skipping exporter startup"
            );
            None
        }
    }

    #[must_use]
    pub fn watch_runtime(
        &self,
        entries: &[crate::config_loader::ConfigEntry],
        config_inputs: crate::run_engine::ConfigInputs,
        import_path: Option<std::path::PathBuf>,
        reload_output: crate::run_engine::ReloadOutputMode,
        supervisor: Arc<sb_core::runtime::supervisor::Supervisor>,
    ) -> crate::run_engine_runtime::watch::WatchRuntime {
        crate::run_engine_runtime::watch::WatchRuntime::new(
            entries,
            config_inputs,
            import_path,
            reload_output,
            self.reload_state(),
            supervisor,
        )
    }

    #[must_use]
    pub fn spawn_watch(
        &self,
        entries: &[crate::config_loader::ConfigEntry],
        config_inputs: crate::run_engine::ConfigInputs,
        import_path: Option<std::path::PathBuf>,
        reload_output: crate::run_engine::ReloadOutputMode,
        supervisor: Arc<sb_core::runtime::supervisor::Supervisor>,
    ) -> crate::run_engine_runtime::watch::WatchHandle {
        self.watch_runtime(
            entries,
            config_inputs,
            import_path,
            reload_output,
            supervisor,
        )
        .spawn()
    }

    pub async fn start_admin_services(
        &self,
        opts: &crate::run_engine::RunOptions,
        supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
    ) -> Result<crate::run_engine_runtime::admin_start::AdminServices> {
        crate::run_engine_runtime::admin_start::start_admin_services(
            crate::run_engine_runtime::admin_start::AdminStartContext::new(opts, supervisor, self),
        )
        .await
    }
}

#[cfg(feature = "observe")]
pub struct PromExporterHandle {
    join: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "observe")]
impl PromExporterHandle {
    fn spawn(registry: sb_metrics::MetricsRegistryHandle, addr: std::net::SocketAddr) -> Self {
        Self {
            join: sb_metrics::spawn_http_exporter(registry, addr),
        }
    }

    #[cfg(test)]
    fn from_join_for_test(join: tokio::task::JoinHandle<()>) -> Self {
        Self { join }
    }

    pub async fn shutdown(self) {
        self.join.abort();
        if let Err(error) = self.join.await {
            if !error.is_cancelled() {
                tracing::warn!(%error, "prom exporter join failed during shutdown");
            }
        }
    }
}

#[cfg(not(feature = "observe"))]
pub struct PromExporterHandle;

#[cfg(not(feature = "observe"))]
impl PromExporterHandle {
    pub async fn shutdown(self) {}
}

pub struct RuntimeLifecycle {
    prom_exporter: Option<PromExporterHandle>,
    admin_services: crate::run_engine_runtime::admin_start::AdminServices,
    watch: Option<crate::run_engine_runtime::watch::WatchHandle>,
}

impl RuntimeLifecycle {
    #[must_use]
    pub const fn new(
        prom_exporter: Option<PromExporterHandle>,
        admin_services: crate::run_engine_runtime::admin_start::AdminServices,
        watch: Option<crate::run_engine_runtime::watch::WatchHandle>,
    ) -> Self {
        Self {
            prom_exporter,
            admin_services,
            watch,
        }
    }

    pub async fn shutdown(self) {
        if let Some(watch) = self.watch {
            watch.shutdown().await;
        }
        self.admin_services.shutdown().await;
        if let Some(prom_exporter) = self.prom_exporter {
            prom_exporter.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeContext, RuntimeLifecycle};
    use serial_test::serial;

    #[test]
    #[serial]
    fn runtime_context_tracks_reload_fingerprint() -> anyhow::Result<()> {
        #[cfg(feature = "admin_debug")]
        crate::admin_debug::security_metrics::clear_default_for_test();

        let raw = serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "rules": [], "default": "direct" }
        });
        let expected = sb_config::json_norm::fingerprint_hex8(&raw);
        let runtime = RuntimeContext::from_raw(&raw)?;

        assert_eq!(runtime.startup_config_fingerprint(), expected);
        let source = include_str!("context.rs");

        assert!(source.contains("fn spawn_watch("));
        assert!(source.contains("async fn start_admin_services("));

        #[cfg(feature = "observe")]
        assert!(matches!(
            runtime.metrics_registry(),
            sb_metrics::MetricsRegistryHandle::Owned(_)
        ));

        drop(runtime);

        #[cfg(feature = "admin_debug")]
        crate::admin_debug::security_metrics::clear_default_for_test();
        Ok(())
    }

    #[cfg(feature = "observe")]
    #[tokio::test]
    async fn runtime_lifecycle_shutdown_aborts_owned_prom_exporter_task() {
        let join = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let lifecycle = RuntimeLifecycle::new(
            Some(super::PromExporterHandle::from_join_for_test(join)),
            crate::run_engine_runtime::admin_start::AdminServices::default(),
            None,
        );

        lifecycle.shutdown().await;
    }
}
