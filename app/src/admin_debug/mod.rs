pub mod audit;
pub mod breaker;
pub mod cache;
pub mod endpoints;
pub mod http;
pub mod http_util;
pub mod prefetch;
pub mod reloadable;
pub mod security;
pub mod security_async;
pub mod security_metrics;
mod server_extension;

use std::sync::Arc;
use std::time::Instant;

pub use sb_api::debug::auth;
pub use sb_api::debug::server::{AuthConf, TlsConf};

pub struct AdminDebugHandle {
    server: Option<sb_api::debug::server::AdminDebugHandle>,
    reload_signal: Option<reloadable::ReloadSignalHandle>,
}

impl AdminDebugHandle {
    pub async fn shutdown(mut self) {
        if let Some(reload_signal) = self.reload_signal.take() {
            reload_signal.shutdown().await;
        }
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }
}

#[derive(Clone)]
pub struct AdminDebugState {
    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    analyze_registry: Arc<crate::analyze::registry::AnalyzeRegistry>,
    breaker: Arc<breaker::BreakerStore>,
    cache: Arc<cache::CacheStore>,
    reloadable: Arc<reloadable::ReloadableConfigStore>,
    security_metrics: Arc<security_metrics::SecurityMetricsState>,
    started_at: Instant,
}

pub struct AdminDebugQuery<'a> {
    state: &'a AdminDebugState,
}

impl AdminDebugState {
    #[must_use]
    pub const fn new(
        #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))] analyze_registry: Arc<
            crate::analyze::registry::AnalyzeRegistry,
        >,
        breaker: Arc<breaker::BreakerStore>,
        cache: Arc<cache::CacheStore>,
        reloadable: Arc<reloadable::ReloadableConfigStore>,
        security_metrics: Arc<security_metrics::SecurityMetricsState>,
        started_at: Instant,
    ) -> Self {
        Self {
            #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
            analyze_registry,
            breaker,
            cache,
            reloadable,
            security_metrics,
            started_at,
        }
    }

    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    #[must_use]
    pub fn analyze_registry(&self) -> &crate::analyze::registry::AnalyzeRegistry {
        &self.analyze_registry
    }

    #[must_use]
    pub const fn query(&self) -> AdminDebugQuery<'_> {
        AdminDebugQuery { state: self }
    }

    #[must_use]
    pub fn security_metrics_state(&self) -> Arc<security_metrics::SecurityMetricsState> {
        Arc::clone(&self.security_metrics)
    }

    #[must_use]
    pub fn reloadable_config(&self) -> reloadable::EnvConfig {
        self.query().reloadable_config()
    }

    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.query().started_at()
    }

    #[must_use]
    pub fn spawn_reload_signal(&self) -> reloadable::ReloadSignalHandle {
        reloadable::spawn_signal_handler(Arc::clone(&self.reloadable))
    }

    /// # Errors
    /// Returns any bind or startup error from the admin debug HTTP server.
    pub async fn spawn_http_server(
        self: &Arc<Self>,
        addr: std::net::SocketAddr,
        tls: Option<TlsConf>,
        auth: AuthConf,
    ) -> std::io::Result<AdminDebugHandle> {
        let server = sb_api::debug::server::spawn(
            addr,
            tls,
            auth,
            server_extension::extension(Arc::clone(self)),
        )
        .await?;
        Ok(AdminDebugHandle {
            server: Some(server),
            reload_signal: Some(self.spawn_reload_signal()),
        })
    }

    #[must_use]
    pub fn spawn_plain_http_server_sync(self: &Arc<Self>, addr: String) -> AdminDebugHandle {
        AdminDebugHandle {
            server: Some(sb_api::debug::server::spawn_plain_sync(
                addr,
                server_extension::extension(Arc::clone(self)),
            )),
            reload_signal: Some(self.spawn_reload_signal()),
        }
    }

    /// # Errors
    /// Returns an error when the control-plane query path cannot gather a
    /// current admin snapshot.
    pub fn security_snapshot(&self) -> anyhow::Result<security_metrics::SecuritySnapshot> {
        self.query().security_snapshot()
    }

    pub fn apply_config_delta(
        &self,
        delta: &endpoints::config::ConfigDelta,
        dry_run: bool,
    ) -> Result<reloadable::ApplyResult, String> {
        self.reloadable.apply_with_dryrun(delta, dry_run)
    }

    #[must_use]
    pub fn config_version(&self) -> u64 {
        self.query().config_version()
    }

    #[cfg(any(
        feature = "subs_http",
        feature = "subs_clash",
        feature = "subs_singbox"
    ))]
    #[must_use]
    pub fn subs_control_plane(&self) -> endpoints::subs::SubsControlPlane<'_> {
        endpoints::subs::SubsControlPlane::new(
            self.cache.as_ref(),
            self.breaker.as_ref(),
            self.reloadable.as_ref(),
        )
    }
}

impl AdminDebugQuery<'_> {
    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    #[must_use]
    pub fn analyze_registry(&self) -> &crate::analyze::registry::AnalyzeRegistry {
        &self.state.analyze_registry
    }

    #[must_use]
    pub fn reloadable_config(&self) -> reloadable::EnvConfig {
        self.state.reloadable.get()
    }

    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.state.started_at
    }

    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started_at().elapsed().as_secs()
    }

    #[must_use]
    pub fn config_version(&self) -> u64 {
        self.state.reloadable.version()
    }

    #[must_use]
    pub fn supported_kinds_count(&self) -> usize {
        #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
        {
            self.analyze_registry().supported_kinds().len()
        }
        #[cfg(not(any(feature = "router", feature = "sbcore_rules_tool")))]
        {
            0
        }
    }

    #[must_use]
    pub fn supported_async_kinds_count(&self) -> usize {
        #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
        {
            self.analyze_registry().supported_async_kinds().len()
        }
        #[cfg(not(any(feature = "router", feature = "sbcore_rules_tool")))]
        {
            0
        }
    }

    /// # Errors
    /// Returns an error when the explicit admin control-plane owners cannot be
    /// queried into a consistent snapshot.
    pub fn security_snapshot(&self) -> anyhow::Result<security_metrics::SecuritySnapshot> {
        self.state.security_metrics.snapshot_with_control_plane(
            &self.state.cache,
            &self.state.breaker,
            security_metrics::current_concurrency(),
        )
    }
}

// Note: http_server contains the plain HTTP admin server functionality
// while http/ contains redirect policies and other HTTP utilities

/// Initialize admin debug server if enabled.
///
/// Returns a handle whose `Drop` fires the cancellation signal (stopping the
/// accept loop). For an orderly shutdown that also *awaits* connection drain,
/// call [`AdminDebugHandle::shutdown()`] instead of just dropping.
pub fn init(addr: Option<&str>, state: Arc<AdminDebugState>) -> AdminDebugHandle {
    let bind_addr = match addr {
        Some(a) => a.to_string(),
        None => std::env::var("SB_DEBUG_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string()),
    };

    state.spawn_plain_http_server_sync(bind_addr)
}

#[cfg(test)]
mod tests {
    #[test]
    fn admin_debug_state_keeps_http_server_wiring_owner_local() {
        let source = include_str!("mod.rs");
        let admin_start = include_str!("../run_engine_runtime/admin_start.rs");
        let health = include_str!("endpoints/health.rs");
        let metrics = include_str!("endpoints/metrics.rs");

        assert!(source.contains("pub struct AdminDebugQuery"));
        assert!(source.contains("pub const fn query(&self) -> AdminDebugQuery<'_>"));
        assert!(source.contains("async fn spawn_http_server("));
        assert!(source.contains("fn spawn_plain_http_server_sync("));
        assert!(source.contains("fn reloadable_config(&self)"));
        assert!(source.contains("fn apply_config_delta("));
        assert!(source.contains("fn subs_control_plane(&self)"));
        assert!(source.contains("state.spawn_plain_http_server_sync(bind_addr)"));
        assert!(health.contains("let query = state.query();"));
        assert!(metrics.contains("let query = state.query();"));
        assert!(admin_start.contains("admin_state.spawn_http_server("));
        assert!(!admin_start.contains("http_server::spawn("));
    }
}
