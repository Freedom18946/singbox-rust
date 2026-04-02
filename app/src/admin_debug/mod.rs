#![allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_doc_comments,
    unused_comparisons,
    clippy::future_not_send,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::items_after_statements,
    clippy::await_holding_lock,
    clippy::cast_possible_truncation,
    clippy::assigning_clones,
    clippy::no_effect_underscore_binding,
    clippy::missing_errors_doc,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::implicit_hasher,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::result_large_err,
    clippy::match_same_arms,
    clippy::must_use_candidate,
    clippy::borrow_deref_ref,
    clippy::useless_vec,
    // Additional relaxations for monitoring/metrics code
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::type_complexity,
    clippy::verbose_bit_mask,
    clippy::map_unwrap_or,
    clippy::needless_pass_by_value,
    // Additional style relaxations
    clippy::ref_option,
    clippy::use_debug,
    clippy::format_push_string,
    clippy::significant_drop_tightening,
    clippy::fn_params_excessive_bools,
    clippy::if_same_then_else,
    clippy::single_match_else,
    clippy::trivial_regex,
    clippy::collection_is_never_read,
    clippy::should_implement_trait,
    clippy::struct_excessive_bools,
    clippy::unused_self
)] // Admin debug functionality allows relaxed linting standards

pub mod audit;
pub mod breaker;
pub mod cache;
pub mod endpoints;
pub mod http;
pub mod http_server;
pub mod http_util;
pub mod prefetch;
pub mod reloadable;
pub mod security;
pub mod security_async;
pub mod security_metrics;

#[cfg(feature = "auth")]
pub mod auth;

pub mod middleware;

use std::sync::Arc;
use std::time::Instant;

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
    pub fn security_metrics_state(&self) -> Arc<security_metrics::SecurityMetricsState> {
        Arc::clone(&self.security_metrics)
    }

    #[must_use]
    pub fn prefetch_queue_high_watermark(&self) -> u64 {
        self.security_metrics.get_prefetch_queue_high_watermark()
    }

    #[must_use]
    pub const fn started_at(&self) -> Instant {
        self.started_at
    }

    #[must_use]
    pub fn spawn_reload_signal(&self) -> reloadable::ReloadSignalHandle {
        reloadable::spawn_signal_handler(Arc::clone(&self.reloadable))
    }

    /// # Errors
    /// Returns an error when the control-plane query path cannot gather a
    /// current admin snapshot.
    pub fn security_snapshot(&self) -> anyhow::Result<security_metrics::SecuritySnapshot> {
        self.security_metrics
            .snapshot_with_query(security_metrics::SecuritySnapshotQuery::new(
                &self.cache,
                &self.breaker,
                security_metrics::current_concurrency(),
            ))
    }

    #[must_use]
    pub fn config_version(&self) -> u64 {
        self.reloadable.version()
    }
}

// Note: http_server contains the plain HTTP admin server functionality
// while http/ contains redirect policies and other HTTP utilities

/// Initialize admin debug server if enabled.
///
/// Returns a handle whose `Drop` fires the cancellation signal (stopping the
/// accept loop). For an orderly shutdown that also *awaits* connection drain,
/// call [`AdminDebugHandle::shutdown()`] instead of just dropping.
pub fn init(addr: Option<&str>, state: Arc<AdminDebugState>) -> http_server::AdminDebugHandle {
    let bind_addr = match addr {
        Some(a) => a.to_string(),
        None => std::env::var("SB_DEBUG_ADDR").unwrap_or_else(|_| "127.0.0.1:0".to_string()),
    };

    let reload_signal = state.spawn_reload_signal();
    http_server::spawn_plain_sync(bind_addr, state).with_reload_signal(reload_signal)
}
