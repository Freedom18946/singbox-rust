use std::sync::OnceLock;

/// Ensure tracing is initialized only once across the application
static TRACING: OnceLock<()> = OnceLock::new();

/// Ensure metrics exporter is initialized only once across the application
static METRICS: OnceLock<()> = OnceLock::new();

/// Initialize tracing once, safe to call multiple times
pub fn init_tracing_once() {
    TRACING.get_or_init(|| {
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
        let fmt_json = std::env::var("SB_TRACING_FORMAT").ok().map(|v| v=="json").unwrap_or(false);
        let builder = tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(filter)).with_target(true);
        let _ = if fmt_json { builder.json().try_init() } else { builder.compact().try_init() };
        tracing::debug!("tracing initialized (json={})", fmt_json);
    });
}

/// Initialize tracing with custom filter, safe to call multiple times
pub fn init_tracing_once_with_filter(filter: &str) {
    TRACING.get_or_init(|| {
        let fmt_json = std::env::var("SB_TRACING_FORMAT").ok().map(|v| v=="json").unwrap_or(false);
        let builder = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_target(true);
        let _ = if fmt_json { builder.json().try_init() } else { builder.compact().try_init() };
        tracing::debug!("tracing initialized with custom filter (json={})", fmt_json);
    });
}

/// Initialize metrics exporter once, safe to call multiple times
/// Returns () on success, () on error (non-blocking)
pub fn init_metrics_exporter_once() {
    METRICS.get_or_init(|| {
        // Check if metrics should be enabled
        if let Ok(addr_env) = std::env::var("SB_METRICS_ADDR") {
            if !addr_env.trim().is_empty() {
                tracing::info!(addr=%addr_env, "metrics exporter initialized (placeholder)");
                // TODO: real metrics exporter implementation
                // For now just log that it would be enabled
            }
        }
        // Always return () to mark as initialized
    });
}

/// Initialize both tracing and metrics in one call, safe to call multiple times
pub fn init_observability_once() {
    init_tracing_once();
    init_metrics_exporter_once();
}