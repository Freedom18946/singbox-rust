use std::sync::OnceLock;

/// Ensure tracing is initialized only once across the application
#[allow(dead_code)]
static TRACING: OnceLock<()> = OnceLock::new();

/// Ensure metrics exporter is initialized only once across the application
#[allow(dead_code)]
static METRICS: OnceLock<()> = OnceLock::new();

/// Initialize tracing once, safe to call multiple times
#[allow(dead_code)]
pub fn init_tracing_once() {
    TRACING.get_or_init(|| {
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
        let fmt_json = std::env::var("SB_TRACING_FORMAT")
            .ok()
            .is_some_and(|v| v == "json");
        let builder = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_target(true);
        let _ = if fmt_json {
            builder.json().try_init()
        } else {
            builder.compact().try_init()
        };
        tracing::debug!("tracing initialized (json={})", fmt_json);
    });
}

/// Initialize tracing with custom filter, safe to call multiple times
#[allow(dead_code)]
pub fn init_tracing_once_with_filter(filter: &str) {
    TRACING.get_or_init(|| {
        let fmt_json = std::env::var("SB_TRACING_FORMAT")
            .ok()
            .is_some_and(|v| v == "json");
        let builder = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_target(true);
        let _ = if fmt_json {
            builder.json().try_init()
        } else {
            builder.compact().try_init()
        };
        tracing::debug!("tracing initialized with custom filter (json={})", fmt_json);
    });
}

/// Initialize metrics exporter once, safe to call multiple times
/// Returns () on success, () on error (non-blocking)
#[allow(dead_code)]
pub fn init_metrics_exporter_once() {
    METRICS.get_or_init(|| {
        // Spawn Prometheus exporter if SB_METRICS_ADDR is set, e.g. "127.0.0.1:9090"
        if std::env::var("SB_METRICS_ADDR").ok().is_some() {
            #[cfg(feature = "sb-metrics")]
            {
                if let Some(_jh) = sb_metrics::maybe_spawn_http_exporter_from_env() {
                    tracing::info!("metrics exporter started");
                } else {
                    tracing::warn!("metrics exporter disabled or failed to start");
                }
            }
            #[cfg(not(feature = "sb-metrics"))]
            {
                tracing::warn!("metrics exporter disabled: sb-metrics feature not enabled");
            }
        } else {
            tracing::debug!("metrics exporter not configured (SB_METRICS_ADDR unset)");
        }
    });
}

/// Initialize both tracing and metrics in one call, safe to call multiple times
#[allow(dead_code)]
pub fn init_observability_once() {
    init_tracing_once();
    init_metrics_exporter_once();
}
