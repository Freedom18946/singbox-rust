//! Observability bootstrap helpers.

use anyhow::Result;

fn tracing_format_is_json() -> bool {
    std::env::var("SB_TRACING_FORMAT").is_ok_and(|value| value == "json")
}

/// Initialize tracing using `RUST_LOG` or a default `info` filter.
pub fn init_tracing_once() -> Result<()> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    init_tracing_once_with_filter(&filter)
}

/// Initialize tracing with an explicit filter.
pub fn init_tracing_once_with_filter(filter: &str) -> Result<()> {
    let fmt_json = tracing_format_is_json();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(true);
    if fmt_json {
        builder
            .json()
            .try_init()
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to install JSON tracing subscriber for '{filter}': {error}"
                )
            })?;
    } else {
        builder.compact().try_init().map_err(|error| {
            anyhow::anyhow!(
                "failed to install compact tracing subscriber for '{filter}': {error}"
            )
        })?;
    }
    tracing::debug!("tracing initialized (json={fmt_json})");
    Ok(())
}

/// Initialize metrics exporter using the caller-provided registry handle.
#[cfg(feature = "sb-metrics")]
pub fn init_metrics_exporter_once(registry: sb_metrics::MetricsRegistryHandle) -> Result<()> {
    if std::env::var("SB_METRICS_ADDR").is_ok() {
        if sb_metrics::spawn_http_exporter_from_env(registry).is_some() {
            tracing::info!("metrics exporter started");
        } else {
            anyhow::bail!("SB_METRICS_ADDR is set but metrics exporter could not be spawned");
        }
    } else {
        tracing::debug!("metrics exporter not configured (SB_METRICS_ADDR unset)");
    }
    Ok(())
}

/// Initialize metrics exporter when metrics support is not compiled in.
#[cfg(not(feature = "sb-metrics"))]
pub fn init_metrics_exporter_once(_registry: ()) -> Result<()> {
    if std::env::var("SB_METRICS_ADDR").is_ok() {
        anyhow::bail!("SB_METRICS_ADDR is set but app was built without sb-metrics support");
    }
    Ok(())
}

/// Initialize tracing and metrics explicitly from runtime dependencies.
#[cfg(feature = "observe")]
pub fn init_observability_once(deps: &app::runtime_deps::AppRuntimeDeps) -> Result<()> {
    init_tracing_once()?;
    init_metrics_exporter_once(deps.metrics_registry())?;
    Ok(())
}

/// Initialize tracing only in builds without metrics support.
#[cfg(not(feature = "observe"))]
pub fn init_observability_once(_deps: &app::runtime_deps::AppRuntimeDeps) -> Result<()> {
    init_tracing_once()
}
