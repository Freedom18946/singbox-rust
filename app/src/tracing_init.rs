#![allow(dead_code)]

//! Observability bootstrap helpers.

use anyhow::Result;

fn tracing_format_is_json() -> bool {
    std::env::var("SB_TRACING_FORMAT").is_ok_and(|value| value == "json")
}

#[cfg(feature = "sb-metrics")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetricsExporterPlan {
    addr: std::net::SocketAddr,
}

#[cfg(feature = "sb-metrics")]
impl MetricsExporterPlan {
    #[must_use]
    pub const fn explicit(addr: std::net::SocketAddr) -> Self {
        Self { addr }
    }

    /// # Errors
    ///
    /// Returns an error when the supplied listen address is not a valid
    /// `SocketAddr`.
    pub fn parse(addr: &str, source: &'static str) -> Result<Self> {
        addr.parse().map(Self::explicit).map_err(|error| {
            anyhow::anyhow!("{source} value '{addr}' is not a valid SocketAddr: {error}")
        })
    }

    /// # Errors
    ///
    /// Returns an error when the configured listen address is invalid.
    pub fn from_optional(addr: Option<&str>, source: &'static str) -> Result<Option<Self>> {
        addr.map(|value| Self::parse(value, source)).transpose()
    }

    /// # Errors
    ///
    /// Returns an error when `SB_METRICS_ADDR` is set but invalid.
    pub fn from_env() -> Result<Option<Self>> {
        Self::from_optional(
            std::env::var("SB_METRICS_ADDR").ok().as_deref(),
            "SB_METRICS_ADDR",
        )
    }

    #[must_use]
    pub fn install(self, registry: sb_metrics::MetricsRegistryHandle) -> MetricsExporterHandle {
        MetricsExporterHandle::new(registry, self.addr)
    }
}

#[cfg(feature = "sb-metrics")]
pub struct MetricsExporterHandle {
    join: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "sb-metrics")]
impl MetricsExporterHandle {
    #[must_use]
    pub fn new(registry: sb_metrics::MetricsRegistryHandle, addr: std::net::SocketAddr) -> Self {
        Self {
            join: sb_metrics::spawn_http_exporter(registry, addr),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_join_for_test(join: tokio::task::JoinHandle<()>) -> Self {
        Self { join }
    }

    pub fn detach(self) {
        drop(self.join);
    }

    pub async fn shutdown(self) {
        self.join.abort();
        if let Err(error) = self.join.await {
            if !error.is_cancelled() {
                tracing::warn!(%error, "metrics exporter join failed during shutdown");
            }
        }
    }
}

#[cfg(not(feature = "sb-metrics"))]
pub struct MetricsExporterHandle;

#[cfg(not(feature = "sb-metrics"))]
impl MetricsExporterHandle {
    pub const fn detach(self) {}

    pub async fn shutdown(self) {}
}

/// Initialize tracing using `RUST_LOG` or a default `info` filter.
///
/// # Errors
///
/// Returns the subscriber installation error from `init_tracing_once_with_filter`.
pub fn init_tracing_once() -> Result<()> {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    init_tracing_once_with_filter(&filter)
}

/// Initialize tracing with an explicit filter.
///
/// # Errors
///
/// Returns the tracing subscriber installation error for the selected format.
pub fn init_tracing_once_with_filter(filter: &str) -> Result<()> {
    let fmt_json = tracing_format_is_json();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(true);
    if fmt_json {
        builder.json().try_init().map_err(|error| {
            anyhow::anyhow!("failed to install JSON tracing subscriber for '{filter}': {error}")
        })?;
    } else {
        builder.compact().try_init().map_err(|error| {
            anyhow::anyhow!("failed to install compact tracing subscriber for '{filter}': {error}")
        })?;
    }
    tracing::debug!("tracing initialized (json={fmt_json})");
    Ok(())
}

/// Initialize metrics exporter using the caller-provided registry handle.
#[cfg(feature = "sb-metrics")]
///
/// # Errors
///
/// Returns any exporter startup error when `SB_METRICS_ADDR` is configured.
#[must_use]
pub fn install_metrics_exporter(
    registry: sb_metrics::MetricsRegistryHandle,
    addr: std::net::SocketAddr,
) -> MetricsExporterHandle {
    MetricsExporterPlan::explicit(addr).install(registry)
}

/// Install metrics exporter from an optional listen address.
///
/// # Errors
///
/// Returns an error when the configured listen address is invalid.
#[cfg(feature = "sb-metrics")]
pub fn install_metrics_exporter_from_listen(
    registry: sb_metrics::MetricsRegistryHandle,
    listen: Option<&str>,
    source: &'static str,
) -> Result<Option<MetricsExporterHandle>> {
    Ok(MetricsExporterPlan::from_optional(listen, source)?.map(|plan| plan.install(registry)))
}

/// Install metrics exporter from `SB_METRICS_ADDR` if configured.
///
/// # Errors
///
/// Returns an error when `SB_METRICS_ADDR` is set but invalid.
#[cfg(feature = "sb-metrics")]
pub fn install_configured_metrics_exporter(
    registry: sb_metrics::MetricsRegistryHandle,
) -> Result<Option<MetricsExporterHandle>> {
    Ok(MetricsExporterPlan::from_env()?.map(|plan| plan.install(registry)))
}

/// Install metrics exporter for legacy compat callers and detach its task.
///
/// # Errors
///
/// Returns an error when `SB_METRICS_ADDR` is set but invalid.
#[cfg(feature = "sb-metrics")]
pub fn install_compat_metrics_exporter(registry: sb_metrics::MetricsRegistryHandle) -> Result<()> {
    if let Some(handle) = install_configured_metrics_exporter(registry)? {
        tracing::info!("metrics exporter started");
        handle.detach();
    }
    Ok(())
}

/// Initialize metrics exporter using the caller-provided registry handle.
#[cfg(feature = "sb-metrics")]
///
/// # Errors
///
/// Returns any exporter startup error when `SB_METRICS_ADDR` is configured.
#[must_use]
pub fn start_metrics_exporter(
    registry: sb_metrics::MetricsRegistryHandle,
    addr: std::net::SocketAddr,
) -> MetricsExporterHandle {
    install_metrics_exporter(registry, addr)
}

/// # Errors
///
/// Returns any exporter startup error when `SB_METRICS_ADDR` is configured.
#[cfg(feature = "sb-metrics")]
pub fn start_metrics_exporter_if_configured(
    registry: sb_metrics::MetricsRegistryHandle,
) -> Result<Option<MetricsExporterHandle>> {
    install_configured_metrics_exporter(registry)
}

/// # Errors
///
/// Returns any exporter startup error when `SB_METRICS_ADDR` is configured.
pub fn init_metrics_exporter_once(registry: sb_metrics::MetricsRegistryHandle) -> Result<()> {
    install_compat_metrics_exporter(registry)
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
///
/// # Errors
///
/// Returns any tracing or metrics bootstrap error from the explicit
/// observability startup chain.
pub fn init_observability_once(deps: &app::runtime_deps::AppRuntimeDeps) -> Result<()> {
    init_tracing_once()?;
    deps.observability().install_compat_metrics_exporter()?;
    Ok(())
}

/// Initialize tracing only in builds without metrics support.
#[cfg(not(feature = "observe"))]
pub fn init_observability_once(_deps: &app::runtime_deps::AppRuntimeDeps) -> Result<()> {
    init_tracing_once()
}

#[cfg(test)]
mod tests {
    #[test]
    fn tracing_init_keeps_metrics_exporter_lifecycle_owner_explicit() {
        let source = include_str!("tracing_init.rs");
        let context = include_str!("run_engine_runtime/context.rs");

        assert!(source.contains("pub struct MetricsExporterPlan"));
        assert!(source.contains("pub fn install_metrics_exporter("));
        assert!(source.contains("pub fn install_configured_metrics_exporter("));
        assert!(source.contains("pub fn install_compat_metrics_exporter("));
        assert!(source.contains("pub struct MetricsExporterHandle"));
        assert!(source.contains("pub fn start_metrics_exporter("));
        assert!(source.contains("pub fn start_metrics_exporter_if_configured("));
        assert!(source.contains("handle.detach();"));
        assert!(context.contains("fn install_metrics_exporter("));
        assert!(!context.contains("struct PromExporterHandle"));
    }
}
