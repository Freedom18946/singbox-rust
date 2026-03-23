use anyhow::{Context, Result};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::net::IpAddr;
use std::time::Instant;
use url::Url;

type SecurityMetricsState = crate::admin_debug::security_metrics::SecurityMetricsState;

fn build_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.cache_size = 1024;
    opts.timeout = std::time::Duration::from_secs(5);
    TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
}

/// Shared DNS resolution logic with optional metrics recording.
///
/// When `metrics` is `Some`, latency and cache-hit/miss counters are recorded.
/// When `None`, metrics calls are silently skipped (same no-op behavior as the
/// compat wrappers when no state is installed).
async fn resolve_checked_inner(
    host: &str,
    metrics: Option<&SecurityMetricsState>,
) -> Result<Vec<IpAddr>> {
    // Skip resolution if it's already an IP
    if let Ok(ip) = host.parse::<IpAddr>() {
        if crate::admin_debug::security::is_private_ip(ip) {
            anyhow::bail!("direct private ip not allowed: {ip}");
        }
        return Ok(vec![ip]);
    }

    // Apply IDNA normalization first
    let normalized_host = crate::admin_debug::security::normalize_host(host)
        .with_context(|| format!("IDNA normalization failed for host: {host}"))?;

    let t0 = Instant::now();
    let resolver = build_resolver();
    let resp = resolver.lookup_ip(&normalized_host).await;
    let ms = t0.elapsed().as_millis() as u64;

    match resp {
        Ok(ips) => {
            if let Some(m) = metrics {
                m.record_dns_latency_ms(ms);
                if ms < 5 {
                    m.inc_dns_cache_hit();
                } else {
                    m.inc_dns_cache_miss();
                }
            }

            let resolved_ips: Vec<IpAddr> = ips.iter().collect();

            // Check each resolved IP against private ranges
            for ip in &resolved_ips {
                if crate::admin_debug::security::is_private_ip(*ip) {
                    anyhow::bail!("resolved to private ip: {ip}");
                }
            }

            Ok(resolved_ips)
        }
        Err(e) => {
            if let Some(m) = metrics {
                m.record_dns_latency_ms(ms);
                // DNS resolution error - count as a miss since we didn't get a
                // successful response
                m.inc_dns_cache_miss();
            }
            anyhow::bail!("dns resolution failed: {e}")
        }
    }
}

/// Unified DNS resolution with private IP checking and metrics.
/// This is the single entry point for all DNS resolution needs in subs processing.
pub async fn resolve_checked(host: &str) -> Result<Vec<IpAddr>> {
    let metrics = crate::admin_debug::security_metrics::current_owner();
    resolve_checked_inner(host, metrics.as_deref()).await
}

/// Unified DNS resolution with an explicit metrics owner for runtime paths that
/// already hold `SecurityMetricsState`.
pub async fn resolve_checked_with_metrics(
    host: &str,
    metrics: &SecurityMetricsState,
) -> Result<Vec<IpAddr>> {
    resolve_checked_inner(host, Some(metrics)).await
}

pub async fn resolve_host_checked(host: &str) -> Result<Vec<IpAddr>> {
    // Legacy wrapper around the new unified function
    resolve_checked(host).await
}

/// Shared forbid-private logic with optional metrics recording.
async fn forbid_private_inner(url: &Url, metrics: Option<&SecurityMetricsState>) -> Result<()> {
    let allow = crate::admin_debug::security::parse_private_allowlist();
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if crate::admin_debug::security::host_matches_allowlist(host, Some(ip), &allow) {
                return Ok(());
            }
        } else if crate::admin_debug::security::host_matches_allowlist(host, None, &allow) {
            return Ok(());
        }
    }

    crate::admin_debug::security::forbid_private_host(url)?;
    if let Some(host) = url.host_str() {
        // Skip resolution if it's already an IP
        if host.parse::<IpAddr>().is_err() {
            let _ips = resolve_checked_inner(host, metrics).await?;
        }
    }
    Ok(())
}

/// Async DNS validation: resolve A/AAAA, reject if any result is private
/// (combined with synchronous allowlist).
pub async fn forbid_private_host_or_resolved_async(url: &Url) -> Result<()> {
    let metrics = crate::admin_debug::security_metrics::current_owner();
    forbid_private_inner(url, metrics.as_deref()).await
}

pub async fn forbid_private_host_or_resolved_async_with_metrics(
    url: &Url,
    metrics: &SecurityMetricsState,
) -> Result<()> {
    forbid_private_inner(url, Some(metrics)).await
}
