use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use std::net::IpAddr;
use std::time::Instant;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use url::Url;

static RESOLVER: OnceCell<TokioAsyncResolver> = OnceCell::new();

fn init_resolver() -> &'static TokioAsyncResolver {
    RESOLVER.get_or_init(|| {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 1024;
        opts.timeout = std::time::Duration::from_secs(5);
        TokioAsyncResolver::tokio(ResolverConfig::default(), opts)
    })
}

/// Unified DNS resolution with private IP checking and metrics
/// This is the single entry point for all DNS resolution needs in subs processing
pub async fn resolve_checked(host: &str) -> Result<Vec<IpAddr>> {
    // Skip resolution if it's already an IP
    if let Ok(ip) = host.parse::<IpAddr>() {
        if super::security::is_private_ip(ip) {
            anyhow::bail!("direct private ip not allowed: {}", ip);
        }
        return Ok(vec![ip]);
    }

    // Apply IDNA normalization first
    let normalized_host = super::security::normalize_host(host)
        .with_context(|| format!("IDNA normalization failed for host: {}", host))?;

    let t0 = Instant::now();
    let r = init_resolver();
    let resp = r.lookup_ip(&normalized_host).await;
    let ms = t0.elapsed().as_millis() as u64;

    match resp {
        Ok(ips) => {
            super::security_metrics::record_dns_latency_ms(ms);
            super::security_metrics::inc_dns_cache_hit(); // TODO: distinguish hit/miss
            let resolved_ips: Vec<IpAddr> = ips.iter().collect();

            // Check each resolved IP against private ranges
            for ip in &resolved_ips {
                if super::security::is_private_ip(*ip) {
                    anyhow::bail!("resolved to private ip: {}", ip);
                }
            }

            Ok(resolved_ips)
        }
        Err(e) => {
            super::security_metrics::record_dns_latency_ms(ms);
            super::security_metrics::inc_dns_cache_miss();
            anyhow::bail!("dns resolution failed: {}", e)
        }
    }
}

pub async fn resolve_host_checked(host: &str) -> Result<Vec<IpAddr>> {
    // Legacy wrapper around the new unified function
    resolve_checked(host).await
}

/// 异步 DNS 校验：解析 A/AAAA，命中私网即拒（配合同步 allowlist）
pub async fn forbid_private_host_or_resolved_async(url: &Url) -> Result<()> {
    super::security::forbid_private_host(url)?;
    if let Some(host) = url.host_str() {
        // Skip resolution if it's already an IP
        if host.parse::<IpAddr>().is_err() {
            let _ips = resolve_host_checked(host).await?; // Just for security check, don't use return value
        }
    }
    Ok(())
}
