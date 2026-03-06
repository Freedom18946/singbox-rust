//! DNS integration utilities for routing
//! Provides convenient functions to set up DNS-enabled routing

use std::sync::Arc;

use super::{EnhancedDnsResolver, RouterHandle};
use crate::dns::{Resolver, ResolverHandle};

/// DNS integration configuration
#[derive(Debug, Clone)]
pub struct DnsIntegrationConfig {
    /// Enable DNS resolution in routing decisions
    pub enabled: bool,
    /// DNS resolution timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable enhanced metrics and monitoring
    pub enhanced_metrics: bool,
    /// Resolver name for metrics labeling
    pub resolver_name: String,
}

impl Default for DnsIntegrationConfig {
    fn default() -> Self {
        Self {
            enabled: router_dns_from_env(),
            timeout_ms: router_dns_timeout_ms_from_env(),
            enhanced_metrics: true,
            resolver_name: "default".to_string(),
        }
    }
}

fn parse_router_dns_env(value: Option<&str>) -> Result<bool, Arc<str>> {
    match value {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(raw) => Err(format!(
            "router env 'SB_ROUTER_DNS' value '{raw}' is not a recognized boolean; silent parse fallback is disabled; use '1'/'true' or '0'/'false'"
        )
        .into()),
        None => Ok(false),
    }
}

fn router_dns_from_env() -> bool {
    let raw = std::env::var("SB_ROUTER_DNS").ok();
    match parse_router_dns_env(raw.as_deref()) {
        Ok(val) => val,
        Err(reason) => {
            tracing::warn!("{reason}; using default false");
            false
        }
    }
}

fn parse_router_dns_timeout_ms_env(value: Option<&str>) -> Result<u64, Arc<str>> {
    match value {
        Some(raw) => raw.parse::<u64>().map_err(|err| {
            format!(
                "router env 'SB_ROUTER_DNS_TIMEOUT_MS' value '{raw}' is invalid; silent parse fallback is disabled; fix the config explicitly: {err}"
            )
            .into()
        }),
        None => Ok(5000),
    }
}

fn router_dns_timeout_ms_from_env() -> u64 {
    let raw = std::env::var("SB_ROUTER_DNS_TIMEOUT_MS").ok();
    match parse_router_dns_timeout_ms_env(raw.as_deref()) {
        Ok(val) => val,
        Err(reason) => {
            tracing::warn!("{reason}; using default 5000");
            5000
        }
    }
}

/// Set up DNS-enabled routing with the default DNS resolver
pub fn setup_dns_routing() -> RouterHandle {
    setup_dns_routing_with_config(DnsIntegrationConfig::default())
}

/// Set up DNS-enabled routing with custom configuration
pub fn setup_dns_routing_with_config(config: DnsIntegrationConfig) -> RouterHandle {
    let mut router = RouterHandle::from_env();

    if config.enabled {
        let dns_resolver: Arc<dyn Resolver> = crate::dns::global::get()
            .unwrap_or_else(|| Arc::new(ResolverHandle::from_env_or_default()));

        if config.enhanced_metrics {
            let enhanced_resolver =
                EnhancedDnsResolver::new(dns_resolver.clone(), config.resolver_name);
            router = router.with_dns_resolver(Arc::new(enhanced_resolver));
        } else {
            router = router.with_dns_resolver(dns_resolver.clone());
        }
    }

    router
}

/// Set up DNS-enabled routing with a custom resolver
pub fn setup_dns_routing_with_resolver(
    resolver: Arc<dyn Resolver>,
    config: DnsIntegrationConfig,
) -> RouterHandle {
    let mut router = RouterHandle::from_env();

    if config.enabled {
        if config.enhanced_metrics {
            let enhanced_resolver = EnhancedDnsResolver::new(resolver, config.resolver_name);
            router = router.with_dns_resolver(Arc::new(enhanced_resolver));
        } else {
            router = router.with_dns_resolver(resolver);
        }
    }

    router
}

/// Validate DNS integration setup
pub fn validate_dns_integration(router: &RouterHandle) -> Result<(), String> {
    // Check if DNS is enabled in environment
    let dns_enabled = std::env::var("SB_ROUTER_DNS")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false);

    if dns_enabled && !router.has_dns_resolver() {
        return Err("DNS routing is enabled but no DNS resolver is configured".to_string());
    }

    if !dns_enabled && router.has_dns_resolver() {
        eprintln!("Warning: DNS resolver is configured but DNS routing is disabled");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsAnswer, Resolver};
    use std::time::Duration;

    struct TestResolver;

    #[async_trait::async_trait]
    impl Resolver for TestResolver {
        async fn resolve(&self, _domain: &str) -> anyhow::Result<DnsAnswer> {
            Ok(DnsAnswer::new(
                vec!["1.2.3.4".parse().unwrap()],
                Duration::from_secs(300),
                crate::dns::cache::Source::System,
                crate::dns::cache::Rcode::NoError,
            ))
        }

        fn name(&self) -> &str {
            "test"
        }
    }

    #[test]
    fn test_default_config() {
        let config = DnsIntegrationConfig::default();
        assert!(!config.enabled); // Should be false by default unless env var is set
        assert_eq!(config.timeout_ms, 5000);
        assert!(config.enhanced_metrics);
        assert_eq!(config.resolver_name, "default");
    }

    #[test]
    fn test_setup_dns_routing_disabled() {
        // Use explicit config to avoid env var races with parallel tests
        let config = DnsIntegrationConfig {
            enabled: false,
            ..Default::default()
        };
        let router = setup_dns_routing_with_config(config);
        assert!(!router.has_dns_resolver());
    }

    #[test]
    fn test_setup_dns_routing_enabled() {
        // Use explicit config to avoid env var races with parallel tests
        let config = DnsIntegrationConfig {
            enabled: true,
            ..Default::default()
        };
        let router = setup_dns_routing_with_config(config);
        assert!(router.has_dns_resolver());
    }

    #[test]
    fn test_setup_with_custom_resolver() {
        let config = DnsIntegrationConfig {
            enabled: true,
            enhanced_metrics: false,
            ..Default::default()
        };

        let resolver = Arc::new(TestResolver);
        let router = setup_dns_routing_with_resolver(resolver, config);
        assert!(router.has_dns_resolver());
    }

    #[test]
    fn test_validate_dns_integration_no_resolver() {
        // When SB_ROUTER_DNS is not set, a router without resolver should be valid
        // Note: We can't reliably test env-var-dependent behavior in parallel tests,
        // so we only test the case where no resolver is configured and DNS is not
        // explicitly enabled (the common default case).
        let router = RouterHandle::from_env();
        // If SB_ROUTER_DNS happens to be "1" (set by another test), this would fail,
        // but in practice, validation just checks consistency.
        // Test the direct logic: router without resolver and dns not enabled = ok
        if std::env::var("SB_ROUTER_DNS")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            // Another test set the env var; skip this assertion
            assert!(validate_dns_integration(&router).is_err());
        } else {
            assert!(validate_dns_integration(&router).is_ok());
        }
    }

    #[test]
    fn invalid_router_dns_env_reports_explicitly() {
        let err = super::parse_router_dns_env(Some("on"))
            .expect_err("unrecognized boolean env should be rejected explicitly");
        let msg = err.to_string();
        assert!(msg.contains("SB_ROUTER_DNS"));
        assert!(msg.contains("silent parse fallback is disabled"));
    }

    #[test]
    fn invalid_router_dns_timeout_ms_env_reports_explicitly() {
        let err = super::parse_router_dns_timeout_ms_env(Some("bad-ms"))
            .expect_err("invalid timeout env should be rejected explicitly");
        let msg = err.to_string();
        assert!(msg.contains("SB_ROUTER_DNS_TIMEOUT_MS"));
        assert!(msg.contains("silent parse fallback is disabled"));
    }
}
