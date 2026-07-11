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
        Self::from_options(&crate::runtime_options::RouterRuntimeOptions::default())
    }
}

impl DnsIntegrationConfig {
    #[must_use]
    pub fn from_options(options: &crate::runtime_options::RouterRuntimeOptions) -> Self {
        Self {
            enabled: options.dns_enabled,
            timeout_ms: options.dns_integration_timeout_ms,
            enhanced_metrics: true,
            resolver_name: "default".to_string(),
        }
    }
}

/// Set up DNS-enabled routing with the default DNS resolver
pub fn setup_dns_routing() -> RouterHandle {
    setup_dns_routing_with_runtime_options(Arc::new(
        crate::runtime_options::CoreRuntimeOptions::default(),
    ))
}

#[must_use]
pub fn setup_dns_routing_with_runtime_options(
    runtime_options: Arc<crate::runtime_options::CoreRuntimeOptions>,
) -> RouterHandle {
    let config = DnsIntegrationConfig::from_options(&runtime_options.router);
    setup_dns_routing_with_config_and_options(config, runtime_options)
}

/// Set up DNS-enabled routing with custom configuration
pub fn setup_dns_routing_with_config(config: DnsIntegrationConfig) -> RouterHandle {
    setup_dns_routing_with_config_and_options(
        config,
        Arc::new(crate::runtime_options::CoreRuntimeOptions::default()),
    )
}

fn setup_dns_routing_with_config_and_options(
    config: DnsIntegrationConfig,
    runtime_options: Arc<crate::runtime_options::CoreRuntimeOptions>,
) -> RouterHandle {
    let mut router = RouterHandle::from_options(Arc::new(runtime_options.router.clone()));

    if config.enabled {
        let dns_resolver: Arc<dyn Resolver> = crate::dns::global::get().unwrap_or_else(|| {
            Arc::new(ResolverHandle::from_options(Arc::new(
                runtime_options.dns.clone(),
            )))
        });

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
    let mut router = RouterHandle::from_options(Arc::new(
        crate::runtime_options::RouterRuntimeOptions::default(),
    ));

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
    let dns_enabled = router.runtime_options().dns_enabled;

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
        let router = RouterHandle::from_env();
        assert!(validate_dns_integration(&router).is_ok());
    }
}
