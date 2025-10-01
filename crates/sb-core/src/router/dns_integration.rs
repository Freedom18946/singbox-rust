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
            enabled: std::env::var("SB_ROUTER_DNS")
                .ok()
                .map(|v| v == "1")
                .unwrap_or(false),
            timeout_ms: std::env::var("SB_ROUTER_DNS_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5000),
            enhanced_metrics: true,
            resolver_name: "default".to_string(),
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
        let dns_resolver = ResolverHandle::from_env_or_default();

        if config.enhanced_metrics {
            let enhanced_resolver =
                EnhancedDnsResolver::new(Arc::new(dns_resolver), config.resolver_name);
            router = router.with_dns_resolver(Arc::new(enhanced_resolver));
        } else {
            router = router.with_dns_resolver(Arc::new(dns_resolver));
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
        std::env::remove_var("SB_ROUTER_DNS");
        let router = setup_dns_routing();
        assert!(!router.has_dns_resolver());
    }

    #[test]
    fn test_setup_dns_routing_enabled() {
        std::env::set_var("SB_ROUTER_DNS", "1");
        let router = setup_dns_routing();
        assert!(router.has_dns_resolver());
        std::env::remove_var("SB_ROUTER_DNS");
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
    fn test_validate_dns_integration() {
        // Test valid configuration
        std::env::remove_var("SB_ROUTER_DNS");
        let router = RouterHandle::from_env();
        assert!(validate_dns_integration(&router).is_ok());

        // Test invalid configuration (DNS enabled but no resolver)
        std::env::set_var("SB_ROUTER_DNS", "1");
        let router = RouterHandle::from_env();
        assert!(validate_dns_integration(&router).is_err());

        std::env::remove_var("SB_ROUTER_DNS");
    }
}
