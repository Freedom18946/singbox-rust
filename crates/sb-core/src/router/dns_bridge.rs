//! DNS bridge implementation to connect DNS module with router
//! This module provides adapters to integrate the DNS system into routing decisions

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use super::engine::{DnsResolve, DnsResult};
use crate::dns::{DnsAnswer, Resolver};

/// Bridge adapter that implements DnsResolve using the DNS module's Resolver trait
pub struct DnsResolverBridge {
    resolver: Arc<dyn Resolver>,
}

impl DnsResolverBridge {
    /// Create a new DNS resolver bridge
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self { resolver }
    }
}

impl DnsResolve for DnsResolverBridge {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = DnsResult> + Send + 'a>> {
        Box::pin(async move {
            // Use a timeout wrapper around the resolver
            let timeout_duration = std::time::Duration::from_millis(timeout_ms);

            match tokio::time::timeout(timeout_duration, self.resolver.resolve(host)).await {
                Ok(Ok(answer)) => {
                    if answer.ips.is_empty() {
                        DnsResult::Miss
                    } else {
                        DnsResult::Ok(answer.ips)
                    }
                }
                Ok(Err(_)) => DnsResult::Error,
                Err(_) => DnsResult::Timeout,
            }
        })
    }
}

/// Enhanced DNS resolver that provides additional metrics and monitoring
pub struct EnhancedDnsResolver {
    inner: Arc<dyn Resolver>,
    name: String,
}

impl EnhancedDnsResolver {
    pub fn new(resolver: Arc<dyn Resolver>, name: String) -> Self {
        Self {
            inner: resolver,
            name,
        }
    }
}

#[async_trait::async_trait]
impl Resolver for EnhancedDnsResolver {
    async fn resolve(&self, domain: &str) -> anyhow::Result<DnsAnswer> {
        let start = std::time::Instant::now();

        // Record query attempt
        #[cfg(feature = "metrics")]
        metrics::counter!("dns_query_total",
            "resolver" => self.name.clone(),
            "domain" => domain.to_string()
        )
        .increment(1);

        let result = self.inner.resolve(domain).await;

        let elapsed = start.elapsed().as_millis() as f64;

        match &result {
            Ok(answer) => {
                // Record successful resolution
                #[cfg(feature = "metrics")]
                {
                    metrics::histogram!("dns_resolve_duration_ms",
                        "resolver" => self.name.clone(),
                        "result" => "success"
                    )
                    .record(elapsed);

                    metrics::counter!("dns_resolve_total",
                        "resolver" => self.name.clone(),
                        "result" => "success"
                    )
                    .increment(1);

                    // Record answer count
                    metrics::histogram!("dns_answer_count",
                        "resolver" => self.name.clone()
                    )
                    .record(answer.ips.len() as f64);
                }
            }
            Err(_) => {
                // Record failed resolution
                #[cfg(feature = "metrics")]
                {
                    metrics::histogram!("dns_resolve_duration_ms",
                        "resolver" => self.name.clone(),
                        "result" => "error"
                    )
                    .record(elapsed);

                    metrics::counter!("dns_resolve_total",
                        "resolver" => self.name.clone(),
                        "result" => "error"
                    )
                    .increment(1);
                }
            }
        }

        result
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::Duration;

    struct MockResolver {
        response: anyhow::Result<DnsAnswer>,
    }

    #[async_trait::async_trait]
    impl Resolver for MockResolver {
        async fn resolve(&self, _domain: &str) -> anyhow::Result<DnsAnswer> {
            self.response
                .as_ref()
                .map(|r| r.clone())
                .map_err(|e| anyhow::anyhow!("{}", e))
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_dns_bridge_success() {
        let mock_resolver = Arc::new(MockResolver {
            response: Ok(DnsAnswer {
                ips: vec!["1.2.3.4".parse().unwrap()],
                ttl: Duration::from_secs(300),
                source: crate::dns::cache::Source::System,
                rcode: crate::dns::cache::Rcode::NoError,
            }),
        });

        let bridge = DnsResolverBridge::new(mock_resolver);
        let result = bridge.resolve("example.com", 5000).await;

        match result {
            DnsResult::Ok(ips) => {
                assert_eq!(ips.len(), 1);
                assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());
            }
            _ => panic!("Expected successful resolution"),
        }
    }

    #[tokio::test]
    async fn test_dns_bridge_empty_response() {
        let mock_resolver = Arc::new(MockResolver {
            response: Ok(DnsAnswer {
                ips: vec![],
                ttl: Duration::from_secs(300),
                source: crate::dns::cache::Source::System,
                rcode: crate::dns::cache::Rcode::NoError,
            }),
        });

        let bridge = DnsResolverBridge::new(mock_resolver);
        let result = bridge.resolve("example.com", 5000).await;

        match result {
            DnsResult::Miss => {}
            _ => panic!("Expected Miss result for empty response"),
        }
    }

    #[tokio::test]
    async fn test_dns_bridge_error() {
        let mock_resolver = Arc::new(MockResolver {
            response: Err(anyhow::anyhow!("DNS resolution failed")),
        });

        let bridge = DnsResolverBridge::new(mock_resolver);
        let result = bridge.resolve("example.com", 5000).await;

        match result {
            DnsResult::Error => {}
            _ => panic!("Expected Error result"),
        }
    }
}
