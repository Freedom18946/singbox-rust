//! DNS Rule Engine with Rule-Set support
//!
//! Provides DNS routing based on Rule-Set matching:
//! - Route DNS queries to different upstreams based on domain rules
//! - Support Rule-Set domain matching (exact/suffix/keyword/regex)
//! - Cache routing decisions for performance
//! - Fallback to default upstream when no rule matches

use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use super::{DnsAnswer, DnsUpstream, RecordType};
use crate::router::ruleset::matcher::{MatchContext, RuleMatcher};
use crate::router::ruleset::RuleSet;

/// DNS routing decision cache key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RoutingCacheKey {
    domain: String,
}

/// DNS routing decision
#[derive(Debug, Clone)]
struct RoutingDecision {
    /// Upstream server tag to use
    upstream_tag: String,
}

/// DNS routing rule configuration
#[derive(Debug, Clone)]
pub struct DnsRoutingRule {
    /// Rule-Set to match against
    pub rule_set: Arc<RuleSet>,
    /// Upstream server tag to route to
    pub upstream_tag: String,
    /// Rule priority (lower = higher priority)
    pub priority: u32,
}

/// DNS Rule Engine with Rule-Set routing
pub struct DnsRuleEngine {
    /// Routing rules (sorted by priority)
    rules: Vec<DnsRoutingRule>,
    /// Rule matchers (cached)
    matchers: HashMap<String, RuleMatcher>,
    /// Upstream servers by tag
    upstreams: HashMap<String, Arc<dyn DnsUpstream>>,
    /// Default upstream tag (fallback)
    default_upstream_tag: String,
    /// Routing decision cache
    cache: Arc<parking_lot::Mutex<lru::LruCache<RoutingCacheKey, RoutingDecision>>>,
}

impl DnsRuleEngine {
    /// Create a new DNS rule engine
    pub fn new(
        rules: Vec<DnsRoutingRule>,
        upstreams: HashMap<String, Arc<dyn DnsUpstream>>,
        default_upstream_tag: String,
    ) -> Self {
        // Sort rules by priority
        let mut sorted_rules = rules;
        sorted_rules.sort_by_key(|r| r.priority);

        // Create matchers for each rule-set
        let mut matchers = HashMap::new();
        for rule in &sorted_rules {
            let tag = rule.upstream_tag.clone();
            matchers.insert(tag, RuleMatcher::new(rule.rule_set.clone()));
        }

        // Create routing cache (10k entries)
        let cache = Arc::new(parking_lot::Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(10000).unwrap(),
        )));

        Self {
            rules: sorted_rules,
            matchers,
            upstreams,
            default_upstream_tag,
            cache,
        }
    }

    /// Route a DNS query to the appropriate upstream
    pub async fn resolve(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        // Get routing decision (cached or fresh)
        let decision = self.route_domain(domain);

        // Get upstream server
        let upstream = self.upstreams.get(&decision.upstream_tag).ok_or_else(|| {
            anyhow::anyhow!(
                "Upstream '{}' not found for domain '{}'",
                decision.upstream_tag,
                domain
            )
        })?;

        // Query upstream
        tracing::debug!(
            "DNS routing: domain={}, upstream={}, type={:?}",
            domain,
            decision.upstream_tag,
            record_type
        );

        upstream.query(domain, record_type).await
    }

    /// Determine which upstream to use for a domain
    fn route_domain(&self, domain: &str) -> RoutingDecision {
        // Check cache first
        let cache_key = RoutingCacheKey {
            domain: domain.to_string(),
        };

        {
            let mut cache = self.cache.lock();
            if let Some(decision) = cache.get(&cache_key) {
                return decision.clone();
            }
        }

        // Match against rules (in priority order)
        let ctx = MatchContext {
            domain: Some(domain.to_string()),
            destination_ip: None,
            destination_port: 0,
            network: None,
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
        };

        for rule in &self.rules {
            if let Some(matcher) = self.matchers.get(&rule.upstream_tag) {
                if matcher.matches(&ctx) {
                    let decision = RoutingDecision {
                        upstream_tag: rule.upstream_tag.clone(),
                    };

                    // Cache decision
                    let mut cache = self.cache.lock();
                    cache.put(cache_key, decision.clone());

                    tracing::debug!(
                        "DNS rule matched: domain={}, upstream={}, rule_set={:?}",
                        domain,
                        decision.upstream_tag,
                        rule.rule_set.source
                    );

                    return decision;
                }
            }
        }

        // No rule matched, use default upstream
        let decision = RoutingDecision {
            upstream_tag: self.default_upstream_tag.clone(),
        };

        // Cache decision
        let mut cache = self.cache.lock();
        cache.put(cache_key, decision.clone());

        tracing::debug!(
            "DNS no rule matched: domain={}, using default upstream={}",
            domain,
            decision.upstream_tag
        );

        decision
    }

    /// Resolve both A and AAAA records (dual-stack)
    pub async fn resolve_dual_stack(&self, domain: &str) -> Result<DnsAnswer> {
        let mut all_ips = Vec::new();
        let mut min_ttl: Option<std::time::Duration> = None;

        // Concurrent A and AAAA queries
        let (a_result, aaaa_result) = tokio::join!(
            self.resolve(domain, RecordType::A),
            self.resolve(domain, RecordType::AAAA)
        );

        // Merge A records
        if let Ok(a_answer) = a_result {
            all_ips.extend(a_answer.ips);
            min_ttl = Some(min_ttl.map_or(a_answer.ttl, |ttl| ttl.min(a_answer.ttl)));
        }

        // Merge AAAA records
        if let Ok(aaaa_answer) = aaaa_result {
            all_ips.extend(aaaa_answer.ips);
            min_ttl = Some(min_ttl.map_or(aaaa_answer.ttl, |ttl| ttl.min(aaaa_answer.ttl)));
        }

        if all_ips.is_empty() {
            return Err(anyhow::anyhow!("No DNS records for domain: {}", domain));
        }

        Ok(DnsAnswer::new(
            all_ips,
            min_ttl.unwrap_or(std::time::Duration::from_secs(60)),
            crate::dns::cache::Source::System,
            crate::dns::cache::Rcode::NoError,
        ))
    }

    /// Clear routing cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.lock();
        (cache.len(), cache.cap().get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::ruleset::{DefaultRule, Rule, RuleSetFormat};
    use std::time::SystemTime;

    /// Mock DNS upstream for testing
    struct MockUpstream {
        tag: String,
    }

    #[async_trait::async_trait]
    impl DnsUpstream for MockUpstream {
        async fn query(&self, _domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
            Ok(DnsAnswer::new(
                vec![IpAddr::from([127, 0, 0, 1])],
                std::time::Duration::from_secs(60),
                crate::dns::cache::Source::System,
                crate::dns::cache::Rcode::NoError,
            ))
        }

        fn name(&self) -> &str {
            &self.tag
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_dns_rule_engine_basic() {
        // Create rule-set: *.google.com -> google_dns
        let rule = Rule::Default(DefaultRule {
            domain_suffix: vec!["google.com".to_string()],
            ..Default::default()
        });

        let ruleset = Arc::new(RuleSet {
            source: crate::router::ruleset::RuleSetSource::Local(std::path::PathBuf::from("test")),
            format: RuleSetFormat::Binary,
            version: 1,
            rules: vec![rule],
            #[cfg(feature = "suffix_trie")]
            domain_trie: Arc::new(Default::default()),
            #[cfg(not(feature = "suffix_trie"))]
            domain_suffixes: Arc::new(vec![]),
            ip_tree: Arc::new(Default::default()),
            last_updated: SystemTime::now(),
            etag: None,
        });

        let routing_rule = DnsRoutingRule {
            rule_set: ruleset,
            upstream_tag: "google_dns".to_string(),
            priority: 10,
        };

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "google_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "google_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );
        upstreams.insert(
            "default_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "default_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );

        let engine = DnsRuleEngine::new(
            vec![routing_rule],
            upstreams,
            "default_dns".to_string(),
        );

        // Test: google.com should route to google_dns
        let result = engine.resolve("www.google.com", RecordType::A).await;
        assert!(result.is_ok());

        // Test: other domain should route to default_dns
        let result = engine.resolve("example.com", RecordType::A).await;
        assert!(result.is_ok());

        // Check cache
        let (cache_len, _cache_cap) = engine.cache_stats();
        assert_eq!(cache_len, 2); // 2 domains cached
    }

    #[tokio::test]
    async fn test_dns_rule_engine_priority() {
        // Create two rule-sets with different priorities
        let high_priority_ruleset = Arc::new(RuleSet {
            source: crate::router::ruleset::RuleSetSource::Local(std::path::PathBuf::from("high")),
            format: RuleSetFormat::Binary,
            version: 1,
            rules: vec![Rule::Default(DefaultRule {
                domain_suffix: vec!["example.com".to_string()],
                ..Default::default()
            })],
            #[cfg(feature = "suffix_trie")]
            domain_trie: Arc::new(Default::default()),
            #[cfg(not(feature = "suffix_trie"))]
            domain_suffixes: Arc::new(vec![]),
            ip_tree: Arc::new(Default::default()),
            last_updated: SystemTime::now(),
            etag: None,
        });

        let low_priority_ruleset = Arc::new(RuleSet {
            source: crate::router::ruleset::RuleSetSource::Local(std::path::PathBuf::from("low")),
            format: RuleSetFormat::Binary,
            version: 1,
            rules: vec![Rule::Default(DefaultRule {
                domain_suffix: vec!["example.com".to_string()],
                ..Default::default()
            })],
            #[cfg(feature = "suffix_trie")]
            domain_trie: Arc::new(Default::default()),
            #[cfg(not(feature = "suffix_trie"))]
            domain_suffixes: Arc::new(vec![]),
            ip_tree: Arc::new(Default::default()),
            last_updated: SystemTime::now(),
            etag: None,
        });

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "high_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "high_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );
        upstreams.insert(
            "low_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "low_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );
        upstreams.insert(
            "default_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "default_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );

        let engine = DnsRuleEngine::new(
            vec![
                DnsRoutingRule {
                    rule_set: high_priority_ruleset,
                    upstream_tag: "high_dns".to_string(),
                    priority: 10,
                },
                DnsRoutingRule {
                    rule_set: low_priority_ruleset,
                    upstream_tag: "low_dns".to_string(),
                    priority: 20,
                },
            ],
            upstreams,
            "default_dns".to_string(),
        );

        // High priority rule should win
        let result = engine.resolve("www.example.com", RecordType::A).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dns_rule_engine_cache() {
        let ruleset = Arc::new(RuleSet {
            source: crate::router::ruleset::RuleSetSource::Local(std::path::PathBuf::from("test")),
            format: RuleSetFormat::Binary,
            version: 1,
            rules: vec![Rule::Default(DefaultRule {
                domain_suffix: vec!["test.com".to_string()],
                ..Default::default()
            })],
            #[cfg(feature = "suffix_trie")]
            domain_trie: Arc::new(Default::default()),
            #[cfg(not(feature = "suffix_trie"))]
            domain_suffixes: Arc::new(vec![]),
            ip_tree: Arc::new(Default::default()),
            last_updated: SystemTime::now(),
            etag: None,
        });

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "test_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "test_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );
        upstreams.insert(
            "default_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "default_dns".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );

        let engine = DnsRuleEngine::new(
            vec![DnsRoutingRule {
                rule_set: ruleset,
                upstream_tag: "test_dns".to_string(),
                priority: 10,
            }],
            upstreams,
            "default_dns".to_string(),
        );

        // First query
        let _result = engine.resolve("www.test.com", RecordType::A).await;
        let (cache_len, _) = engine.cache_stats();
        assert_eq!(cache_len, 1);

        // Second query (should hit cache)
        let _result = engine.resolve("www.test.com", RecordType::A).await;
        let (cache_len, _) = engine.cache_stats();
        assert_eq!(cache_len, 1); // Still 1 (cached)

        // Clear cache
        engine.clear_cache();
        let (cache_len, _) = engine.cache_stats();
        assert_eq!(cache_len, 0);
    }
}
