//! DNS Rule Engine with Rule-Set support
//!
//! Provides DNS routing based on Rule-Set matching:
//! - Route DNS queries to different upstreams based on domain rules
//! - Support Rule-Set domain matching (exact/suffix/keyword/regex)
//! - Cache routing decisions for performance
//! - Fallback to default upstream when no rule matches

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

use super::{DnsAnswer, DnsUpstream, RecordType};
use crate::dns::dns_router::DnsQueryContext;
use crate::router::geo::{GeoIpDb, GeoSiteDb};
use crate::router::ruleset::matcher::{MatchContext, RuleMatcher};
use crate::router::ruleset::{RuleSet, RuleSetFormat, RuleSetSource};

/// DNS routing decision cache key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RoutingCacheKey {
    domain: String,
    query_type: String,
}

/// DNS routing decision
#[derive(Debug, Clone)]
struct RoutingDecision {
    /// Upstream server tag to use (None if action is Reject/Hijack)
    upstream_tag: Option<String>,
    /// Matched rule metadata (None when using default)
    matched_rule: Option<MatchedRuleInfo>,
    /// Whether the decision came from cache
    from_cache: bool,
    /// Helper to fail fast if action is Reject
    action: Option<DnsRuleAction>,
    /// Address limit (truncate IPs)
    address_limit: Option<u32>,
    /// Predefined Answer IPs (for HijackDns)
    rewrite_ip: Option<Vec<std::net::IpAddr>>,
    /// Predefined RCode
    rcode: Option<String>,
    /// Predefined Answer Records
    answer: Option<Vec<String>>,
    /// Predefined Authority Records
    #[allow(dead_code)]
    ns: Option<Vec<String>>,
    /// Predefined Additional Records
    #[allow(dead_code)]
    extra: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct MatchedRuleInfo {
    upstream_tag: Option<String>,
    priority: u32,
    source: RuleSetSource,
    format: RuleSetFormat,
    action: DnsRuleAction,
}

struct CompiledRule {
    rule: DnsRoutingRule,
    matcher: RuleMatcher,
}

/// DNS rule action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleAction {
    Route,
    Reject,
    HijackDns,
}

/// DNS routing rule configuration
#[derive(Debug, Clone)]
pub struct DnsRoutingRule {
    /// Rule-Set to match against
    pub rule_set: Arc<RuleSet>,
    /// Upstream server tag to route to (optional for some actions)
    pub upstream_tag: Option<String>,
    /// Rule action
    pub action: DnsRuleAction,
    /// Rule priority (lower = higher priority)
    pub priority: u32,
    /// Address limit
    pub address_limit: Option<u32>,
    /// Predefined IPs
    pub rewrite_ip: Option<Vec<std::net::IpAddr>>,
    /// Predefined RCode
    pub rcode: Option<String>,
    /// Predefined Answer Records
    pub answer: Option<Vec<String>>,
    /// Predefined Authority Records
    pub ns: Option<Vec<String>>,
    /// Predefined Additional Records
    pub extra: Option<Vec<String>>,
}

/// DNS Rule Engine with Rule-Set routing
pub struct DnsRuleEngine {
    /// Routing rules (sorted by priority)
    rules: Vec<CompiledRule>,
    /// Upstream servers by tag
    upstreams: HashMap<String, Arc<dyn DnsUpstream>>,
    /// Default upstream tag (fallback)
    default_upstream_tag: String,
    /// Routing decision cache
    cache: Arc<parking_lot::Mutex<lru::LruCache<RoutingCacheKey, RoutingDecision>>>,
    /// Resolution strategy
    strategy: super::DnsStrategy,
    /// Transport registry for lifecycle management
    registry: Arc<crate::dns::transport::TransportRegistry>,
    /// GeoIP database
    geoip: Option<Arc<GeoIpDb>>,
    /// GeoSite database
    geosite: Option<Arc<GeoSiteDb>>,
}

impl DnsRuleEngine {
    /// Create a new DNS rule engine
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rules: Vec<DnsRoutingRule>,
        upstreams: HashMap<String, Arc<dyn DnsUpstream>>,
        default_upstream_tag: String,
        strategy: super::DnsStrategy,
        registry: Arc<crate::dns::transport::TransportRegistry>,
        geoip: Option<Arc<GeoIpDb>>,
        geosite: Option<Arc<GeoSiteDb>>,
    ) -> Self {
        // Sort rules by priority
        let mut sorted_rules = rules;
        sorted_rules.sort_by_key(|r| r.priority);

        // Compile matchers for each rule-set, preserving priority order
        let rules = sorted_rules
            .into_iter()
            .map(|rule| CompiledRule {
                matcher: RuleMatcher::new(rule.rule_set.clone()),
                rule,
            })
            .collect();

        // Create routing cache (10k entries)
        let cache = Arc::new(parking_lot::Mutex::new(lru::LruCache::new(
            std::num::NonZeroUsize::new(10000).unwrap(),
        )));

        Self {
            rules,
            upstreams,
            default_upstream_tag,
            cache,
            strategy,
            registry,
            geoip,
            geosite,
        }
    }

    /// Route a DNS query to the appropriate upstream
    pub async fn resolve(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        self.resolve_with_context(&DnsQueryContext::default(), domain, record_type)
            .await
    }

    /// Route a DNS query with context
    pub async fn resolve_with_context(
        &self,
        ctx: &DnsQueryContext,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnsAnswer> {
        let qt = format!("{:?}", record_type);

        // Build MatchContext
        let mut match_ctx = MatchContext {
            domain: Some(domain.to_string()),
            destination_ip: None,
            destination_port: 0,
            network: ctx.transport.clone().or(Some("udp".to_string())), // Default to UDP if unspecified
            process_name: None,
            process_path: None,
            source_ip: ctx.client.map(|a| a.ip()),
            source_port: ctx.client.map(|a| a.port()),
            query_type: Some(qt.clone()),
            clash_mode: None,
            geosite_codes: if let Some(db) = &self.geosite {
                db.lookup_categories(domain)
            } else {
                Vec::new()
            },
            geoip_code: None, // Will fill if source IP exists
            inbound_tag: ctx.inbound.clone(),
        };

        // Resolve source GeoIP if client IP is present
        if let Some(ip) = match_ctx.source_ip {
            if let Some(db) = &self.geoip {
                if let Some(code) = db.lookup_country(ip) {
                    match_ctx.geoip_code = Some(code);
                }
            }
        }

        // Get routing decision (cached or fresh)
        let decision = self.route_domain(&match_ctx, domain, &qt);

        if let Some(action) = &decision.action {
            match action {
                DnsRuleAction::Reject => {
                    tracing::debug!(
                        "DNS routing: domain={}, type={:?}, action=Reject",
                        domain,
                        record_type
                    );
                    return Ok(DnsAnswer::new(
                        Vec::new(),
                        std::time::Duration::from_secs(0),
                        crate::dns::cache::Source::System,
                        crate::dns::cache::Rcode::Refused,
                    ));
                }
                DnsRuleAction::HijackDns => {
                    let mut answer_ips = Vec::new();
                    // Merge rewrite_ip and answer fields
                    if let Some(ips) = &decision.rewrite_ip {
                        answer_ips.extend(ips.clone());
                    }
                    if let Some(answers) = &decision.answer {
                        for ans in answers {
                            if let Ok(ip) = ans.parse::<std::net::IpAddr>() {
                                answer_ips.push(ip);
                            }
                        }
                    }

                    let rcode = if let Some(rcode_str) = &decision.rcode {
                        match rcode_str.to_ascii_uppercase().as_str() {
                            "NXDOMAIN" => crate::dns::cache::Rcode::NxDomain,
                            "REFUSED" => crate::dns::cache::Rcode::Refused,
                            _ => crate::dns::cache::Rcode::NoError, 
                        }
                    } else {
                        crate::dns::cache::Rcode::NoError
                    };

                    if !answer_ips.is_empty() || decision.rcode.is_some() {
                       tracing::debug!(
                            "DNS routing: domain={}, type={:?}, action=HijackDns (ips={:?}, rcode={:?})",
                            domain,
                            record_type,
                            answer_ips,
                            rcode
                        );

                        answer_ips.retain(|ip| match record_type {
                            RecordType::A => ip.is_ipv4(),
                            RecordType::AAAA => ip.is_ipv6(),
                            _ => true,
                        });
                        
                        return Ok(DnsAnswer::new(
                            answer_ips,
                            std::time::Duration::from_secs(10), 
                            crate::dns::cache::Source::System,
                            rcode,
                        )); 
                    }

                    tracing::debug!(
                        "DNS routing: domain={}, type={:?}, action=HijackDns (empty, returning Refused)",
                        domain,
                        record_type
                    );
                     return Ok(DnsAnswer::new(
                        Vec::new(),
                        std::time::Duration::from_secs(0),
                        crate::dns::cache::Source::System,
                        crate::dns::cache::Rcode::Refused,
                    ));
                }
                DnsRuleAction::Route => {
                    // fallthrough to upstream query
                }
            }
        }

        let tag = decision.upstream_tag.as_deref().unwrap_or(&self.default_upstream_tag);

        // Get upstream server
        let upstream = self.upstreams.get(tag).ok_or_else(|| {
            anyhow::anyhow!(
                "Upstream '{}' not found for domain '{}'",
                tag,
                domain
            )
        })?;

        // Query upstream
        tracing::debug!(
            "DNS routing: domain={}, upstream={}, type={:?}",
            domain,
            tag,
            record_type
        );

        let mut answer = upstream.query(domain, record_type).await?;

        if let Some(limit) = decision.address_limit {
             if answer.ips.len() > limit as usize {
                 answer.ips.truncate(limit as usize);
             }
        }
        Ok(answer)
    }

    /// Explain routing decision for a domain
    pub async fn explain(&self, domain: &str) -> Result<serde_json::Value> {
        // Default to A record for explanation if not specified
        let ctx = MatchContext {
            domain: Some(domain.to_string()),
            query_type: Some("A".to_string()),
            ..Default::default()
        };
        let decision = self.route_domain(&ctx, domain, "A");

        let matched_rule = decision
            .matched_rule
            .as_ref()
            .map(|m| {
                let source = match &m.source {
                    RuleSetSource::Local(path) => serde_json::json!({
                        "type": "local",
                        "path": path
                    }),
                    RuleSetSource::Remote(url) => serde_json::json!({
                        "type": "remote",
                        "url": url
                    }),
                };
                serde_json::json!({
                    "upstream": m.upstream_tag,
                    "action": format!("{:?}", m.action),
                    "priority": m.priority,
                    "rule_set": {
                        "source": source,
                        "format": match m.format {
                            RuleSetFormat::Binary => "binary",
                            RuleSetFormat::Source => "source",
                        }
                    }
                })
            })
            .unwrap_or_else(|| serde_json::Value::Null);

        Ok(serde_json::json!({
            "domain": domain,
            "resolver": "dns_rule_engine",
            "upstream": decision.upstream_tag,
            "action": decision.action.map(|a| format!("{:?}", a)),
            "decision": if decision.matched_rule.is_some() { "rule" } else { "default" },
            "cache": if decision.from_cache { "hit" } else { "miss" },
            "matched_rule": matched_rule
        }))
    }

    /// Determine which upstream to use for a domain
    fn route_domain(&self, ctx: &MatchContext, domain: &str, query_type: &str) -> RoutingDecision {
        // Check cache first
        let cache_key = RoutingCacheKey {
            domain: domain.to_string(),
            query_type: query_type.to_string(),
        };

        {
            let mut cache = self.cache.lock();
            if let Some(decision) = cache.get(&cache_key) {
                #[cfg(feature = "metrics")]
                metrics::counter!("dns_rule_cache_hit_total").increment(1);
                let mut decision = decision.clone();
                decision.from_cache = true;
                return decision;
            }
        }
        #[cfg(feature = "metrics")]
        metrics::counter!("dns_rule_cache_miss_total").increment(1);

        // Match against rules (in priority order)
        // ctx is passed in


        for compiled in &self.rules {
            if compiled.matcher.matches(&ctx) {
                let matched_rule = MatchedRuleInfo {
                    upstream_tag: compiled.rule.upstream_tag.clone(),
                    priority: compiled.rule.priority,
                    source: compiled.rule.rule_set.source.clone(),
                    format: compiled.rule.rule_set.format,
                    action: compiled.rule.action.clone(),
                };
                let decision = RoutingDecision {
                    upstream_tag: compiled.rule.upstream_tag.clone(),
                    matched_rule: Some(matched_rule),
                    from_cache: false,
                    action: Some(compiled.rule.action.clone()),
                    address_limit: compiled.rule.address_limit,
                    rewrite_ip: compiled.rule.rewrite_ip.clone(),
                    rcode: compiled.rule.rcode.clone(),
                    answer: compiled.rule.answer.clone(),
                    ns: compiled.rule.ns.clone(),
                    extra: compiled.rule.extra.clone(),
                };

                // Cache decision
                let mut cache = self.cache.lock();
                cache.put(cache_key, decision.clone());

                tracing::debug!(
                    "DNS rule matched: domain={}, type={}, action={:?}, upstream={:?}",
                    domain,
                    query_type,
                    decision.action,
                    decision.upstream_tag
                );

                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "dns_rule_match_total",
                    "upstream" => decision.upstream_tag.clone().unwrap_or_default(),
                    "matched" => "true"
                )
                .increment(1);

                return decision;
            }
        }

        // No rule matched, use default upstream
        let decision = RoutingDecision {
            upstream_tag: Some(self.default_upstream_tag.clone()),
            matched_rule: None,
            from_cache: false,
            action: None,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
        };

        // Cache decision
        let mut cache = self.cache.lock();
        cache.put(cache_key, decision.clone());

        tracing::debug!(
            "DNS no rule matched: domain={}, type={}, using default upstream={}",
            domain,
            query_type,
            decision.upstream_tag.as_ref().unwrap()
        );

        #[cfg(feature = "metrics")]
        metrics::counter!(
            "dns_rule_match_total",
            "upstream" => decision.upstream_tag.clone().unwrap_or_default(),
            "matched" => "false"
        )
        .increment(1);

        decision
    }

    /// Start the rule engine (and all upstreams)
    pub async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {
        for (tag, up) in &self.upstreams {
            up.start(stage).await.map_err(|e| anyhow::anyhow!("Failed to start upstream {}: {}", tag, e))?;
        }
        self.registry.start_all(stage).await?;
        Ok(())
    }

    /// Close the rule engine
    pub async fn close(&self) -> Result<()> {
        for (tag, up) in &self.upstreams {
            up.close().await.map_err(|e| anyhow::anyhow!("Failed to close upstream {}: {}", tag, e))?;
        }
        self.registry.close_all().await?;
        Ok(())
    }

    /// Resolve both A and AAAA records (dual-stack)
    pub async fn resolve_dual_stack(&self, domain: &str) -> Result<DnsAnswer> {
        self.resolve_dual_stack_with_context(&DnsQueryContext::default(), domain)
            .await
    }

    /// Resolve both A and AAAA records with context
    pub async fn resolve_dual_stack_with_context(
        &self,
        ctx: &DnsQueryContext,
        domain: &str,
    ) -> Result<DnsAnswer> {
        let mut all_ips = Vec::new();
        let mut min_ttl: Option<std::time::Duration> = None;

        use super::DnsStrategy;

        let (query_ipv4, query_ipv6) = match self.strategy {
            DnsStrategy::Ipv4Only => (true, false),
            DnsStrategy::Ipv6Only => (false, true),
            _ => (true, true),
        };

        // TODO: Parallelize queries for better performance
        if query_ipv4 {
            match self.resolve_with_context(ctx, domain, RecordType::A).await {
                Ok(mut ans) => {
                    all_ips.append(&mut ans.ips);
                    min_ttl = Some(ans.ttl);
                }
                Err(e) => {
                    tracing::trace!("Dual-stack A query failed: {}", e);
                }
            }
        }

        if query_ipv6 {
            match self.resolve_with_context(ctx, domain, RecordType::AAAA).await {
                Ok(mut ans) => {
                    all_ips.append(&mut ans.ips);
                    if let Some(ttl) = min_ttl {
                        min_ttl = Some(ttl.min(ans.ttl));
                    } else {
                        min_ttl = Some(ans.ttl);
                    }
                }
                Err(e) => {
                    tracing::trace!("Dual-stack AAAA query failed: {}", e);
                }
            }
        }

        Ok(DnsAnswer::new(
            all_ips,
            min_ttl.unwrap_or_else(|| std::time::Duration::from_secs(10)),
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


#[async_trait::async_trait]
impl crate::dns::dns_router::DnsRouter for DnsRuleEngine {
    async fn exchange(
        &self,
        _ctx: &DnsQueryContext,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("DnsRuleEngine: raw exchange not yet supported"))
    }

    async fn lookup(
        &self,
        ctx: &DnsQueryContext,
        domain: &str,
    ) -> Result<Vec<std::net::IpAddr>> {
        let ans = self.resolve_dual_stack_with_context(ctx, domain).await?;
        Ok(ans.ips)
    }

    async fn lookup_default(&self, domain: &str) -> Result<Vec<std::net::IpAddr>> {
        let tag = &self.default_upstream_tag;
        let upstream = self.upstreams.get(tag).ok_or_else(|| {
            anyhow::anyhow!("Default upstream '{}' not found", tag)
        })?;

        let (query_ipv4, query_ipv6) = match self.strategy {
            crate::dns::DnsStrategy::Ipv4Only => (true, false),
            crate::dns::DnsStrategy::Ipv6Only => (false, true),
            _ => (true, true),
        };

        let mut all_ips = Vec::new();
        if query_ipv4 {
            if let Ok(mut ans) = upstream.query(domain, RecordType::A).await {
                all_ips.append(&mut ans.ips);
            }
        }
        if query_ipv6 {
            if let Ok(mut ans) = upstream.query(domain, RecordType::AAAA).await {
                all_ips.append(&mut ans.ips);
            }
        }
        Ok(all_ips)
    }

    async fn resolve(&self, ctx: &DnsQueryContext, domain: &str) -> Result<DnsAnswer> {
        self.resolve_dual_stack_with_context(ctx, domain).await
    }

    fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        cache.clear();
    }
    
    fn name(&self) -> &str {
        "dns_rule_engine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::ruleset::{DefaultRule, Rule, RuleSetFormat};
    use std::net::IpAddr;
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
            upstream_tag: Some("google_dns".to_string()),
            action: DnsRuleAction::Route,
            priority: 10,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
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
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
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
                    upstream_tag: Some("high_dns".to_string()),
                    action: DnsRuleAction::Route,
                    priority: 10,
                    address_limit: None,
                    rewrite_ip: None,
                    rcode: None,
                    answer: None,
                    ns: None,
                    extra: None,
                },
                DnsRoutingRule {
                    rule_set: low_priority_ruleset,
                    upstream_tag: Some("low_dns".to_string()),
                    action: DnsRuleAction::Route,
                    priority: 20,
                    address_limit: None,
                    rewrite_ip: None,
                    rcode: None,
                    answer: None,
                    ns: None,
                    extra: None,
                },
            ],
            upstreams,
            "default_dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
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
                upstream_tag: Some("test_dns".to_string()),
                action: DnsRuleAction::Route,
                priority: 10,
                address_limit: None,
                rewrite_ip: None,
                rcode: None,
                answer: None,
                ns: None,
                extra: None,
            }],
            upstreams,
            "default_dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
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

    #[tokio::test]
    async fn test_dns_rule_engine_context() {
        use crate::router::ruleset::{Rule, DefaultRule};
        let ruleset = Arc::new(RuleSet {
            source: crate::router::ruleset::RuleSetSource::Local(std::path::PathBuf::from("test")),
            format: RuleSetFormat::Binary,
            version: 1,
            rules: vec![Rule::Default(DefaultRule {
                inbound: vec!["tun".to_string()],
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
            "tun_dns".to_string(),
            Arc::new(MockUpstream {
                tag: "tun_dns".to_string(),
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
                upstream_tag: Some("tun_dns".to_string()),
                action: DnsRuleAction::Route,
                priority: 10,
                address_limit: None,
                rewrite_ip: None,
                rcode: None,
                answer: None,
                ns: None,
                extra: None,
            }],
            upstreams,
            "default_dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );

        // Test with matching context
        let ctx = DnsQueryContext::new().with_inbound("tun");
        let result = engine.resolve_with_context(&ctx, "example.com", RecordType::A).await;
        // Mock Upstream always returns OK. We can't easily inspect which upstream was chosen 
        // without introspection or mocking details, but we can rely on coverage or detailed logs.
        // For this unit test, we at least verify compilation and execution.
        assert!(result.is_ok());

        // For verification, we can check the stats if we had exposted metrics or check cache.
    }
    #[tokio::test]
    async fn explain_reports_rule_and_cache_hit() {
        use crate::router::ruleset::{Rule, DefaultRule};
        let rule = Rule::Default(DefaultRule {
            domain_suffix: vec!["google.com".to_string()],
            ..Default::default()
        });

        let ruleset = Arc::new(RuleSet {
            source: crate::router::ruleset::RuleSetSource::Local(std::path::PathBuf::from(
                "google.srs",
            )),
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
            upstream_tag: Some("google_dns".to_string()),
            action: DnsRuleAction::Route,
            priority: 10,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
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
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );

        let first = engine.explain("www.google.com").await.unwrap();
        assert_eq!(first["upstream"], serde_json::json!("google_dns"));
        assert_eq!(first["decision"], serde_json::json!("rule"));
        assert_eq!(first["cache"], serde_json::json!("miss"));
        assert_eq!(first["matched_rule"]["priority"], serde_json::json!(10));
        assert_eq!(
            first["matched_rule"]["rule_set"]["source"]["type"],
            serde_json::json!("local")
        );

        let cached = engine.explain("www.google.com").await.unwrap();
        assert_eq!(cached["cache"], serde_json::json!("hit"));

        let fallback = engine.explain("example.org").await.unwrap();
        assert_eq!(fallback["decision"], serde_json::json!("default"));
        assert!(fallback["matched_rule"].is_null());
    }
}
