//! Rule matching engine for Rule-Set
//!
//! Provides high-performance rule matching with:
//! - Domain matching (exact/suffix/keyword/regex)
//! - IP/CIDR matching with prefix tree
//! - Logical operations (AND/OR)
//! - Match result caching

use super::*;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;

/// Match context for rule evaluation
#[derive(Debug, Clone, Default)]
pub struct MatchContext {
    pub domain: Option<String>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: u16,
    pub network: Option<String>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub query_type: Option<String>,
    pub geosite_codes: Vec<String>,
    pub geoip_code: Option<String>,
    pub clash_mode: Option<String>,
    pub inbound_tag: Option<String>,
}

/// Compiled regex cache
type RegexCache = Arc<parking_lot::RwLock<HashMap<String, Regex>>>;

/// Rule matcher with caching
#[derive(Debug)]
pub struct RuleMatcher {
    /// The rule-set to match against
    ruleset: Arc<RuleSet>,
    /// Compiled regex cache
    regex_cache: RegexCache,
    /// Match result cache (LRU)
    result_cache: Arc<parking_lot::Mutex<lru::LruCache<MatchKey, bool>>>,
}

/// Cache key for match results
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct MatchKey {
    domain: Option<String>,
    ip: Option<IpAddr>,
    port: Option<u16>,
    network: Option<String>,
    query_type: Option<String>,
    clash_mode: Option<String>,
    inbound_tag: Option<String>,
}

impl RuleMatcher {
    /// Create a new matcher for a rule-set
    pub fn new(ruleset: Arc<RuleSet>) -> Self {
        Self {
            ruleset,
            regex_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            result_cache: Arc::new(parking_lot::Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(10000).unwrap(),
            ))),
        }
    }

    /// Match against the rule-set
    pub fn matches(&self, ctx: &MatchContext) -> bool {
        // Build cache key
        let key = MatchKey {
            domain: ctx.domain.clone(),
            ip: ctx.destination_ip,
            port: Some(ctx.destination_port),
            network: ctx.network.clone(),
            query_type: ctx.query_type.clone(),
            clash_mode: ctx.clash_mode.clone(),
            inbound_tag: ctx.inbound_tag.clone(),
        };

        // Check cache
        {
            let mut cache = self.result_cache.lock();
            if let Some(&result) = cache.get(&key) {
                return result;
            }
        }

        // Perform matching
        let result = self.matches_rules(&self.ruleset.rules, ctx);

        // Cache result
        {
            let mut cache = self.result_cache.lock();
            cache.put(key, result);
        }

        result
    }

    fn matches_rules(&self, rules: &[Rule], ctx: &MatchContext) -> bool {
        for rule in rules {
            if self.matches_rule(rule, ctx) {
                return true;
            }
        }
        false
    }

    fn matches_rule(&self, rule: &Rule, ctx: &MatchContext) -> bool {
        match rule {
            Rule::Default(r) => {
                let result = self.matches_default_rule(r, ctx);
                if r.invert {
                    !result
                } else {
                    result
                }
            }
            Rule::Logical(r) => {
                let result = self.matches_logical_rule(r, ctx);
                if r.invert {
                    !result
                } else {
                    result
                }
            }
        }
    }

    fn matches_default_rule(&self, rule: &DefaultRule, ctx: &MatchContext) -> bool {
        // All conditions must match (AND semantics within a rule)

        // Domain matching (using DomainRule enum)
        if !rule.domain.is_empty() {
            if let Some(ref domain) = ctx.domain {
                if !self.matches_domain_rules(&rule.domain, domain) {
                    return false;
                }
            } else {
                return false; // Rule has domain criteria but no domain in context
            }
        }

        // Domain suffix matching (convenience field)
        if !rule.domain_suffix.is_empty() {
            if let Some(ref domain) = ctx.domain {
                let matched = rule
                    .domain_suffix
                    .iter()
                    .any(|suffix| domain == suffix || domain.ends_with(&format!(".{}", suffix)));
                if !matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Domain keyword matching (convenience field)
        if !rule.domain_keyword.is_empty() {
            if let Some(ref domain) = ctx.domain {
                let matched = rule
                    .domain_keyword
                    .iter()
                    .any(|keyword| domain.contains(keyword));
                if !matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Domain regex matching (convenience field)
        if !rule.domain_regex.is_empty() {
            if let Some(ref domain) = ctx.domain {
                let matched = rule
                    .domain_regex
                    .iter()
                    .any(|pattern| match Regex::new(pattern) {
                        Ok(re) => re.is_match(domain),
                        Err(_) => false,
                    });
                if !matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        if !rule.geosite.is_empty() && !ctx.geosite_codes.iter().any(|c| rule.geosite.contains(c)) {
            return false;
        }

        // IP CIDR matching
        if !rule.ip_cidr.is_empty() {
            let target_ip = if rule.rule_set_ip_cidr_match_source {
                ctx.source_ip
            } else {
                ctx.destination_ip
            };

            if let Some(ip) = target_ip {
                if !self.matches_ip_cidrs(&rule.ip_cidr, &ip) {
                    return false;
                }
            } else {
                // Check accept_empty behavior
                if !rule.rule_set_ip_cidr_accept_empty {
                    return false;
                }
            }
        }

        if !rule.geoip.is_empty() {
            if let Some(ref code) = ctx.geoip_code {
                if !rule.geoip.iter().any(|c| c.eq_ignore_ascii_case(code)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Port matching
        if !rule.port.is_empty() && !rule.port.contains(&ctx.destination_port) {
            return false;
        }

        // Port range matching
        if !rule.port_range.is_empty() {
            let port = ctx.destination_port;
            let in_range = rule
                .port_range
                .iter()
                .any(|(start, end)| port >= *start && port <= *end);
            if !in_range {
                return false;
            }
        }

        // Network matching
        if !rule.network.is_empty() {
            if let Some(ref network) = ctx.network {
                if !rule.network.iter().any(|n| n == network) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Process name matching
        if !rule.process_name.is_empty() {
            if let Some(ref process) = ctx.process_name {
                if !rule.process_name.iter().any(|n| n == process) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Process path matching
        if !rule.process_path.is_empty() {
            if let Some(ref path) = ctx.process_path {
                if !rule.process_path.iter().any(|p| p == path) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Process path regex matching
        if !rule.process_path_regex.is_empty() {
            if let Some(ref path) = ctx.process_path {
                let matched = rule.process_path_regex.iter().any(|pattern| {
                    self.get_or_compile_regex(pattern)
                        .map(|regex| regex.is_match(path))
                        .unwrap_or(false)
                });
                if !matched {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Query type matching
        if !rule.query_type.is_empty() {
            if let Some(ref qt) = ctx.query_type {
                if !rule.query_type.iter().any(|t| t.eq_ignore_ascii_case(qt)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Inbound matching
        if !rule.inbound.is_empty() {
            if let Some(ref tag) = ctx.inbound_tag {
                if !rule.inbound.iter().any(|t| t == tag) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Clash Mode matching
        if let Some(ref mode) = rule.clash_mode {
            if let Some(ref ctx_mode) = ctx.clash_mode {
                if mode != ctx_mode {
                    return false;
                }
            } else {
                return false;
            }
        }

        // IP Is Private matching
        if rule.ip_is_private {
            if let Some(ip) = ctx.destination_ip {
                if !is_private_ip(&ip) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Source IP Is Private matching
        if rule.source_ip_is_private {
            if let Some(ip) = ctx.source_ip {
                if !is_private_ip(&ip) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // IP Accept Any matching
        if rule.ip_accept_any && ctx.destination_ip.is_none() {
            return false;
        }

        true // All conditions matched
    }

    fn matches_logical_rule(&self, rule: &LogicalRule, ctx: &MatchContext) -> bool {
        match rule.mode {
            LogicalMode::And => {
                // All sub-rules must match
                rule.rules.iter().all(|r| self.matches_rule(r, ctx))
            }
            LogicalMode::Or => {
                // At least one sub-rule must match
                rule.rules.iter().any(|r| self.matches_rule(r, ctx))
            }
        }
    }

    fn matches_domain_rules(&self, rules: &[DomainRule], domain: &str) -> bool {
        for rule in rules {
            if self.matches_domain_rule(rule, domain) {
                return true;
            }
        }
        false
    }

    fn matches_domain_rule(&self, rule: &DomainRule, domain: &str) -> bool {
        match rule {
            DomainRule::Exact(pattern) => domain == pattern,
            DomainRule::Suffix(_pattern) => {
                // Use suffix trie or fallback to linear search
                #[cfg(feature = "suffix_trie")]
                {
                    self.ruleset.domain_trie.contains(domain)
                }
                #[cfg(not(feature = "suffix_trie"))]
                {
                    // Fallback: check if domain ends with any suffix
                    self.ruleset
                        .domain_suffixes
                        .iter()
                        .any(|suffix| domain == suffix || domain.ends_with(&format!(".{}", suffix)))
                }
            }
            DomainRule::Keyword(keyword) => domain.contains(keyword),
            DomainRule::Regex(pattern) => match self.get_or_compile_regex(pattern) {
                Some(regex) => regex.is_match(domain),
                None => false,
            },
        }
    }

    fn matches_ip_cidrs(&self, cidrs: &[IpCidr], ip: &IpAddr) -> bool {
        // Use prefix tree for fast matching
        if self.ruleset.ip_tree.matches(ip) {
            return true;
        }

        // Fallback to linear search (for edge cases)
        cidrs.iter().any(|cidr| cidr.matches(ip))
    }

    /// Clear the match result cache
    pub fn clear_cache(&self) {
        let mut cache = self.result_cache.lock();
        cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.result_cache.lock();
        (cache.len(), cache.cap().get())
    }

    /// Retrieve a compiled regex from cache or compile and store it.
    fn get_or_compile_regex(&self, pattern: &str) -> Option<Regex> {
        {
            let cache = self.regex_cache.read();
            if let Some(regex) = cache.get(pattern) {
                return Some(regex.clone());
            }
        }

        let mut cache = self.regex_cache.write();
        match Regex::new(pattern) {
            Ok(regex) => {
                cache.insert(pattern.to_string(), regex.clone());
                Some(regex)
            }
            Err(e) => {
                tracing::warn!("invalid regex pattern '{}': {}", pattern, e);
                None
            }
        }
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            // IPv6 unique local: fc00::/7
            (ip.segments()[0] & 0xfe00) == 0xfc00
                || ip.is_loopback()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ruleset() -> RuleSet {
        let rules = vec![
            Rule::Default(DefaultRule {
                invert: false,
                domain: vec![DomainRule::Suffix("example.com".to_string())],
                domain_suffix: vec!["example.com".to_string()],
                ..Default::default()
            }),
            Rule::Default(DefaultRule {
                invert: false,
                ip_cidr: vec![IpCidr::parse("192.168.0.0/16").unwrap()],
                ..Default::default()
            }),
        ];

        let mut ip_tree = IpPrefixTree::new();
        ip_tree.insert(&IpCidr::parse("192.168.0.0/16").unwrap());

        RuleSet {
            source: RuleSetSource::Local(PathBuf::from("/test")),
            format: RuleSetFormat::Binary,
            version: 1,
            rules,
            #[cfg(feature = "suffix_trie")]
            domain_trie: {
                let mut domain_trie = crate::router::suffix_trie::SuffixTrie::new();
                domain_trie.insert("example.com");
                Arc::new(domain_trie)
            },
            #[cfg(not(feature = "suffix_trie"))]
            domain_suffixes: Arc::new(vec!["example.com".to_string()]),
            ip_tree: Arc::new(ip_tree),
            last_updated: SystemTime::now(),
            etag: None,
        }
    }

    #[test]
    fn test_domain_matching() {
        let ruleset = Arc::new(create_test_ruleset());
        let matcher = RuleMatcher::new(ruleset);

        let ctx = MatchContext {
            domain: Some("test.example.com".to_string()),
            destination_ip: None,
            destination_port: 443,
            network: Some("tcp".to_string()),
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
            query_type: None,
            geosite_codes: Vec::new(),
            geoip_code: None,
            clash_mode: None,
            inbound_tag: None,
        };

        assert!(matcher.matches(&ctx));
    }

    #[test]
    fn test_ip_matching() {
        let ruleset = Arc::new(create_test_ruleset());
        let matcher = RuleMatcher::new(ruleset);

        let ctx = MatchContext {
            domain: None,
            destination_ip: Some("192.168.1.1".parse().unwrap()),
            destination_port: 80,
            network: Some("tcp".to_string()),
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
            query_type: None,
            geosite_codes: Vec::new(),
            geoip_code: None,
            clash_mode: None,
            inbound_tag: None,
        };

        assert!(matcher.matches(&ctx));
    }

    #[test]
    fn test_no_match() {
        let ruleset = Arc::new(create_test_ruleset());
        let matcher = RuleMatcher::new(ruleset);

        let ctx = MatchContext {
            domain: Some("other.com".to_string()),
            destination_ip: Some("10.0.0.1".parse().unwrap()),
            destination_port: 80,
            network: Some("tcp".to_string()),
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
            query_type: None,
            geosite_codes: Vec::new(),
            geoip_code: None,
            clash_mode: None,
            inbound_tag: None,
        };

        assert!(!matcher.matches(&ctx));
    }

    #[test]
    fn test_cache() {
        let ruleset = Arc::new(create_test_ruleset());
        let matcher = RuleMatcher::new(ruleset);

        let ctx = MatchContext {
            domain: Some("test.example.com".to_string()),
            destination_ip: None,
            destination_port: 443,
            network: Some("tcp".to_string()),
            process_name: None,
            process_path: None,
            source_ip: None,
            source_port: None,
            query_type: None,
            geosite_codes: Vec::new(),
            geoip_code: None,
            clash_mode: None,
            inbound_tag: None,
        };

        // First match (cache miss)
        assert!(matcher.matches(&ctx));

        // Second match (cache hit)
        assert!(matcher.matches(&ctx));

        let (size, _cap) = matcher.cache_stats();
        assert_eq!(size, 1);
    }
}
