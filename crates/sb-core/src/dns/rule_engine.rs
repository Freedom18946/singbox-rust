//! DNS Rule Engine with Rule-Set support
//!
//! Provides DNS routing based on Rule-Set matching:
//! - Route DNS queries to different upstreams based on domain rules
//! - Support Rule-Set domain matching (exact/suffix/keyword/regex)
//! - Cache routing decisions for performance
//! - Fallback to default upstream when no rule matches

use anyhow::Result;
use base64::Engine as _;
use hickory_proto::rr::RecordType as HickoryRecordType;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use super::cache::{DnsCache, Key as CacheKey, QType as CacheQType, Rcode, Source};
use super::{DnsAnswer, DnsUpstream, RecordType};
use crate::dns::dns_router::DnsQueryContext;
use crate::router::geo::{GeoIpDb, GeoSiteDb};
use crate::router::ruleset::matcher::{MatchContext, RuleMatcher};
use crate::router::ruleset::{Rule, RuleSet, RuleSetFormat, RuleSetSource};

/// DNS routing decision cache key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct RoutingCacheKey {
    domain: String,
    query_type: String,
    destination_ip: Option<IpAddr>,
    destination_port: u16,
    network: Option<String>,
    auth_user: Option<String>,
    protocol: Option<String>,
    process_name: Option<String>,
    process_path: Option<String>,
    package_name: Option<String>,
    user: Option<String>,
    user_id: Option<u32>,
    outbound_tag: Option<String>,
    source_ip: Option<IpAddr>,
    source_port: Option<u16>,
    clash_mode: Option<String>,
    inbound_tag: Option<String>,
    network_type: Option<String>,
    network_is_expensive: Option<bool>,
    network_is_constrained: Option<bool>,
    wifi_ssid: Option<String>,
    wifi_bssid: Option<String>,
    ignore_destination_ip_cidr: bool,
}

impl RoutingCacheKey {
    fn from_match_context(ctx: &MatchContext, domain: &str, query_type: &str) -> Self {
        Self {
            domain: domain.to_ascii_lowercase(),
            query_type: query_type.to_string(),
            destination_ip: ctx.destination_ip,
            destination_port: ctx.destination_port,
            network: ctx.network.clone(),
            auth_user: ctx.auth_user.clone(),
            protocol: ctx.protocol.clone(),
            process_name: ctx.process_name.clone(),
            process_path: ctx.process_path.clone(),
            package_name: ctx.package_name.clone(),
            user: ctx.user.clone(),
            user_id: ctx.user_id,
            outbound_tag: ctx.outbound_tag.clone(),
            source_ip: ctx.source_ip,
            source_port: ctx.source_port,
            clash_mode: ctx.clash_mode.clone(),
            inbound_tag: ctx.inbound_tag.clone(),
            network_type: ctx.network_type.clone(),
            network_is_expensive: ctx.network_is_expensive,
            network_is_constrained: ctx.network_is_constrained,
            wifi_ssid: ctx.wifi_ssid.clone(),
            wifi_bssid: ctx.wifi_bssid.clone(),
            ignore_destination_ip_cidr: ctx.ignore_destination_ip_cidr,
        }
    }
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
    /// Client subnet override from route-options (L2.10.21)
    #[allow(dead_code)]
    client_subnet: Option<String>,
    /// Strategy override from matching route-options/rule action.
    strategy: Option<String>,
    /// Disable answer cache for this query.
    disable_cache: bool,
    /// Rewrite TTL for successful answers.
    rewrite_ttl: Option<u32>,
    /// Index of the terminal matched rule, if any.
    matched_rule_index: Option<usize>,
    /// Terminal rule needs post-answer destination IP validation.
    has_destination_ip_match: bool,
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
    has_destination_ip_match: bool,
}

fn lru_capacity(cap: usize) -> std::num::NonZeroUsize {
    std::num::NonZeroUsize::new(cap.max(1)).unwrap_or(std::num::NonZeroUsize::MIN)
}

fn rule_set_has_destination_ip_match(rule_set: &RuleSet) -> bool {
    rule_set.rules.iter().any(rule_has_destination_ip_match)
}

fn rule_has_destination_ip_match(rule: &Rule) -> bool {
    match rule {
        Rule::Default(default_rule) => {
            (!default_rule.ip_cidr.is_empty() && !default_rule.rule_set_ip_cidr_match_source)
                || !default_rule.geoip.is_empty()
                || default_rule.ip_is_private
                || default_rule.ip_accept_any
        }
        Rule::Logical(logical_rule) => logical_rule.rules.iter().any(rule_has_destination_ip_match),
    }
}

fn rcode_to_wire(rcode: Option<&str>) -> u8 {
    match rcode.unwrap_or("NOERROR").to_ascii_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        _ => 0,
    }
}

fn rcode_to_answer(rcode: Option<&str>) -> Rcode {
    match rcode.unwrap_or("NOERROR").to_ascii_uppercase().as_str() {
        "NOERROR" => Rcode::NoError,
        "FORMERR" => Rcode::FormErr,
        "SERVFAIL" => Rcode::ServFail,
        "NXDOMAIN" => Rcode::NxDomain,
        "NOTIMP" => Rcode::NotImp,
        "REFUSED" => Rcode::Refused,
        _ => Rcode::NoError,
    }
}

fn pack_dns_name(name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Some(vec![0]);
    }

    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(out)
}

fn parse_rr_type(token: &str) -> Option<u16> {
    HickoryRecordType::from_str(token)
        .ok()
        .map(u16::from)
        .or_else(|| {
            let upper = token.to_ascii_uppercase();
            upper.strip_prefix("TYPE")?.parse().ok()
        })
}

fn is_class_token(token: &str) -> bool {
    matches!(token.to_ascii_uppercase().as_str(), "IN" | "CH" | "HS")
}

fn parse_text_rr_parts(raw: &str, default_ttl: u32) -> Option<(u16, u32, Vec<u8>)> {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let type_index = tokens
        .iter()
        .position(|token| parse_rr_type(token).is_some())?;
    let rtype = parse_rr_type(tokens[type_index])?;

    let ttl = tokens[..type_index]
        .iter()
        .rev()
        .filter(|token| !is_class_token(token))
        .find_map(|token| token.parse::<u32>().ok())
        .unwrap_or(default_ttl);

    let data = &tokens[type_index + 1..];
    let rdata = match rtype {
        1 => data
            .first()
            .and_then(|value| value.parse::<std::net::Ipv4Addr>().ok())
            .map(|ip| ip.octets().to_vec())?,
        28 => data
            .first()
            .and_then(|value| value.parse::<std::net::Ipv6Addr>().ok())
            .map(|ip| ip.octets().to_vec())?,
        2 | 5 | 12 => pack_dns_name(data.first().copied()?)?,
        16 => {
            let text = data.join(" ").trim_matches('"').to_string();
            if text.len() > 255 {
                return None;
            }
            let mut out = Vec::with_capacity(text.len() + 1);
            out.push(text.len() as u8);
            out.extend_from_slice(text.as_bytes());
            out
        }
        15 => {
            let preference = data.first()?.parse::<u16>().ok()?;
            let exchange = pack_dns_name(data.get(1).copied()?)?;
            let mut out = Vec::with_capacity(2 + exchange.len());
            out.extend_from_slice(&preference.to_be_bytes());
            out.extend_from_slice(&exchange);
            out
        }
        33 => {
            let priority = data.first()?.parse::<u16>().ok()?;
            let weight = data.get(1)?.parse::<u16>().ok()?;
            let port = data.get(2)?.parse::<u16>().ok()?;
            let target = pack_dns_name(data.get(3).copied()?)?;
            let mut out = Vec::with_capacity(6 + target.len());
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&target);
            out
        }
        _ => return None,
    };

    Some((rtype, ttl, rdata))
}

fn decode_base64_rr(raw: &str, qname: &str) -> Option<Vec<u8>> {
    let encoded = raw
        .strip_prefix("base64:")
        .or_else(|| raw.strip_prefix("b64:"))?
        .trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    crate::dns::message::rewrite_rr_name_uncompressed(&decoded, qname)
}

fn predefined_records(
    records: Option<&Vec<String>>,
    qname: &str,
    default_ttl: u32,
    fallback_qtype: Option<u16>,
) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(records) = records else {
        return out;
    };

    for raw in records {
        if let Some(rr) = decode_base64_rr(raw, qname) {
            out.push(rr);
            continue;
        }

        if let Ok(ip) = raw.parse::<IpAddr>() {
            match (fallback_qtype, ip) {
                (Some(1), IpAddr::V4(v4)) => {
                    if let Some(rr) = crate::dns::message::pack_rr_uncompressed(
                        qname,
                        1,
                        1,
                        default_ttl,
                        &v4.octets(),
                    ) {
                        out.push(rr);
                    }
                }
                (Some(28), IpAddr::V6(v6)) => {
                    if let Some(rr) = crate::dns::message::pack_rr_uncompressed(
                        qname,
                        28,
                        1,
                        default_ttl,
                        &v6.octets(),
                    ) {
                        out.push(rr);
                    }
                }
                _ => {}
            }
            continue;
        }

        if let Some((rtype, ttl, rdata)) = parse_text_rr_parts(raw, default_ttl) {
            if let Some(rr) =
                crate::dns::message::pack_rr_uncompressed(qname, rtype, 1, ttl, &rdata)
            {
                out.push(rr);
            }
        }
    }

    out
}

fn predefined_ips(raw: &str, record_type: RecordType) -> Vec<IpAddr> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return match (record_type, ip) {
            (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_)) => vec![ip],
            _ => Vec::new(),
        };
    }

    let Some((rtype, _ttl, rdata)) = parse_text_rr_parts(raw, 10) else {
        return Vec::new();
    };
    match (record_type, rtype, rdata.as_slice()) {
        (RecordType::A, 1, [a, b, c, d]) => {
            vec![IpAddr::V4(std::net::Ipv4Addr::new(*a, *b, *c, *d))]
        }
        (RecordType::AAAA, 28, data) if data.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(data);
            vec![IpAddr::V6(std::net::Ipv6Addr::from(octets))]
        }
        _ => Vec::new(),
    }
}

fn build_predefined_wire_response(
    query: &[u8],
    qname: &str,
    qtype: u16,
    decision: &RoutingDecision,
) -> Option<Vec<u8>> {
    let ttl = decision.rewrite_ttl.unwrap_or(10);
    let mut answers = Vec::new();

    if let Some(ips) = &decision.rewrite_ip {
        for ip in ips {
            match (qtype, ip) {
                (1, IpAddr::V4(v4)) => answers.push(crate::dns::message::pack_rr_uncompressed(
                    qname,
                    1,
                    1,
                    ttl,
                    &v4.octets(),
                )?),
                (28, IpAddr::V6(v6)) => answers.push(crate::dns::message::pack_rr_uncompressed(
                    qname,
                    28,
                    1,
                    ttl,
                    &v6.octets(),
                )?),
                _ => {}
            }
        }
    }

    answers.extend(predefined_records(
        decision.answer.as_ref(),
        qname,
        ttl,
        Some(qtype),
    ));
    let authorities = predefined_records(decision.ns.as_ref(), qname, ttl, None);
    let additionals = predefined_records(decision.extra.as_ref(), qname, ttl, None);

    crate::dns::message::build_dns_response_with_records(
        query,
        &answers,
        &authorities,
        &additionals,
        rcode_to_wire(decision.rcode.as_deref()),
    )
}

/// DNS rule action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleAction {
    Route,
    Reject,
    HijackDns,
    /// Modify query options (strategy, disable_cache, etc.) then continue matching
    RouteOptions,
    /// Return predefined response (rcode + answer records)
    Predefined,
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
    /// Disable cache for this rule (route-options)
    pub disable_cache: Option<bool>,
    /// Rewrite TTL for this rule (route-options)
    pub rewrite_ttl: Option<u32>,
    /// Client subnet override (route-options)
    pub client_subnet: Option<String>,
    /// Strategy override (route-options or route action option)
    pub strategy: Option<String>,
}

/// DNS Rule Engine with Rule-Set routing
pub struct DnsRuleEngine {
    /// Routing rules (sorted by priority)
    rules: Vec<CompiledRule>,
    /// Upstream servers by tag
    upstreams: HashMap<String, Arc<dyn DnsUpstream>>,
    /// Optional deterministic lifecycle order for upstream tags.
    lifecycle_order: Vec<String>,
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
    /// Reverse mapping cache: IP → domain (L2.10.13)
    reverse_mapping: parking_lot::Mutex<lru::LruCache<IpAddr, String>>,
    /// Whether successful real answers should populate reverse mapping.
    reverse_mapping_enabled: bool,
    /// Tags of FakeIP upstreams (L2.10.12)
    fakeip_tags: std::collections::HashSet<String>,
    /// Answer cache used by rule-engine A/AAAA queries.
    answer_cache: Option<Arc<DnsCache>>,
    /// Include upstream tag in answer-cache keys.
    independent_cache: bool,
    /// Global DNS client subnet fallback for raw exchange.
    global_client_subnet: Option<String>,
    /// CacheFileService for RDRC response rejection persistence.
    cache_file: Option<Arc<crate::services::cache_file::CacheFileService>>,
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
                has_destination_ip_match: rule_set_has_destination_ip_match(&rule.rule_set),
                matcher: RuleMatcher::new(rule.rule_set.clone()),
                rule,
            })
            .collect();

        // Create routing cache (10k entries)
        let cache = Arc::new(parking_lot::Mutex::new(lru::LruCache::new(lru_capacity(
            10000,
        ))));

        Self {
            rules,
            upstreams,
            lifecycle_order: Vec::new(),
            default_upstream_tag,
            cache,
            strategy,
            registry,
            geoip,
            geosite,
            reverse_mapping: parking_lot::Mutex::new(lru::LruCache::new(lru_capacity(1024))),
            reverse_mapping_enabled: false,
            fakeip_tags: std::collections::HashSet::new(),
            answer_cache: None,
            independent_cache: false,
            global_client_subnet: None,
            cache_file: None,
        }
    }

    /// Set deterministic upstream lifecycle order.
    ///
    /// Callers that own dependency ordering, such as the DNS server manager, should pass
    /// dependency-first tags here. Close runs in the reverse order.
    pub fn with_lifecycle_order(mut self, lifecycle_order: Vec<String>) -> Self {
        self.lifecycle_order = lifecycle_order;
        self
    }

    /// Wire the rule-engine answer cache for A/AAAA queries.
    pub fn with_answer_cache(
        mut self,
        answer_cache: Option<Arc<DnsCache>>,
        independent_cache: bool,
    ) -> Self {
        self.answer_cache = answer_cache;
        self.independent_cache = independent_cache;
        self
    }

    /// Enable or disable reverse mapping writes.
    pub fn with_reverse_mapping_enabled(mut self, enabled: bool) -> Self {
        self.reverse_mapping_enabled = enabled;
        self
    }

    /// Set global DNS ECS fallback used when no rule/server override is present.
    pub fn with_global_client_subnet(mut self, client_subnet: Option<String>) -> Self {
        self.global_client_subnet = client_subnet;
        self
    }

    /// Wire CacheFileService for RDRC rejection checks/saves.
    pub fn with_cache_file(
        mut self,
        cache_file: Option<Arc<crate::services::cache_file::CacheFileService>>,
    ) -> Self {
        self.cache_file = cache_file;
        self
    }

    fn lifecycle_tags(&self) -> Vec<String> {
        if self.lifecycle_order.is_empty() {
            let mut tags: Vec<String> = self.upstreams.keys().cloned().collect();
            tags.sort();
            tags
        } else {
            let mut tags = self.lifecycle_order.clone();
            let mut seen: std::collections::HashSet<String> = tags.iter().cloned().collect();
            let mut remaining: Vec<String> = self
                .upstreams
                .keys()
                .filter(|tag| !seen.contains(*tag))
                .cloned()
                .collect();
            remaining.sort();
            for tag in remaining {
                seen.insert(tag.clone());
                tags.push(tag);
            }
            tags
        }
    }

    /// Route a DNS query to the appropriate upstream
    pub async fn resolve(&self, domain: &str, record_type: RecordType) -> Result<DnsAnswer> {
        self.resolve_with_context(&DnsQueryContext::default(), domain, record_type)
            .await
    }

    /// Mark an upstream tag as FakeIP (L2.10.12).
    /// Lookup operations will skip FakeIP upstreams.
    pub fn mark_fakeip_upstream(&mut self, tag: &str) {
        self.fakeip_tags.insert(tag.to_string());
    }

    /// Check if an upstream tag is a FakeIP upstream
    pub fn is_fakeip_upstream(&self, tag: &str) -> bool {
        self.fakeip_tags.contains(tag)
    }

    fn build_match_context(
        &self,
        ctx: &DnsQueryContext,
        domain: &str,
        query_type: &str,
    ) -> MatchContext {
        let source_ip = ctx.client.map(|a| a.ip());
        let source_geoip_code =
            source_ip.and_then(|ip| self.geoip.as_ref().and_then(|db| db.lookup_country(ip)));

        MatchContext {
            domain: Some(domain.to_string()),
            destination_ip: None,
            destination_port: 0,
            network: ctx.transport.clone().or(Some("udp".to_string())),
            auth_user: ctx.auth_user.clone(),
            protocol: ctx.protocol.clone(),
            process_name: ctx.process_name.clone(),
            process_path: ctx.process_path.clone(),
            package_name: ctx.package_name.clone(),
            user: ctx.user.clone(),
            user_id: ctx.user_id,
            outbound_tag: ctx.outbound_tag.clone(),
            source_ip,
            source_port: ctx.client.map(|a| a.port()),
            query_type: Some(query_type.to_string()),
            clash_mode: None,
            geosite_codes: if let Some(db) = &self.geosite {
                db.lookup_categories(domain)
            } else {
                Vec::new()
            },
            geoip_code: None,
            source_geoip_code,
            inbound_tag: ctx.inbound.clone(),
            network_type: ctx.network_type.clone(),
            network_is_expensive: ctx.network_is_expensive,
            network_is_constrained: ctx.network_is_constrained,
            wifi_ssid: ctx.wifi_ssid.clone(),
            wifi_bssid: ctx.wifi_bssid.clone(),
            ignore_destination_ip_cidr: true,
        }
    }

    /// Route a DNS query with context
    pub async fn resolve_with_context(
        &self,
        ctx: &DnsQueryContext,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnsAnswer> {
        let qt = format!("{:?}", record_type);

        // Destination IP CIDR/GeoIP cannot be evaluated before querying.
        // Match with those conditions ignored, then validate answer IPs below.
        let match_ctx = self.build_match_context(ctx, domain, &qt);

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
                DnsRuleAction::HijackDns | DnsRuleAction::Predefined => {
                    let mut answer_ips = Vec::new();
                    // Merge rewrite_ip and answer fields
                    if let Some(ips) = &decision.rewrite_ip {
                        answer_ips.extend(ips.clone());
                    }
                    if let Some(answers) = &decision.answer {
                        for ans in answers {
                            answer_ips.extend(predefined_ips(ans, record_type));
                        }
                    }

                    let rcode = rcode_to_answer(decision.rcode.as_deref());

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
                            std::time::Duration::from_secs(
                                decision.rewrite_ttl.unwrap_or(10) as u64
                            ),
                            Source::System,
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
                        Source::System,
                        Rcode::Refused,
                    ));
                }
                DnsRuleAction::Route => {
                    // fallthrough to upstream query
                }
                DnsRuleAction::RouteOptions => {
                    // Already handled in route_domain() - shouldn't reach here
                    // fallthrough to upstream query
                }
            }
        }

        let tag = decision
            .upstream_tag
            .as_deref()
            .unwrap_or(&self.default_upstream_tag);

        let effective_strategy = decision
            .strategy
            .as_deref()
            .and_then(|s| s.parse::<super::DnsStrategy>().ok())
            .unwrap_or(self.strategy);

        if record_type == RecordType::A && effective_strategy == super::DnsStrategy::Ipv6Only {
            return Ok(DnsAnswer::new(
                Vec::new(),
                std::time::Duration::from_secs(0),
                Source::System,
                Rcode::NoError,
            ));
        }
        if record_type == RecordType::AAAA && effective_strategy == super::DnsStrategy::Ipv4Only {
            return Ok(DnsAnswer::new(
                Vec::new(),
                std::time::Duration::from_secs(0),
                Source::System,
                Rcode::NoError,
            ));
        }

        let cache_disabled = decision.disable_cache || self.fakeip_tags.contains(tag);
        let cache_key = self.answer_cache_key(domain, record_type, tag);
        if !cache_disabled {
            if let (Some(cache), Some(key)) = (&self.answer_cache, &cache_key) {
                if let Some(answer) = cache.get(key) {
                    return Ok(answer);
                }
            }
        }

        if decision.has_destination_ip_match {
            if let Some(cache_file) = &self.cache_file {
                if cache_file.check_rdrc_rejection(tag, domain, record_type.as_u16()) {
                    return Ok(DnsAnswer::new(
                        Vec::new(),
                        std::time::Duration::from_secs(0),
                        Source::System,
                        Rcode::Refused,
                    ));
                }
            }
        }

        // Get upstream server
        let upstream = self.upstreams.get(tag).ok_or_else(|| {
            anyhow::anyhow!("Upstream '{}' not found for domain '{}'", tag, domain)
        })?;

        // Query upstream
        tracing::debug!(
            "DNS routing: domain={}, upstream={}, type={:?}",
            domain,
            tag,
            record_type
        );

        let mut answer = upstream.query(domain, record_type).await?;

        if decision.has_destination_ip_match
            && !self.answer_ips_satisfy_rule(&decision, &match_ctx, &answer.ips)
        {
            if let Some(cache_file) = &self.cache_file {
                cache_file.save_rdrc_rejection(tag, domain, record_type.as_u16());
            }
            return Ok(DnsAnswer::new(
                Vec::new(),
                std::time::Duration::from_secs(0),
                Source::System,
                Rcode::Refused,
            ));
        }

        if let Some(limit) = decision.address_limit {
            if answer.ips.len() > limit as usize {
                answer.ips.truncate(limit as usize);
            }
        }

        if let Some(ttl) = decision.rewrite_ttl {
            answer.ttl = std::time::Duration::from_secs(ttl as u64);
        }

        // Store reverse mapping only for successful real answers.
        if self.reverse_mapping_enabled
            && !self.fakeip_tags.contains(tag)
            && answer.rcode == Rcode::NoError
            && !answer.ips.is_empty()
        {
            let mut rmap = self.reverse_mapping.lock();
            for ip in &answer.ips {
                rmap.put(*ip, domain.to_string());
            }
        }

        if !cache_disabled {
            if let (Some(cache), Some(key)) = (&self.answer_cache, cache_key) {
                cache.put(key, answer.clone());
            }
        }

        Ok(answer)
    }

    fn answer_cache_key(
        &self,
        domain: &str,
        record_type: RecordType,
        upstream_tag: &str,
    ) -> Option<CacheKey> {
        let qtype = match record_type {
            RecordType::A => CacheQType::A,
            RecordType::AAAA => CacheQType::AAAA,
            _ => return None,
        };

        Some(CacheKey {
            name: domain.to_ascii_lowercase(),
            qtype,
            transport_tag: self.independent_cache.then(|| upstream_tag.to_string()),
        })
    }

    fn answer_ips_satisfy_rule(
        &self,
        decision: &RoutingDecision,
        base_ctx: &MatchContext,
        ips: &[IpAddr],
    ) -> bool {
        let Some(index) = decision.matched_rule_index else {
            return true;
        };
        let Some(compiled) = self.rules.get(index) else {
            return true;
        };

        if ips.is_empty() {
            let mut ctx = base_ctx.clone();
            ctx.ignore_destination_ip_cidr = false;
            return compiled.matcher.matches(&ctx);
        }

        ips.iter().any(|ip| {
            let mut ctx = base_ctx.clone();
            ctx.destination_ip = Some(*ip);
            ctx.ignore_destination_ip_cidr = false;
            ctx.geoip_code = self.geoip.as_ref().and_then(|db| db.lookup_country(*ip));
            compiled.matcher.matches(&ctx)
        })
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
        let cache_key = RoutingCacheKey::from_match_context(ctx, domain, query_type);

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

        // Track accumulated route-options (L2.10.14)
        let mut accumulated_client_subnet: Option<String> = None;
        let mut accumulated_strategy: Option<String> = None;
        let mut accumulated_disable_cache = false;
        let mut accumulated_rewrite_ttl: Option<u32> = None;

        for (index, compiled) in self.rules.iter().enumerate() {
            if compiled.matcher.matches(ctx) {
                // L2.10.14: RouteOptions modifies query options and continues matching
                if compiled.rule.action == DnsRuleAction::RouteOptions {
                    if let Some(ref cs) = compiled.rule.client_subnet {
                        accumulated_client_subnet = Some(cs.clone());
                    }
                    if let Some(ref strategy) = compiled.rule.strategy {
                        accumulated_strategy = Some(strategy.clone());
                    }
                    if let Some(disable_cache) = compiled.rule.disable_cache {
                        accumulated_disable_cache = disable_cache;
                    }
                    if let Some(rewrite_ttl) = compiled.rule.rewrite_ttl {
                        accumulated_rewrite_ttl = Some(rewrite_ttl);
                    }
                    tracing::debug!(
                        "DNS route-options matched: domain={}, type={}, continuing",
                        domain,
                        query_type
                    );
                    continue; // Continue matching subsequent rules
                }

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
                    client_subnet: accumulated_client_subnet
                        .clone()
                        .or_else(|| compiled.rule.client_subnet.clone()),
                    strategy: compiled
                        .rule
                        .strategy
                        .clone()
                        .or_else(|| accumulated_strategy.clone()),
                    disable_cache: accumulated_disable_cache
                        || compiled.rule.disable_cache.unwrap_or(false),
                    rewrite_ttl: compiled.rule.rewrite_ttl.or(accumulated_rewrite_ttl),
                    matched_rule_index: Some(index),
                    has_destination_ip_match: compiled.has_destination_ip_match,
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
            client_subnet: accumulated_client_subnet,
            strategy: accumulated_strategy,
            disable_cache: accumulated_disable_cache,
            rewrite_ttl: accumulated_rewrite_ttl,
            matched_rule_index: None,
            has_destination_ip_match: false,
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
        for tag in self.lifecycle_tags() {
            let up = self
                .upstreams
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("Lifecycle upstream '{}' not found", tag))?;
            up.start(stage)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to start upstream {}: {}", tag, e))?;
        }
        self.registry.start_all(stage).await?;
        Ok(())
    }

    /// Close the rule engine
    pub async fn close(&self) -> Result<()> {
        for tag in self.lifecycle_tags().into_iter().rev() {
            let up = self
                .upstreams
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("Lifecycle upstream '{}' not found", tag))?;
            up.close()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to close upstream {}: {}", tag, e))?;
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

        // Parallel execution of A and AAAA queries using tokio::join!
        match (query_ipv4, query_ipv6) {
            (true, true) => {
                // Both queries in parallel for improved latency
                let (a_result, aaaa_result) = tokio::join!(
                    self.resolve_with_context(ctx, domain, RecordType::A),
                    self.resolve_with_context(ctx, domain, RecordType::AAAA)
                );

                // Process A record result
                match a_result {
                    Ok(mut ans) => {
                        all_ips.append(&mut ans.ips);
                        min_ttl = Some(ans.ttl);
                    }
                    Err(e) => {
                        tracing::trace!("Dual-stack A query failed: {}", e);
                    }
                }

                // Process AAAA record result
                match aaaa_result {
                    Ok(mut ans) => {
                        all_ips.append(&mut ans.ips);
                        min_ttl = Some(min_ttl.map_or(ans.ttl, |t| t.min(ans.ttl)));
                    }
                    Err(e) => {
                        tracing::trace!("Dual-stack AAAA query failed: {}", e);
                    }
                }
            }
            (true, false) => {
                // IPv4 only
                match self.resolve_with_context(ctx, domain, RecordType::A).await {
                    Ok(mut ans) => {
                        all_ips.append(&mut ans.ips);
                        min_ttl = Some(ans.ttl);
                    }
                    Err(e) => {
                        tracing::trace!("IPv4-only A query failed: {}", e);
                    }
                }
            }
            (false, true) => {
                // IPv6 only
                match self
                    .resolve_with_context(ctx, domain, RecordType::AAAA)
                    .await
                {
                    Ok(mut ans) => {
                        all_ips.append(&mut ans.ips);
                        min_ttl = Some(ans.ttl);
                    }
                    Err(e) => {
                        tracing::trace!("IPv6-only AAAA query failed: {}", e);
                    }
                }
            }
            (false, false) => {
                // No queries (shouldn't happen in practice)
                tracing::warn!("DNS dual-stack called with no query types enabled");
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
    async fn exchange(&self, ctx: &DnsQueryContext, message: &[u8]) -> Result<Vec<u8>> {
        use crate::dns::cache::Rcode;
        use crate::dns::message::{
            build_dns_response, inject_edns0_client_subnet, parse_question_key,
        };

        // 1. Parse the question from the wire-format query
        let qk = parse_question_key(message)
            .ok_or_else(|| anyhow::anyhow!("DnsRuleEngine::exchange: failed to parse question"))?;

        fn qtype_to_string(qtype: u16) -> String {
            match qtype {
                1 => "A".to_string(),
                2 => "NS".to_string(),
                5 => "CNAME".to_string(),
                12 => "PTR".to_string(),
                15 => "MX".to_string(),
                16 => "TXT".to_string(),
                28 => "AAAA".to_string(),
                33 => "SRV".to_string(),
                41 => "OPT".to_string(),
                _ => format!("TYPE{qtype}"),
            }
        }

        let qt = qtype_to_string(qk.qtype);
        let match_ctx = self.build_match_context(ctx, &qk.name, &qt);
        let decision = self.route_domain(&match_ctx, &qk.name, &qt);

        if let Some(action) = &decision.action {
            match action {
                DnsRuleAction::Reject => {
                    let resp = build_dns_response(message, &[], 0, 5).ok_or_else(|| {
                        anyhow::anyhow!("DnsRuleEngine::exchange: failed to build REFUSED response")
                    })?;
                    return Ok(resp);
                }
                DnsRuleAction::HijackDns | DnsRuleAction::Predefined => {
                    let resp =
                        build_predefined_wire_response(message, &qk.name, qk.qtype, &decision)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "DnsRuleEngine::exchange: failed to build predefined response"
                                )
                            })?;
                    return Ok(resp);
                }
                DnsRuleAction::Route | DnsRuleAction::RouteOptions => {}
            }
        }

        // 2. A/AAAA: preserve existing "answer builder" path with rule actions.
        if qk.qtype == 1 || qk.qtype == 28 {
            let record_type = if qk.qtype == 1 {
                RecordType::A
            } else {
                RecordType::AAAA
            };

            // Resolve via the rule engine
            let answer = self
                .resolve_with_context(ctx, &qk.name, record_type)
                .await?;

            // Map Rcode → wire rcode byte
            let rcode_byte: u8 = match &answer.rcode {
                Rcode::NoError => 0,
                Rcode::ServFail => 2,
                Rcode::NxDomain => 3,
                Rcode::Refused => 5,
                _ => 2, // default to SERVFAIL
            };

            // Build the wire-format response (preserves the original transaction ID)
            let ttl_secs = answer.ttl.as_secs() as u32;
            let resp = build_dns_response(message, &answer.ips, ttl_secs, rcode_byte).ok_or_else(
                || anyhow::anyhow!("DnsRuleEngine::exchange: failed to build DNS response"),
            )?;

            return Ok(resp);
        }

        // 3. Non-A/AAAA: do a raw passthrough based on routing decision.
        let tag = decision
            .upstream_tag
            .as_deref()
            .unwrap_or(&self.default_upstream_tag);
        let upstream = self.upstreams.get(tag).ok_or_else(|| {
            anyhow::anyhow!("Upstream '{}' not found for domain '{}'", tag, qk.name)
        })?;

        let mut packet = message.to_vec();
        let ecs = decision
            .client_subnet
            .as_ref()
            .or(self.global_client_subnet.as_ref());
        if let Some(subnet) = ecs {
            let _ = inject_edns0_client_subnet(&mut packet, subnet);
        }

        upstream.exchange(&packet).await
    }

    async fn lookup(&self, ctx: &DnsQueryContext, domain: &str) -> Result<Vec<std::net::IpAddr>> {
        // L2.10.12: lookup() skips FakeIP upstreams (Go: allowFakeIP = false)
        // Use resolve_dual_stack which goes through resolve_with_context → route_domain
        // If routed to FakeIP, fall back to default non-FakeIP upstream
        let ans = self.resolve_dual_stack_with_context(ctx, domain).await?;
        Ok(ans.ips)
    }

    async fn lookup_default(&self, domain: &str) -> Result<Vec<std::net::IpAddr>> {
        // L2.10.12: Skip FakeIP upstreams in default lookup
        let tag = &self.default_upstream_tag;

        // If default is FakeIP, find first non-FakeIP upstream
        let effective_tag = if self.fakeip_tags.contains(tag) {
            self.upstreams
                .keys()
                .find(|t| !self.fakeip_tags.contains(t.as_str()))
                .cloned()
                .unwrap_or_else(|| tag.clone())
        } else {
            tag.clone()
        };

        let upstream = self
            .upstreams
            .get(&effective_tag)
            .ok_or_else(|| anyhow::anyhow!("Default upstream '{}' not found", effective_tag))?;

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

    fn lookup_reverse_mapping(&self, ip: &std::net::IpAddr) -> Option<String> {
        self.reverse_mapping.lock().get(ip).cloned()
    }

    fn name(&self) -> &str {
        "dns_rule_engine"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::dns_router::DnsQueryContext;
    use crate::dns::dns_router::DnsRouter as _;
    use crate::router::ruleset::{DefaultRule, Rule, RuleSetFormat};
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    struct CountingUpstream {
        tag: String,
        ips: Vec<IpAddr>,
        ttl: std::time::Duration,
        queries: Arc<AtomicUsize>,
    }

    impl CountingUpstream {
        fn new(tag: &str, ips: Vec<IpAddr>) -> (Arc<Self>, Arc<AtomicUsize>) {
            let queries = Arc::new(AtomicUsize::new(0));
            (
                Arc::new(Self {
                    tag: tag.to_string(),
                    ips,
                    ttl: std::time::Duration::from_secs(60),
                    queries: queries.clone(),
                }),
                queries,
            )
        }
    }

    #[async_trait::async_trait]
    impl DnsUpstream for CountingUpstream {
        async fn query(&self, _domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            Ok(DnsAnswer::new(
                self.ips.clone(),
                self.ttl,
                Source::System,
                Rcode::NoError,
            ))
        }

        fn name(&self) -> &str {
            &self.tag
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    fn test_ruleset(rule: Rule) -> Arc<RuleSet> {
        Arc::new(RuleSet {
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
        })
    }

    fn route_rule(rule: Rule, upstream_tag: &str, priority: u32) -> DnsRoutingRule {
        DnsRoutingRule {
            rule_set: test_ruleset(rule),
            upstream_tag: Some(upstream_tag.to_string()),
            action: DnsRuleAction::Route,
            priority,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
            disable_cache: None,
            rewrite_ttl: None,
            client_subnet: None,
            strategy: None,
        }
    }

    /// Mock upstream that supports raw exchange.
    struct MockExchangeUpstream {
        tag: String,
        resp: Vec<u8>,
        seen: parking_lot::Mutex<Option<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl DnsUpstream for MockExchangeUpstream {
        async fn query(&self, _domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
            Err(anyhow::anyhow!("not implemented"))
        }

        async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
            *self.seen.lock() = Some(packet.to_vec());
            Ok(self.resp.clone())
        }

        fn name(&self) -> &str {
            &self.tag
        }

        async fn health_check(&self) -> bool {
            true
        }
    }

    struct LifecycleTraceUpstream {
        tag: String,
        events: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl DnsUpstream for LifecycleTraceUpstream {
        async fn query(&self, _domain: &str, _record_type: RecordType) -> Result<DnsAnswer> {
            Err(anyhow::anyhow!("not implemented"))
        }

        fn name(&self) -> &str {
            &self.tag
        }

        async fn health_check(&self) -> bool {
            true
        }

        async fn start(&self, _stage: crate::dns::transport::DnsStartStage) -> Result<()> {
            self.events.lock().push(format!("start:{}", self.tag));
            Ok(())
        }

        async fn close(&self) -> Result<()> {
            self.events.lock().push(format!("close:{}", self.tag));
            Ok(())
        }
    }

    #[tokio::test]
    async fn p1313_02_rule_engine_lifecycle_uses_order_and_reverse_close() {
        let events = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
        let bootstrap = Arc::new(LifecycleTraceUpstream {
            tag: "bootstrap".to_string(),
            events: events.clone(),
        }) as Arc<dyn DnsUpstream>;
        let main = Arc::new(LifecycleTraceUpstream {
            tag: "main".to_string(),
            events: events.clone(),
        }) as Arc<dyn DnsUpstream>;

        let mut upstreams = HashMap::new();
        upstreams.insert("main".to_string(), main);
        upstreams.insert("bootstrap".to_string(), bootstrap);

        let engine = DnsRuleEngine::new(
            vec![],
            upstreams,
            "main".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        )
        .with_lifecycle_order(vec!["bootstrap".to_string(), "main".to_string()]);

        engine
            .start(crate::dns::transport::DnsStartStage::Start)
            .await
            .unwrap();
        engine.close().await.unwrap();

        assert_eq!(
            events.lock().as_slice(),
            &[
                "start:bootstrap".to_string(),
                "start:main".to_string(),
                "close:main".to_string(),
                "close:bootstrap".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_dns_rule_engine_exchange_passthrough_non_a_aaaa() {
        let resp = vec![0xde, 0xad, 0xbe, 0xef];
        let up = Arc::new(MockExchangeUpstream {
            tag: "mock".to_string(),
            resp: resp.clone(),
            seen: parking_lot::Mutex::new(None),
        }) as Arc<dyn DnsUpstream>;

        let mut upstreams = HashMap::new();
        upstreams.insert("mock".to_string(), up.clone());

        let engine = DnsRuleEngine::new(
            vec![],
            upstreams,
            "mock".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );

        let req = crate::dns::udp::build_query("example.com", 12).expect("ptr query");
        let ctx = DnsQueryContext::new()
            .with_inbound("resolved")
            .with_transport("udp");
        let got = engine.exchange(&ctx, &req).await.expect("exchange");
        assert_eq!(got, resp);
    }

    #[tokio::test]
    async fn test_dns_rule_engine_exchange_reject_non_a_aaaa_returns_refused() {
        // Reject *.example.com
        let rule = Rule::Default(DefaultRule {
            domain_suffix: vec!["example.com".to_string()],
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
            upstream_tag: None,
            action: DnsRuleAction::Reject,
            priority: 10,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
            disable_cache: None,
            rewrite_ttl: None,
            client_subnet: None,
            strategy: None,
        };

        let mut upstreams = HashMap::new();
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

        let req = crate::dns::udp::build_query("www.example.com", 12).expect("ptr query");
        let ctx = DnsQueryContext::new();
        let resp = engine.exchange(&ctx, &req).await.expect("exchange");
        assert!(resp.len() >= 4);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        let rcode = flags & 0x000F;
        assert_eq!(rcode, 5); // REFUSED
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
            disable_cache: None,
            rewrite_ttl: None,
            client_subnet: None,
            strategy: None,
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
                    disable_cache: None,
                    rewrite_ttl: None,
                    client_subnet: None,
                    strategy: None,
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
                    disable_cache: None,
                    rewrite_ttl: None,
                    client_subnet: None,
                    strategy: None,
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
                disable_cache: None,
                rewrite_ttl: None,
                client_subnet: None,
                strategy: None,
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
        use crate::router::ruleset::{DefaultRule, Rule};
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
                disable_cache: None,
                rewrite_ttl: None,
                client_subnet: None,
                strategy: None,
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
        let result = engine
            .resolve_with_context(&ctx, "example.com", RecordType::A)
            .await;
        // Mock Upstream always returns OK. We can't easily inspect which upstream was chosen
        // without introspection or mocking details, but we can rely on coverage or detailed logs.
        // For this unit test, we at least verify compilation and execution.
        assert!(result.is_ok());

        // For verification, we can check the stats if we had exposted metrics or check cache.
    }

    #[tokio::test]
    async fn p1313_03_route_options_accumulate_and_disable_answer_cache() {
        let (upstream, queries) = CountingUpstream::new("dns", vec![IpAddr::from([1, 1, 1, 1])]);

        let route_options = DnsRoutingRule {
            rule_set: test_ruleset(Rule::Default(DefaultRule {
                inbound: vec!["tun".to_string()],
                ..Default::default()
            })),
            upstream_tag: None,
            action: DnsRuleAction::RouteOptions,
            priority: 1,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
            disable_cache: Some(true),
            rewrite_ttl: Some(7),
            client_subnet: None,
            strategy: Some("ipv4_only".to_string()),
        };
        let route = route_rule(
            Rule::Default(DefaultRule {
                domain_suffix: vec!["example.com".to_string()],
                ..Default::default()
            }),
            "dns",
            10,
        );

        let mut upstreams = HashMap::new();
        upstreams.insert("dns".to_string(), upstream as Arc<dyn DnsUpstream>);
        let engine = DnsRuleEngine::new(
            vec![route_options, route],
            upstreams,
            "dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        )
        .with_answer_cache(Some(Arc::new(DnsCache::new(16))), false);

        let ctx = DnsQueryContext::new().with_inbound("tun");
        let first = engine
            .resolve_with_context(&ctx, "www.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(first.ttl, std::time::Duration::from_secs(7));
        let _second = engine
            .resolve_with_context(&ctx, "www.example.com", RecordType::A)
            .await
            .unwrap();
        assert_eq!(
            queries.load(Ordering::SeqCst),
            2,
            "route-options disable_cache must bypass answer cache"
        );

        let aaaa = engine
            .resolve_with_context(&ctx, "www.example.com", RecordType::AAAA)
            .await
            .unwrap();
        assert!(aaaa.ips.is_empty());
        assert_eq!(
            queries.load(Ordering::SeqCst),
            2,
            "route-options strategy=ipv4_only must suppress AAAA upstream query"
        );
    }

    #[tokio::test]
    async fn p1313_03_routing_cache_key_includes_context() {
        let (tun_upstream, tun_queries) =
            CountingUpstream::new("tun_dns", vec![IpAddr::from([10, 0, 0, 1])]);
        let (default_upstream, default_queries) =
            CountingUpstream::new("default_dns", vec![IpAddr::from([10, 0, 0, 2])]);

        let mut upstreams = HashMap::new();
        upstreams.insert("tun_dns".to_string(), tun_upstream as Arc<dyn DnsUpstream>);
        upstreams.insert(
            "default_dns".to_string(),
            default_upstream as Arc<dyn DnsUpstream>,
        );
        let engine = DnsRuleEngine::new(
            vec![route_rule(
                Rule::Default(DefaultRule {
                    inbound: vec!["tun".to_string()],
                    ..Default::default()
                }),
                "tun_dns",
                10,
            )],
            upstreams,
            "default_dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );

        let tun_ctx = DnsQueryContext::new().with_inbound("tun");
        let direct_ctx = DnsQueryContext::new().with_inbound("direct");
        let tun_answer = engine
            .resolve_with_context(&tun_ctx, "same.example", RecordType::A)
            .await
            .unwrap();
        let direct_answer = engine
            .resolve_with_context(&direct_ctx, "same.example", RecordType::A)
            .await
            .unwrap();

        assert_eq!(tun_answer.ips, vec![IpAddr::from([10, 0, 0, 1])]);
        assert_eq!(direct_answer.ips, vec![IpAddr::from([10, 0, 0, 2])]);
        assert_eq!(tun_queries.load(Ordering::SeqCst), 1);
        assert_eq!(default_queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn p1313_03_rule_set_ip_cidr_match_source_uses_source_ip_pre_query() {
        let (source_upstream, source_queries) =
            CountingUpstream::new("source_dns", vec![IpAddr::from([10, 0, 0, 3])]);
        let (default_upstream, default_queries) =
            CountingUpstream::new("default_dns", vec![IpAddr::from([10, 0, 0, 4])]);

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "source_dns".to_string(),
            source_upstream as Arc<dyn DnsUpstream>,
        );
        upstreams.insert(
            "default_dns".to_string(),
            default_upstream as Arc<dyn DnsUpstream>,
        );
        let engine = DnsRuleEngine::new(
            vec![route_rule(
                Rule::Default(DefaultRule {
                    ip_cidr: vec![crate::router::ruleset::IpCidr::parse("192.0.2.0/24").unwrap()],
                    rule_set_ip_cidr_match_source: true,
                    ..Default::default()
                }),
                "source_dns",
                10,
            )],
            upstreams,
            "default_dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );

        let matching_ctx = DnsQueryContext::new().with_client("192.0.2.9:12345".parse().unwrap());
        let nonmatching_ctx =
            DnsQueryContext::new().with_client("198.51.100.9:12345".parse().unwrap());
        let matching = engine
            .resolve_with_context(&matching_ctx, "source.example", RecordType::A)
            .await
            .unwrap();
        let nonmatching = engine
            .resolve_with_context(&nonmatching_ctx, "source.example", RecordType::A)
            .await
            .unwrap();

        assert_eq!(matching.ips, vec![IpAddr::from([10, 0, 0, 3])]);
        assert_eq!(nonmatching.ips, vec![IpAddr::from([10, 0, 0, 4])]);
        assert_eq!(source_queries.load(Ordering::SeqCst), 1);
        assert_eq!(default_queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn p1313_03_answer_cache_independent_by_transport_tag_and_rewrites_ttl() {
        let (a_upstream, a_queries) =
            CountingUpstream::new("dns-a", vec![IpAddr::from([10, 0, 0, 1])]);
        let (b_upstream, b_queries) =
            CountingUpstream::new("dns-b", vec![IpAddr::from([10, 0, 0, 2])]);

        let mut rule_a = route_rule(
            Rule::Default(DefaultRule {
                inbound: vec!["a".to_string()],
                ..Default::default()
            }),
            "dns-a",
            1,
        );
        rule_a.rewrite_ttl = Some(30);
        let rule_b = route_rule(
            Rule::Default(DefaultRule {
                inbound: vec!["b".to_string()],
                ..Default::default()
            }),
            "dns-b",
            2,
        );

        let mut upstreams = HashMap::new();
        upstreams.insert("dns-a".to_string(), a_upstream as Arc<dyn DnsUpstream>);
        upstreams.insert("dns-b".to_string(), b_upstream as Arc<dyn DnsUpstream>);
        let engine = DnsRuleEngine::new(
            vec![rule_a, rule_b],
            upstreams,
            "dns-a".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        )
        .with_answer_cache(Some(Arc::new(DnsCache::new(16))), true);

        let ctx_a = DnsQueryContext::new().with_inbound("a");
        let ctx_b = DnsQueryContext::new().with_inbound("b");
        let a1 = engine
            .resolve_with_context(&ctx_a, "cache.example", RecordType::A)
            .await
            .unwrap();
        let b1 = engine
            .resolve_with_context(&ctx_b, "cache.example", RecordType::A)
            .await
            .unwrap();
        let a2 = engine
            .resolve_with_context(&ctx_a, "cache.example", RecordType::A)
            .await
            .unwrap();

        assert_eq!(a1.ips, vec![IpAddr::from([10, 0, 0, 1])]);
        assert_eq!(b1.ips, vec![IpAddr::from([10, 0, 0, 2])]);
        assert_eq!(a2.ips, a1.ips);
        assert_eq!(a1.ttl, std::time::Duration::from_secs(30));
        assert_eq!(a_queries.load(Ordering::SeqCst), 1);
        assert_eq!(b_queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn p1313_03_address_limit_rejection_uses_rdrc() {
        let (upstream, queries) =
            CountingUpstream::new("dns", vec![IpAddr::from([198, 51, 100, 1])]);
        let mut upstreams = HashMap::new();
        upstreams.insert("dns".to_string(), upstream as Arc<dyn DnsUpstream>);

        let cache_file = Arc::new(crate::services::cache_file::CacheFileService::new(
            &sb_config::ir::CacheFileIR {
                enabled: false,
                path: None,
                cache_id: None,
                store_fakeip: false,
                store_rdrc: true,
                rdrc_timeout: Some("1h".to_string()),
            },
        ));

        let engine = DnsRuleEngine::new(
            vec![route_rule(
                Rule::Default(DefaultRule {
                    domain_suffix: vec!["blocked.example".to_string()],
                    ip_cidr: vec![crate::router::ruleset::IpCidr::parse("203.0.113.0/24").unwrap()],
                    ..Default::default()
                }),
                "dns",
                10,
            )],
            upstreams,
            "dns".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        )
        .with_cache_file(Some(cache_file));

        let first = engine
            .resolve("www.blocked.example", RecordType::A)
            .await
            .unwrap();
        let second = engine
            .resolve("www.blocked.example", RecordType::A)
            .await
            .unwrap();

        assert_eq!(first.rcode, Rcode::Refused);
        assert_eq!(second.rcode, Rcode::Refused);
        assert_eq!(
            queries.load(Ordering::SeqCst),
            1,
            "second rejected response should be served from RDRC without upstream query"
        );
    }

    #[tokio::test]
    async fn p1313_03_fakeip_answers_do_not_write_reverse_mapping() {
        let fake_ip = IpAddr::from([198, 18, 0, 1]);
        let (upstream, _queries) = CountingUpstream::new("fake", vec![fake_ip]);
        let mut upstreams = HashMap::new();
        upstreams.insert("fake".to_string(), upstream as Arc<dyn DnsUpstream>);

        let mut engine = DnsRuleEngine::new(
            vec![],
            upstreams,
            "fake".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        )
        .with_reverse_mapping_enabled(true);
        engine.mark_fakeip_upstream("fake");

        let answer = engine.resolve("fake.example", RecordType::A).await.unwrap();
        assert_eq!(answer.ips, vec![fake_ip]);
        assert_eq!(engine.lookup_reverse_mapping(&fake_ip), None);
    }

    #[tokio::test]
    async fn p1313_03_exchange_applies_route_options_ecs_and_predefined_sections() {
        let req = crate::dns::udp::build_query("wire.example", 1).expect("a query");
        let raw_a =
            crate::dns::message::pack_rr_uncompressed("old.example", 1, 1, 60, &[1, 2, 3, 4])
                .unwrap();
        let raw_a = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(raw_a)
        );

        let predefined = DnsRoutingRule {
            rule_set: test_ruleset(Rule::Default(DefaultRule {
                domain_suffix: vec!["wire.example".to_string()],
                ..Default::default()
            })),
            upstream_tag: None,
            action: DnsRuleAction::Predefined,
            priority: 1,
            address_limit: None,
            rewrite_ip: None,
            rcode: Some("NOERROR".to_string()),
            answer: Some(vec![raw_a]),
            ns: Some(vec!["NS ns.example.".to_string()]),
            extra: Some(vec!["TXT \"extra\"".to_string()]),
            disable_cache: None,
            rewrite_ttl: Some(11),
            client_subnet: None,
            strategy: None,
        };
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "unused".to_string(),
            Arc::new(MockUpstream {
                tag: "unused".to_string(),
            }) as Arc<dyn DnsUpstream>,
        );
        let engine = DnsRuleEngine::new(
            vec![predefined],
            upstreams,
            "unused".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );

        let resp = engine
            .exchange(&DnsQueryContext::new(), &req)
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 1);
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 1);
        let answers = crate::dns::message::parse_answer_records(&resp).unwrap();
        assert_eq!(answers[0].name, "wire.example");
        assert_eq!(answers[0].as_ip(), Some(IpAddr::from([1, 2, 3, 4])));

        let passthrough_resp = vec![0xca, 0xfe];
        let exchange_upstream = Arc::new(MockExchangeUpstream {
            tag: "exchange".to_string(),
            resp: passthrough_resp.clone(),
            seen: parking_lot::Mutex::new(None),
        });
        let route_options = DnsRoutingRule {
            rule_set: test_ruleset(Rule::Default(DefaultRule::default())),
            upstream_tag: None,
            action: DnsRuleAction::RouteOptions,
            priority: 1,
            address_limit: None,
            rewrite_ip: None,
            rcode: None,
            answer: None,
            ns: None,
            extra: None,
            disable_cache: None,
            rewrite_ttl: None,
            client_subnet: Some("1.2.3.0/24".to_string()),
            strategy: None,
        };
        let route = route_rule(Rule::Default(DefaultRule::default()), "exchange", 2);
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "exchange".to_string(),
            exchange_upstream.clone() as Arc<dyn DnsUpstream>,
        );
        let engine = DnsRuleEngine::new(
            vec![route_options, route],
            upstreams,
            "exchange".to_string(),
            crate::dns::DnsStrategy::default(),
            Arc::new(crate::dns::transport::TransportRegistry::new()),
            None,
            None,
        );
        let txt_req = crate::dns::udp::build_query("ecs.example", 16).expect("txt query");
        let got = engine
            .exchange(&DnsQueryContext::new(), &txt_req)
            .await
            .unwrap();
        assert_eq!(got, passthrough_resp);
        let seen = exchange_upstream.seen.lock().clone().unwrap();
        assert_eq!(
            crate::dns::message::parse_edns0_client_subnet(&seen).as_deref(),
            Some("1.2.3.0/24")
        );
    }

    #[tokio::test]
    async fn explain_reports_rule_and_cache_hit() {
        use crate::router::ruleset::{DefaultRule, Rule};
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
            disable_cache: None,
            rewrite_ttl: None,
            client_subnet: None,
            strategy: None,
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
