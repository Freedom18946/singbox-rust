use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use super::{resolver::DnsResolver, rule_engine::{DnsRuleEngine, DnsRoutingRule}, DnsUpstream, Resolver};

/// Build a DNS resolver from sb-config IR (DnsIR).
///
/// - Creates upstreams from `servers`
/// - When `rules` are present, builds a DnsRuleEngine and wraps it as a Resolver
/// - Otherwise falls back to a simple DnsResolver over all upstreams
pub fn resolver_from_ir(dns: &sb_config::ir::DnsIR) -> Result<Arc<dyn Resolver>> {
    // Apply IR-level global knobs to env for compatibility with existing components
    apply_env_from_ir(dns);
    // 1) Build upstream registry
    let mut upstreams: HashMap<String, Arc<dyn DnsUpstream>> = HashMap::new();
    for s in &dns.servers {
        if let Some(up) = build_upstream_from_server(s)? {
            upstreams.insert(s.tag.clone(), up);
        }
    }

    // Determine default upstream tag
    let default_tag = if let Some(d) = dns.default.as_ref() {
        d.clone()
    } else if let Some((tag, _)) = upstreams.iter().next() {
        tag.clone()
    } else {
        "system".to_string()
    };
    if !upstreams.contains_key(&default_tag) {
        // Add system upstream as fallback when default not found
        upstreams.insert(default_tag.clone(), Arc::new(super::upstream::SystemUpstream::new()));
    }

    // 2) If rules defined, build rule engine
    if !dns.rules.is_empty() {
        let mut routing_rules: Vec<DnsRoutingRule> = Vec::new();
    for r in &dns.rules {
        if r.server.trim().is_empty() {
            continue;
        }
        let rs = build_ruleset_from_rule(r);
            routing_rules.push(DnsRoutingRule {
                rule_set: rs,
                upstream_tag: r.server.clone(),
                priority: r.priority.unwrap_or(100),
            });
        }
        let engine = DnsRuleEngine::new(routing_rules, upstreams, default_tag);
        let base: Arc<dyn Resolver> = Arc::new(EngineResolver { engine });
        let overlay = maybe_wrap_hosts_overlay(dns, base.clone());
        return Ok(overlay);
    }

    // 3) No rules: use simple DnsResolver over all upstreams
    let list: Vec<Arc<dyn DnsUpstream>> = upstreams.into_iter().map(|(_, v)| v).collect();
    let base: Arc<dyn Resolver> = Arc::new(DnsResolver::new(list).with_name("dns_ir".to_string()));
    let overlay = maybe_wrap_hosts_overlay(dns, base.clone());
    Ok(overlay)
}

fn build_upstream(addr: &str) -> Result<Option<Arc<dyn DnsUpstream>>> {
    let a = addr.trim();
    if a.is_empty() { return Ok(None); }
    if a.eq_ignore_ascii_case("system") {
        return Ok(Some(Arc::new(super::upstream::SystemUpstream::new())));
    }
    if let Some(rest) = a.strip_prefix("udp://") {
        let sa = normalize_host_port(rest, 53)?;
        return Ok(Some(Arc::new(super::upstream::UdpUpstream::new(sa))));
    }
    if a.starts_with("https://") || a.starts_with("http://") {
        let up = super::upstream::DohUpstream::new(a.to_string())?;
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("dot://").or_else(|| a.strip_prefix("tls://")) {
        let (host, port) = split_host_port(rest, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let up = super::upstream::DotUpstream::new(sa, host.to_string());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("doq://").or_else(|| a.strip_prefix("quic://")) {
        let (hp, sni) = if let Some((h, s)) = rest.split_once('@') { (h, Some(s.to_string())) } else { (rest, None) };
        let (host, port) = split_host_port(hp, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = sni.unwrap_or_else(|| host.to_string());
        let up = super::upstream::DoqUpstream::new(sa, sni);
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("doh3://").or_else(|| a.strip_prefix("h3://")) {
        // Format: doh3://host:port/path or h3://host:port/path
        let (host_port, path) = if let Some((hp, p)) = rest.split_once('/') {
            (hp, format!("/{}", p))
        } else {
            (rest, "/dns-query".to_string())
        };
        let (host, port) = split_host_port(host_port, 443)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let up = super::upstream::Doh3Upstream::new(sa, host.to_string(), path)?;
        return Ok(Some(Arc::new(up)));
    }
    Ok(None)
}

fn build_upstream_from_server(srv: &sb_config::ir::DnsServerIR) -> Result<Option<Arc<dyn DnsUpstream>>> {
    // Prefer detailed builder for DoT/DoQ when extras are present
    let a = srv.address.trim();
    if a.is_empty() { return Ok(None); }
    if a.eq_ignore_ascii_case("system") {
        return Ok(Some(Arc::new(super::upstream::SystemUpstream::new())));
    }
    if let Some(rest) = a.strip_prefix("udp://") {
        let sa = normalize_host_port(rest, 53)?;
        let up = super::upstream::UdpUpstream::new(sa).with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if a.starts_with("https://") || a.starts_with("http://") {
        let mut up = super::upstream::DohUpstream::new(a.to_string())?;
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("dot://").or_else(|| a.strip_prefix("tls://")) {
        let (host, port) = split_host_port(rest, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = srv.sni.clone().unwrap_or_else(|| host.to_string());
        let mut up = super::upstream::DotUpstream::new_with_tls(
            sa,
            sni,
            srv.ca_paths.clone(),
            srv.ca_pem.clone(),
            srv.skip_cert_verify.unwrap_or(false),
        );
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("doq://").or_else(|| a.strip_prefix("quic://")) {
        let (hp, sni_param) = if let Some((h, s)) = rest.split_once('@') { (h, Some(s.to_string())) } else { (rest, None) };
        let (host, port) = split_host_port(hp, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = srv.sni.clone().or(sni_param).unwrap_or_else(|| host.to_string());
        let mut up = super::upstream::DoqUpstream::new_with_tls(
            sa,
            sni,
            srv.ca_paths.clone(),
            srv.ca_pem.clone(),
            srv.skip_cert_verify.unwrap_or(false),
        );
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("doh3://").or_else(|| a.strip_prefix("h3://")) {
        // Format: doh3://host:port/path or h3://host:port/path
        let (host_port, path) = if let Some((hp, p)) = rest.split_once('/') {
            (hp, format!("/{}", p))
        } else {
            (rest, "/dns-query".to_string())
        };
        let (host, port) = split_host_port(host_port, 443)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = srv.sni.clone().unwrap_or_else(|| host.to_string());
        let mut up = super::upstream::Doh3Upstream::new_with_tls(
            sa,
            sni,
            path,
            srv.ca_paths.clone(),
            srv.ca_pem.clone(),
            srv.skip_cert_verify.unwrap_or(false),
        )?;
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    // Fallback to address-only builder
    build_upstream(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_builds_with_mixed_upstreams() {
        let mut ir = sb_config::ir::DnsIR::default();
        ir.servers.push(sb_config::ir::DnsServerIR {
            tag: "sys".into(),
            address: "system".into(),
            sni: None,
            ca_paths: vec![],
            ca_pem: vec![],
            skip_cert_verify: None,
        });
        ir.servers.push(sb_config::ir::DnsServerIR {
            tag: "dot1".into(),
            address: "dot://1.1.1.1:853".into(),
            sni: Some("cloudflare-dns.com".into()),
            ca_paths: vec![],
            ca_pem: vec![],
            skip_cert_verify: Some(false),
        });
        ir.servers.push(sb_config::ir::DnsServerIR {
            tag: "doq1".into(),
            address: "doq://1.0.0.1:853@one.one.one.one".into(),
            sni: None,
            ca_paths: vec![],
            ca_pem: vec![],
            skip_cert_verify: Some(false),
        });
        ir.default = Some("sys".into());

        let res = resolver_from_ir(&ir);
        assert!(res.is_ok());
    }
}

fn normalize_host_port(rest: &str, default_port: u16) -> Result<std::net::SocketAddr> {
    let (host, port) = split_host_port(rest, default_port)?;
    let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
    Ok(sa)
}

fn split_host_port(rest: &str, default_port: u16) -> Result<(String, u16)> {
    // Accept ipv6 in [] or hostname
    if rest.contains(':') {
        // Try direct socketaddr first
        if let Ok(sa) = rest.parse::<std::net::SocketAddr>() {
            return Ok((sa.ip().to_string(), sa.port()));
        }
        // host:port (not IP literal)
        if let Some((h, p)) = rest.rsplit_once(':') {
            let port: u16 = p.parse().unwrap_or(default_port);
            return Ok((h.to_string(), port));
        }
    }
    Ok((rest.to_string(), default_port))
}

/// Simple Resolver adapter wrapping DnsRuleEngine
struct EngineResolver {
    engine: DnsRuleEngine,
}

#[async_trait::async_trait]
impl Resolver for EngineResolver {
    async fn resolve(&self, domain: &str) -> Result<super::DnsAnswer> {
        // Resolve both A/AAAA via rule engine helper
        self.engine.resolve_dual_stack(domain).await
    }

    fn name(&self) -> &str {
        "dns_rule_engine"
    }
}

/// If IR contains hosts mapping, wrap the base resolver with a hosts overlay.
fn maybe_wrap_hosts_overlay(
    dns: &sb_config::ir::DnsIR,
    base: Arc<dyn Resolver>,
) -> Arc<dyn Resolver> {
    if dns.hosts.is_empty() {
        return base;
    }
    use std::net::IpAddr;
    let mut map = std::collections::HashMap::<String, Vec<IpAddr>>::new();
    for h in &dns.hosts {
        let mut ips = Vec::new();
        for s in &h.ips {
            if let Ok(ip) = s.parse::<IpAddr>() { ips.push(ip); }
        }
        if !ips.is_empty() {
            map.insert(h.domain.to_ascii_lowercase(), ips);
        }
    }
    let ttl = std::time::Duration::from_secs(dns.hosts_ttl_s.unwrap_or(300));
    Arc::new(HostsOverlayResolver { map, ttl, inner: base })
}

struct HostsOverlayResolver {
    map: std::collections::HashMap<String, Vec<std::net::IpAddr>>,
    ttl: std::time::Duration,
    inner: Arc<dyn Resolver>,
}

#[async_trait::async_trait]
impl Resolver for HostsOverlayResolver {
    async fn resolve(&self, domain: &str) -> Result<super::DnsAnswer> {
        let key = domain.to_ascii_lowercase();
        if let Some(ips) = self.map.get(&key) {
            let ips = ips.clone();
            return Ok(super::DnsAnswer::new(
                ips,
                self.ttl,
                super::cache::Source::Static,
                super::cache::Rcode::NoError,
            ));
        }
        self.inner.resolve(domain).await
    }

    fn name(&self) -> &str { "hosts_overlay" }
}

fn apply_env_from_ir(dns: &sb_config::ir::DnsIR) {
    fn set_if_unset(k: &str, v: &str) {
        if std::env::var(k).is_err() { std::env::set_var(k, v); }
    }
    if let Some(ms) = dns.timeout_ms { set_if_unset("SB_DNS_UDP_TIMEOUT_MS", &ms.to_string()); set_if_unset("SB_DNS_DOT_TIMEOUT_MS", &ms.to_string()); set_if_unset("SB_DNS_DOH_TIMEOUT_MS", &ms.to_string()); set_if_unset("SB_DNS_DOQ_TIMEOUT_MS", &ms.to_string()); }
    if let Some(s) = dns.ttl_default_s { set_if_unset("SB_DNS_DEFAULT_TTL_S", &s.to_string()); }
    if let Some(s) = dns.ttl_min_s { set_if_unset("SB_DNS_MIN_TTL_S", &s.to_string()); }
    if let Some(s) = dns.ttl_max_s { set_if_unset("SB_DNS_MAX_TTL_S", &s.to_string()); }
    if let Some(s) = dns.ttl_neg_s { set_if_unset("SB_DNS_NEG_TTL_S", &s.to_string()); }
    if dns.fakeip_enabled.unwrap_or(false) { set_if_unset("SB_DNS_FAKEIP_ENABLE", "1"); }
    if let Some(v) = dns.fakeip_v4_base.as_ref() { set_if_unset("SB_FAKEIP_V4_BASE", v); }
    if let Some(v) = dns.fakeip_v4_mask { set_if_unset("SB_FAKEIP_V4_MASK", &v.to_string()); }
    if let Some(v) = dns.fakeip_v6_base.as_ref() { set_if_unset("SB_FAKEIP_V6_BASE", v); }
    if let Some(v) = dns.fakeip_v6_mask { set_if_unset("SB_FAKEIP_V6_MASK", &v.to_string()); }
    if let Some(v) = dns.pool_strategy.as_ref() { set_if_unset("SB_DNS_POOL_STRATEGY", v); }
    if let Some(v) = dns.pool_race_window_ms { set_if_unset("SB_DNS_RACE_WINDOW_MS", &v.to_string()); }
    if let Some(v) = dns.pool_he_race_ms { set_if_unset("SB_DNS_HE_RACE_MS", &v.to_string()); }
    if let Some(v) = dns.pool_he_order.as_ref() { set_if_unset("SB_DNS_HE_ORDER", v); }
    if let Some(v) = dns.pool_max_inflight { set_if_unset("SB_DNS_POOL_MAX_INFLIGHT", &v.to_string()); }
    if let Some(v) = dns.pool_per_host_inflight { set_if_unset("SB_DNS_PER_HOST_INFLIGHT", &v.to_string()); }
    if let Some(v) = dns.client_subnet.as_ref() { set_if_unset("SB_DNS_CLIENT_SUBNET", v); }
}

fn build_ruleset_from_rule(r: &sb_config::ir::DnsRuleIR) -> std::sync::Arc<crate::router::ruleset::RuleSet> {
    use crate::router::ruleset::{DefaultRule, DomainRule, IpPrefixTree, Rule, RuleSet, RuleSetFormat, RuleSetSource};
    use std::path::PathBuf;
    use std::sync::Arc as StdArc;
    use std::time::SystemTime;

    // Build DefaultRule with suffix/keyword/exact
    let mut dr = DefaultRule::default();
    dr.domain_suffix = r.domain_suffix.clone();
    dr.domain_keyword = r.keyword.clone();
    if !r.domain.is_empty() {
        let mut v = Vec::new();
        for d in &r.domain {
            v.push(DomainRule::Exact(d.clone()));
        }
        dr.domain = v;
    }

    // Attach fallback domain suffix list for matcher (when suffix_trie disabled)
    #[cfg(not(feature = "suffix_trie"))]
    let suffixes = dr.domain_suffix.clone();

    StdArc::new(RuleSet {
        source: RuleSetSource::Local(PathBuf::from("dns_rule_ir")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![Rule::Default(dr)],
        #[cfg(feature = "suffix_trie")]
        domain_trie: StdArc::new(Default::default()),
        #[cfg(not(feature = "suffix_trie"))]
        domain_suffixes: StdArc::new(suffixes),
        ip_tree: StdArc::new(IpPrefixTree::new()),
        last_updated: SystemTime::now(),
        etag: None,
    })
}
