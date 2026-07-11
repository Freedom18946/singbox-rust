use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;

use crate::runtime_options::DnsRuntimeOptions;

use crate::dns::{
    cache::{DnsCache, Key as CacheKey, QType as CacheQType},
    resolver::DnsResolver,
    rule_engine::{DnsRoutingRule, DnsRuleEngine},
    DnsUpstream, Resolver,
};

type DnsComponents = (
    Arc<dyn Resolver>,
    Option<Arc<dyn crate::dns::dns_router::DnsRouter>>,
);

#[derive(Clone)]
struct CacheFileFakeIpStorage {
    inner: Arc<dyn crate::context::CacheFile>,
}

impl std::fmt::Debug for CacheFileFakeIpStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheFileFakeIpStorage")
            .finish_non_exhaustive()
    }
}

impl crate::dns::fakeip::FakeIpStorage for CacheFileFakeIpStorage {
    fn get_by_domain(&self, domain: &str, is_ipv6: bool) -> Option<std::net::IpAddr> {
        self.inner.get_fakeip_by_domain(domain, is_ipv6)
    }

    fn store(&self, domain: &str, ip: std::net::IpAddr) {
        self.inner.store_fakeip_mapping(domain, ip);
    }

    fn load_metadata(&self) -> Option<crate::dns::fakeip::FakeIpMetadata> {
        self.inner.load_fakeip_metadata()
    }

    fn save_metadata_debounced(&self, metadata: crate::dns::fakeip::FakeIpMetadata) {
        self.inner.save_fakeip_metadata(metadata);
    }

    fn reset(&self) {
        let _ = self.inner.reset_fakeip();
    }
}

struct DnsServerManager {
    registry: Arc<crate::dns::transport::TransportRegistry>,
    upstreams: HashMap<String, Arc<dyn DnsUpstream>>,
    ordered_tags: Vec<String>,
    fakeip_tags: Vec<String>,
    default_tag: String,
}

impl DnsServerManager {
    fn build(dns: &sb_config::ir::DnsIR, options: &DnsRuntimeOptions) -> Result<Self> {
        let registry = Arc::new(crate::dns::transport::TransportRegistry::new());
        let mut upstreams = HashMap::<String, Arc<dyn DnsUpstream>>::new();
        let mut ordered_tags = Vec::<String>::new();
        let mut fakeip_tags = Vec::<String>::new();
        let mut seen = HashSet::<String>::new();
        let mut dependencies = HashMap::<String, Vec<String>>::new();

        for server in &dns.servers {
            if server.tag.trim().is_empty() {
                anyhow::bail!("dns server tag must not be empty");
            }
            if !seen.insert(server.tag.clone()) {
                anyhow::bail!("duplicate dns server tag: {}", server.tag);
            }

            let kind = dns_server_kind(server);
            let is_fakeip = kind.as_deref() == Some("fakeip");
            if is_fakeip {
                if !fakeip_tags.is_empty() {
                    anyhow::bail!("multiple fakeip server are not supported");
                }
                fakeip_tags.push(server.tag.clone());
            }

            if let Some(dep) = server.address_resolver.as_ref().filter(|s| !s.is_empty()) {
                dependencies
                    .entry(server.tag.clone())
                    .or_default()
                    .push(dep.clone());
            }

            let upstream = build_upstream_from_server_with_options(server, &registry, options)?
                .ok_or_else(|| unknown_dns_transport_error(server))?;
            upstreams.insert(server.tag.clone(), upstream);
            ordered_tags.push(server.tag.clone());
        }

        if upstreams.is_empty() {
            anyhow::bail!("dns: no servers configured");
        }

        for (tag, deps) in &dependencies {
            for dep in deps {
                if !upstreams.contains_key(dep) {
                    anyhow::bail!("dependency[{}] not found for server[{}]", dep, tag);
                }
            }
        }
        let ordered_tags = topological_order(&ordered_tags, &dependencies)?;

        let default_tag = dns
            .default
            .as_ref()
            .or(dns.final_server.as_ref())
            .cloned()
            .or_else(|| {
                ordered_tags
                    .iter()
                    .find(|tag| !fakeip_tags.contains(tag))
                    .cloned()
            })
            .ok_or_else(|| anyhow::anyhow!("default server cannot be fakeip"))?;

        if !upstreams.contains_key(&default_tag) {
            anyhow::bail!("default DNS server not found: {}", default_tag);
        }
        if fakeip_tags.contains(&default_tag) {
            anyhow::bail!("default server cannot be fakeip");
        }

        Ok(Self {
            registry,
            upstreams,
            ordered_tags,
            fakeip_tags,
            default_tag,
        })
    }

    fn ordered_upstreams(&self) -> Vec<Arc<dyn DnsUpstream>> {
        self.ordered_tags
            .iter()
            .filter_map(|tag| self.upstreams.get(tag).cloned())
            .collect()
    }
}

fn dns_server_kind(server: &sb_config::ir::DnsServerIR) -> Option<String> {
    server
        .server_type
        .as_ref()
        .map(|s| normalize_dns_kind(s))
        .or_else(|| kind_from_address(&server.address))
}

fn normalize_dns_kind(kind: &str) -> String {
    match kind.trim().to_ascii_lowercase().as_str() {
        "dot" => "tls".to_string(),
        "doq" => "quic".to_string(),
        "http3" | "doh3" => "h3".to_string(),
        "fake-ip" => "fakeip".to_string(),
        other => other.to_string(),
    }
}

fn is_supported_dns_kind(kind: &str) -> bool {
    matches!(
        normalize_dns_kind(kind).as_str(),
        "system"
            | "local"
            | "hosts"
            | "udp"
            | "tcp"
            | "tls"
            | "quic"
            | "https"
            | "h3"
            | "dhcp"
            | "fakeip"
            | "tailscale"
            | "resolved"
    )
}

fn kind_from_address(address: &str) -> Option<String> {
    let address = address.trim();
    if address.is_empty() {
        return None;
    }
    if let Some((scheme, _)) = address.split_once("://") {
        return Some(normalize_dns_kind(scheme));
    }
    match address.to_ascii_lowercase().as_str() {
        "system" | "local" | "hosts" | "fakeip" | "dhcp" | "tailscale" | "resolved" => {
            Some(address.to_ascii_lowercase())
        }
        _ => Some("udp".to_string()),
    }
}

fn unknown_dns_transport_error(server: &sb_config::ir::DnsServerIR) -> anyhow::Error {
    let kind = dns_server_kind(server).unwrap_or_else(|| server.address.clone());
    anyhow::anyhow!("unknown transport type: {}", kind)
}

fn topological_order(
    ordered_tags: &[String],
    dependencies: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>> {
    fn visit(
        tag: &str,
        dependencies: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        in_progress: &mut Vec<String>,
        ordered: &mut Vec<String>,
    ) -> Result<()> {
        if let Some(pos) = in_progress.iter().position(|item| item == tag) {
            let mut cycle = in_progress[pos..].to_vec();
            cycle.push(tag.to_string());
            anyhow::bail!("circular server dependency: {}", cycle.join(" -> "));
        }
        if visited.contains(tag) {
            return Ok(());
        }

        in_progress.push(tag.to_string());
        if let Some(deps) = dependencies.get(tag) {
            for dep in deps {
                visit(dep, dependencies, visited, in_progress, ordered)?;
            }
        }
        in_progress.pop();
        visited.insert(tag.to_string());
        ordered.push(tag.to_string());
        Ok(())
    }

    let mut visited = HashSet::new();
    let mut ordered = Vec::new();
    for tag in ordered_tags {
        visit(
            tag,
            dependencies,
            &mut visited,
            &mut Vec::new(),
            &mut ordered,
        )?;
    }
    Ok(ordered)
}

/// Build DNS components (Resolver and Router) from sb-config IR.
///
/// `cache_file` is an optional `CacheFile` for RDRC (Resolver DNS Result Cache)
/// integration. When `Some`, the DNS resolver can persist and reuse cached transport results.
pub fn build_dns_components(
    ir: &sb_config::ir::ConfigIR,
    cache_file: Option<Arc<dyn crate::context::CacheFile>>,
) -> Result<DnsComponents> {
    build_dns_components_with_options(ir, cache_file, Arc::new(DnsRuntimeOptions::default()))
}

/// Build DNS components with immutable options supplied by application composition root.
pub fn build_dns_components_with_options(
    ir: &sb_config::ir::ConfigIR,
    cache_file: Option<Arc<dyn crate::context::CacheFile>>,
    options: Arc<DnsRuntimeOptions>,
) -> Result<DnsComponents> {
    let dns_ir = ir
        .dns
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("DNS configuration missing"))?;
    let dns = hydrate_dns_ir_from_options(dns_ir, &options);
    crate::dns::fakeip::configure(&dns, &options);

    // Wire FakeIP persistence (mapping + metadata) if cache file is enabled.
    // Must happen after FakeIP env knobs are applied so restored pointers can be range-validated.
    if let Some(ref cf) = cache_file {
        if cf.store_fakeip() {
            crate::dns::fakeip::set_storage(Arc::new(CacheFileFakeIpStorage { inner: cf.clone() }));
            tracing::debug!(target: "sb_core::dns", "CacheFileService wired for FakeIP persistence");
        }
    }

    if let Some(ref _cf) = cache_file {
        tracing::debug!(target: "sb_core::dns", "CacheFileService available for DNS RDRC");
    }

    // Parse strategy
    let strategy = if let Some(s) = &dns.strategy {
        s.parse::<crate::dns::DnsStrategy>().unwrap_or_default()
    } else {
        crate::dns::DnsStrategy::default()
    };

    let manager = DnsServerManager::build(&dns, &options)?;

    // Load GeoIP
    let geoip_db = if let Some(path) = &ir.route.geoip_path {
        match crate::router::geo::GeoIpDb::load_from_file(std::path::Path::new(path)) {
            Ok(db) => Some(Arc::new(db)),
            Err(e) => {
                tracing::warn!("Failed to load GeoIP database: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Load GeoSite
    let geosite_db = if let Some(path) = &ir.route.geosite_path {
        match crate::router::geo::GeoSiteDb::load_from_file(std::path::Path::new(path)) {
            Ok(db) => Some(Arc::new(db)),
            Err(e) => {
                tracing::warn!("Failed to load GeoSite database: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 2) If rules defined, build rule engine
    if !dns.rules.is_empty() {
        let mut routing_rules: Vec<DnsRoutingRule> = Vec::new();
        for r in &dns.rules {
            use crate::dns::rule_engine::DnsRuleAction;

            let action = match r.action.as_deref() {
                Some("reject") => DnsRuleAction::Reject,
                Some("hijack-dns") => DnsRuleAction::HijackDns,
                Some("route-options") => DnsRuleAction::RouteOptions,
                Some("predefined") => DnsRuleAction::Predefined,
                _ => DnsRuleAction::Route,
            };

            // Validation: Route action requires server
            if action == DnsRuleAction::Route && r.server.is_none() {
                tracing::warn!(
                    "DNS rule with Route action missing server, skipping: {:?}",
                    r
                );
                continue;
            }

            let rewrite_ip = r.rewrite_ip.as_ref().map(|ips| {
                ips.iter()
                    .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
                    .collect()
            });

            let rs = build_ruleset_from_rule(r);
            routing_rules.push(DnsRoutingRule {
                rule_set: rs,
                upstream_tag: r.server.clone(),
                action,
                priority: r.priority.unwrap_or(100),
                address_limit: r.address_limit,
                rewrite_ip,
                rcode: r.rcode.clone(),
                answer: r.answer.clone(),
                ns: r.ns.clone(),
                extra: r.extra.clone(),
                disable_cache: r.disable_cache,
                rewrite_ttl: r.rewrite_ttl,
                client_subnet: r.client_subnet.clone(),
                strategy: r.strategy.clone(),
            });
        }

        let answer_cache = if dns.disable_cache.unwrap_or(false) {
            None
        } else {
            let cap = dns
                .cache_capacity
                .map(|v| v as usize)
                .unwrap_or(options.cache_capacity);
            Some(Arc::new(
                DnsCache::new(cap).with_disable_expire(dns.disable_expire.unwrap_or(false)),
            ))
        };

        let engine = DnsRuleEngine::new(
            routing_rules,
            manager.upstreams.clone(),
            manager.default_tag.clone(),
            strategy,
            manager.registry.clone(),
            geoip_db,
            geosite_db,
        )
        .with_lifecycle_order(manager.ordered_tags.clone())
        .with_answer_cache(answer_cache, dns.independent_cache.unwrap_or(false))
        .with_reverse_mapping_enabled(dns.reverse_mapping.unwrap_or(false))
        .with_global_client_subnet(dns.client_subnet.clone())
        .with_cache_file(cache_file.clone());
        // Mark FakeIP upstreams (L2.10.12)
        let mut engine = engine;
        for tag in &manager.fakeip_tags {
            engine.mark_fakeip_upstream(tag);
        }
        let engine_arc = Arc::new(engine);
        // EngineResolver clones the engine (cheap clone if Arc fields, but DnsRuleEngine fields are expensive to clone?
        // DnsRuleEngine struct fields are Vecs and Maps. Cloning DnsRuleEngine is somewhat expensive.
        // We should wrap DnsRuleEngine in Arc for EngineResolver too, or EngineResolver should allow cloning field?
        // Let's modify EngineResolver to hold Arc<DnsRuleEngine> or just clone it if it's acceptable.
        // DnsRuleEngine derives Clone? Let's check.
        // If not, we might need to change EngineResolver to use Arc.

        let base: Arc<dyn Resolver> = Arc::new(EngineResolver {
            engine: engine_arc.clone(),
        });
        let overlay = maybe_wrap_hosts_overlay(&dns, base.clone());
        let cached = overlay;

        // engine_arc implements DnsRouter
        let router: Arc<dyn crate::dns::dns_router::DnsRouter> = engine_arc;

        return Ok((cached, Some(router)));
    }

    // 3) No rules: use simple DnsResolver over all upstreams
    let list: Vec<Arc<dyn DnsUpstream>> = manager.ordered_upstreams();
    let base: Arc<dyn Resolver> = Arc::new(
        DnsResolver::from_options(list, options.clone())
            .with_name("dns_ir".to_string())
            .with_strategy(strategy),
    );
    let overlay = maybe_wrap_hosts_overlay(&dns, base.clone());
    let cached = maybe_wrap_cache(&dns, overlay, &options);
    Ok((cached, None))
}

/// Build a DNS resolver from sb-config IR (DnsIR).
///
/// Convenience wrapper around `build_dns_components` that discards the optional DnsRouter
/// and passes `None` for the cache file (no RDRC persistence).
pub fn resolver_from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Arc<dyn Resolver>> {
    let (resolver, _) = build_dns_components(ir, None)?;
    Ok(resolver)
}

/// Build a single DNS upstream from address string (e.g., udp://, doh3://, system, local).
/// Exposed for integration tests and CLI validation.
pub fn build_upstream(
    addr: &str,
    _registry: &crate::dns::transport::TransportRegistry,
) -> Result<Option<Arc<dyn DnsUpstream>>> {
    let a = addr.trim();
    if a.is_empty() {
        return Ok(None);
    }
    if a.eq_ignore_ascii_case("system") {
        return Ok(Some(Arc::new(crate::dns::upstream::SystemUpstream::new())));
    }
    if a.eq_ignore_ascii_case("local") || a.starts_with("local://") {
        return Ok(Some(Arc::new(crate::dns::upstream::LocalUpstream::new(
            None,
        ))));
    }
    if a.eq_ignore_ascii_case("dhcp") || a.starts_with("dhcp://") {
        return Ok(Some(build_dhcp_dns_upstream(a, None)?));
    }
    if a.eq_ignore_ascii_case("tailscale") || a.starts_with("tailscale://") {
        return Ok(Some(build_tailscale_dns_upstream(a, None, &[])?));
    }
    if a.eq_ignore_ascii_case("resolved")
        || a.eq_ignore_ascii_case("system")
        || a.starts_with("resolved://")
    {
        return Ok(Some(build_resolved_dns_upstream(a, None)?));
    }
    if let Some(rest) = a.strip_prefix("udp://") {
        let sa = normalize_host_port(rest, 53)?;
        return Ok(Some(Arc::new(crate::dns::upstream::UdpUpstream::new(sa))));
    }
    if let Some(rest) = a.strip_prefix("tcp://") {
        let sa = normalize_host_port(rest, 53)?;
        let transport = crate::dns::transport::TcpTransport::new(sa);
        return Ok(Some(Arc::new(TransportBackedUpstream::new(
            format!("tcp::{sa}"),
            Arc::new(transport),
        ))));
    }
    if a.starts_with("https://") || a.starts_with("http://") {
        let up = crate::dns::upstream::DohUpstream::new(a.to_string())?;
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a
        .strip_prefix("dot://")
        .or_else(|| a.strip_prefix("tls://"))
    {
        let (host, port) = split_host_port(rest, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let up = crate::dns::upstream::DotUpstream::new(sa, host.to_string());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a
        .strip_prefix("doq://")
        .or_else(|| a.strip_prefix("quic://"))
    {
        let (hp, sni) = if let Some((h, s)) = rest.split_once('@') {
            (h, Some(s.to_string()))
        } else {
            (rest, None)
        };
        let (host, port) = split_host_port(hp, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = sni.unwrap_or_else(|| host.to_string());
        let up = crate::dns::upstream::DoqUpstream::new(sa, sni);
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a
        .strip_prefix("doh3://")
        .or_else(|| a.strip_prefix("h3://"))
    {
        // Format: doh3://host:port/path or h3://host:port/path
        let (host_port, path) = if let Some((hp, p)) = rest.split_once('/') {
            (hp, format!("/{}", p))
        } else {
            (rest, "/dns-query".to_string())
        };
        let (host, port) = split_host_port(host_port, 443)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let up = crate::dns::upstream::Doh3Upstream::new(sa, host.to_string(), path)?;
        return Ok(Some(Arc::new(up)));
    }
    if a.split_once("://").is_none() {
        let sa = normalize_host_port(a, 53)?;
        return Ok(Some(Arc::new(crate::dns::upstream::UdpUpstream::new(sa))));
    }
    Ok(None)
}

/// Build a DNS upstream from a full server IR entry.
/// Exposed for integration tests and CLI validation.
pub fn build_upstream_from_server(
    srv: &sb_config::ir::DnsServerIR,
    _registry: &crate::dns::transport::TransportRegistry,
) -> Result<Option<Arc<dyn DnsUpstream>>> {
    build_upstream_from_server_with_options(srv, _registry, &DnsRuntimeOptions::default())
}

fn build_upstream_from_server_with_options(
    srv: &sb_config::ir::DnsServerIR,
    _registry: &crate::dns::transport::TransportRegistry,
    options: &DnsRuntimeOptions,
) -> Result<Option<Arc<dyn DnsUpstream>>> {
    // L2.10.11: Check server_type first (GUI generates "type" field)
    if let Some(ref st) = srv.server_type {
        let st = normalize_dns_kind(st);
        if !is_supported_dns_kind(&st) {
            return Ok(None);
        }
        match st.as_str() {
            "resolved" => {
                #[cfg(all(target_os = "linux", feature = "service_resolved"))]
                {
                    let service = srv
                        .service
                        .clone()
                        .unwrap_or_else(|| "resolved".to_string());
                    let current = crate::dns::transport::resolved::RESOLVED_STATE.get_service_tag();
                    if service != current {
                        tracing::warn!(
                            target: "sb_core::dns",
                            server = %srv.tag,
                            service = %service,
                            current = %current,
                            "resolved DNS server service tag does not match active resolved service tag; continuing"
                        );
                    }

                    let mut cfg =
                        crate::dns::transport::resolved::ResolvedTransportConfig::default();
                    cfg.accept_default_resolvers = srv.accept_default_resolvers.unwrap_or(false);

                    let up =
                        crate::dns::upstream::ResolvedTransportUpstream::new(srv.tag.clone(), cfg);
                    return Ok(Some(Arc::new(up)));
                }
                #[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
                {
                    anyhow::bail!(
                        "dns server type 'resolved' requires Linux + sb-core feature `service_resolved`"
                    );
                }
            }
            "fakeip" => {
                let up = crate::dns::upstream::FakeIpUpstream::new(
                    srv.tag.clone(),
                    srv.inet4_range.clone(),
                    srv.inet6_range.clone(),
                );
                return Ok(Some(Arc::new(up)));
            }
            "hosts" => {
                let up = crate::dns::upstream::HostsUpstream::from_json_predefined(
                    srv.tag.clone(),
                    srv.predefined.as_ref(),
                    &srv.hosts_path,
                );
                return Ok(Some(Arc::new(up)));
            }
            _ => {
                // Fall through to address-based detection
            }
        }
    }

    // Prefer detailed builder for DoT/DoQ when extras are present
    let a = srv.address.trim();
    if a.is_empty() && srv.server_type.is_none() {
        return Ok(None);
    }
    if a.is_empty() {
        return Ok(None);
    }
    if a.eq_ignore_ascii_case("system") {
        return Ok(Some(Arc::new(crate::dns::upstream::SystemUpstream::new())));
    }
    if a.eq_ignore_ascii_case("local") || a.starts_with("local://") {
        return Ok(Some(Arc::new(crate::dns::upstream::LocalUpstream::new(
            Some(&srv.tag),
        ))));
    }
    if a.eq_ignore_ascii_case("dhcp") || a.starts_with("dhcp://") {
        return Ok(Some(build_dhcp_dns_upstream(a, Some(&srv.tag))?));
    }
    if a.eq_ignore_ascii_case("tailscale") || a.starts_with("tailscale://") {
        return Ok(Some(build_tailscale_dns_upstream(
            a,
            Some(&srv.tag),
            &options.tailscale_addrs,
        )?));
    }
    if a.eq_ignore_ascii_case("resolved")
        || a.eq_ignore_ascii_case("system")
        || a.starts_with("resolved://")
    {
        return Ok(Some(build_resolved_dns_upstream(a, Some(&srv.tag))?));
    }
    if let Some(rest) = a.strip_prefix("udp://") {
        let sa = normalize_host_port(rest, 53)?;
        let up = crate::dns::upstream::UdpUpstream::new(sa)
            .with_timeout(std::time::Duration::from_millis(options.udp_timeout_ms))
            .with_retries(options.udp_retries)
            .with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a.strip_prefix("tcp://") {
        let sa = normalize_host_port(rest, 53)?;
        let transport = crate::dns::transport::TcpTransport::new(sa);
        return Ok(Some(Arc::new(TransportBackedUpstream::new(
            format!("tcp::{}", srv.tag),
            Arc::new(transport),
        ))));
    }
    if a.starts_with("https://") || a.starts_with("http://") {
        let mut up = crate::dns::upstream::DohUpstream::new(a.to_string())?;
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a
        .strip_prefix("dot://")
        .or_else(|| a.strip_prefix("tls://"))
    {
        let (host, port) = split_host_port(rest, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = srv.sni.clone().unwrap_or_else(|| host.to_string());
        let mut up = crate::dns::upstream::DotUpstream::new_with_tls(
            sa,
            sni,
            srv.ca_paths.clone(),
            srv.ca_pem.clone(),
            srv.skip_cert_verify.unwrap_or(false),
            None,
        );
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a
        .strip_prefix("doq://")
        .or_else(|| a.strip_prefix("quic://"))
    {
        let (hp, sni_param) = if let Some((h, s)) = rest.split_once('@') {
            (h, Some(s.to_string()))
        } else {
            (rest, None)
        };
        let (host, port) = split_host_port(hp, 853)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = srv
            .sni
            .clone()
            .or(sni_param)
            .unwrap_or_else(|| host.to_string());
        let mut up = crate::dns::upstream::DoqUpstream::new_with_tls(
            sa,
            sni,
            srv.ca_paths.clone(),
            srv.ca_pem.clone(),
            srv.skip_cert_verify.unwrap_or(false),
            None,
        );
        up = up.with_client_subnet(srv.client_subnet.clone());
        return Ok(Some(Arc::new(up)));
    }
    if let Some(rest) = a
        .strip_prefix("doh3://")
        .or_else(|| a.strip_prefix("h3://"))
    {
        // Format: doh3://host:port/path or h3://host:port/path
        let (host_port, path) = if let Some((hp, p)) = rest.split_once('/') {
            (hp, format!("/{}", p))
        } else {
            (rest, "/dns-query".to_string())
        };
        let (host, port) = split_host_port(host_port, 443)?;
        let sa = format!("{host}:{port}").parse::<std::net::SocketAddr>()?;
        let sni = srv.sni.clone().unwrap_or_else(|| host.to_string());
        let mut up = crate::dns::upstream::Doh3Upstream::new_with_tls(
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
    build_upstream(a, _registry)
}

struct TransportBackedUpstream {
    name: String,
    transport: Arc<dyn crate::dns::transport::DnsTransport>,
}

impl TransportBackedUpstream {
    fn new(name: String, transport: Arc<dyn crate::dns::transport::DnsTransport>) -> Self {
        Self { name, transport }
    }
}

#[async_trait::async_trait]
impl DnsUpstream for TransportBackedUpstream {
    async fn query(
        &self,
        domain: &str,
        record_type: crate::dns::RecordType,
    ) -> Result<crate::dns::DnsAnswer> {
        let query_id = 0x1313;
        let query = build_dns_query_packet(query_id, domain, record_type)?;
        let response = self.transport.query(&query).await?;
        parse_dns_answer_packet(&response, query_id, record_type)
    }

    async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.transport.query(packet).await
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> bool {
        true
    }

    async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {
        self.transport.start(stage).await
    }

    async fn close(&self) -> Result<()> {
        self.transport.close().await
    }
}

fn build_dns_query_packet(
    query_id: u16,
    domain: &str,
    record_type: crate::dns::RecordType,
) -> Result<Vec<u8>> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&query_id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("invalid DNS label in domain: {domain}");
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&(record_type as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

fn parse_dns_answer_packet(
    packet: &[u8],
    expected_id: u16,
    expected_type: crate::dns::RecordType,
) -> Result<crate::dns::DnsAnswer> {
    if packet.len() < 12 {
        anyhow::bail!("DNS response too short");
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != expected_id {
        anyhow::bail!("DNS response query id mismatch");
    }
    let rcode = packet[3] & 0x0f;
    if rcode != 0 {
        return Ok(crate::dns::DnsAnswer::new(
            Vec::new(),
            std::time::Duration::from_secs(0),
            crate::dns::cache::Source::Upstream,
            dns_rcode_from_wire(rcode),
        ));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        skip_dns_name(packet, &mut offset)?;
        offset = offset
            .checked_add(4)
            .filter(|n| *n <= packet.len())
            .ok_or_else(|| anyhow::anyhow!("DNS question truncated"))?;
    }

    let mut ips = Vec::new();
    let mut ttl = std::time::Duration::from_secs(300);
    for _ in 0..ancount {
        skip_dns_name(packet, &mut offset)?;
        if offset + 10 > packet.len() {
            anyhow::bail!("DNS answer truncated");
        }
        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            anyhow::bail!("DNS rdata truncated");
        }
        match (rr_type, expected_type, rdlen) {
            (1, crate::dns::RecordType::A, 4) => {
                ips.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                )));
                ttl = ttl.min(std::time::Duration::from_secs(rr_ttl as u64));
            }
            (28, crate::dns::RecordType::AAAA, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[offset..offset + 16]);
                ips.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                ttl = ttl.min(std::time::Duration::from_secs(rr_ttl as u64));
            }
            _ => {}
        }
        offset += rdlen;
    }

    Ok(crate::dns::DnsAnswer::new(
        ips,
        ttl,
        crate::dns::cache::Source::Upstream,
        crate::dns::cache::Rcode::NoError,
    ))
}

fn skip_dns_name(packet: &[u8], offset: &mut usize) -> Result<()> {
    loop {
        if *offset >= packet.len() {
            anyhow::bail!("DNS name truncated");
        }
        let len = packet[*offset];
        if len & 0xc0 == 0xc0 {
            *offset = offset
                .checked_add(2)
                .filter(|n| *n <= packet.len())
                .ok_or_else(|| anyhow::anyhow!("DNS compression pointer truncated"))?;
            return Ok(());
        }
        *offset += 1;
        if len == 0 {
            return Ok(());
        }
        *offset = offset
            .checked_add(len as usize)
            .filter(|n| *n <= packet.len())
            .ok_or_else(|| anyhow::anyhow!("DNS label truncated"))?;
    }
}

fn dns_rcode_from_wire(rcode: u8) -> crate::dns::cache::Rcode {
    match rcode {
        1 => crate::dns::cache::Rcode::FormErr,
        2 => crate::dns::cache::Rcode::ServFail,
        3 => crate::dns::cache::Rcode::NxDomain,
        4 => crate::dns::cache::Rcode::NotImp,
        5 => crate::dns::cache::Rcode::Refused,
        other => crate::dns::cache::Rcode::Other(other),
    }
}

#[cfg(feature = "dns_dhcp")]
fn build_dhcp_dns_upstream(spec: &str, tag: Option<&str>) -> Result<Arc<dyn DnsUpstream>> {
    let up = crate::dns::upstream::DhcpUpstream::from_spec(spec, tag)?;
    Ok(Arc::new(up))
}

#[cfg(not(feature = "dns_dhcp"))]
fn build_dhcp_dns_upstream(_spec: &str, _tag: Option<&str>) -> Result<Arc<dyn DnsUpstream>> {
    Err(anyhow::anyhow!(
        "dhcp DNS upstream requires the `dns_dhcp` feature; rebuild with `--features sb-core/dns_dhcp`"
    ))
}

#[cfg(feature = "dns_tailscale")]
fn build_tailscale_dns_upstream(
    spec: &str,
    tag: Option<&str>,
    fallback: &[std::net::SocketAddr],
) -> Result<Arc<dyn DnsUpstream>> {
    let (name, addrs) = crate::dns::upstream::parse_tailscale_spec(spec, tag, fallback)?;
    if addrs.is_empty() {
        Ok(Arc::new(crate::dns::upstream::TailscaleLocalUpstream::new(
            tag,
        )))
    } else {
        Ok(Arc::new(crate::dns::upstream::StaticMultiUpstream::new(
            name, addrs,
        )))
    }
}

#[cfg(not(feature = "dns_tailscale"))]
fn build_tailscale_dns_upstream(
    _spec: &str,
    _tag: Option<&str>,
    _fallback: &[std::net::SocketAddr],
) -> Result<Arc<dyn DnsUpstream>> {
    Err(anyhow::anyhow!(
        "tailscale DNS upstream requires the `dns_tailscale` feature; rebuild with `--features sb-core/dns_tailscale`"
    ))
}

#[cfg(feature = "dns_resolved")]
fn build_resolved_dns_upstream(spec: &str, tag: Option<&str>) -> Result<Arc<dyn DnsUpstream>> {
    // Accept "system" as an alias for resolved/system resolver.
    let spec = if spec.eq_ignore_ascii_case("system") {
        "resolved"
    } else {
        spec
    };
    let up = crate::dns::upstream::ResolvedUpstream::from_spec(spec, tag)?;
    Ok(Arc::new(up))
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
    engine: Arc<DnsRuleEngine>,
}

#[async_trait::async_trait]
impl Resolver for EngineResolver {
    async fn resolve(&self, domain: &str) -> Result<crate::dns::DnsAnswer> {
        // Resolve both A/AAAA via rule engine helper
        self.engine.resolve_dual_stack(domain).await
    }

    fn name(&self) -> &str {
        "dns_rule_engine"
    }

    async fn explain(&self, domain: &str) -> Result<serde_json::Value> {
        self.engine.explain(domain).await
    }

    async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {
        self.engine.start(stage).await
    }

    async fn close(&self) -> Result<()> {
        self.engine.close().await
    }

    fn cache_stats(&self) -> (usize, usize) {
        self.engine.cache_stats()
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
            if let Ok(ip) = s.parse::<IpAddr>() {
                ips.push(ip);
            }
        }
        if !ips.is_empty() {
            map.insert(h.domain.to_ascii_lowercase(), ips);
        }
    }
    let ttl = std::time::Duration::from_secs(dns.hosts_ttl_s.unwrap_or(300));
    Arc::new(HostsOverlayResolver {
        map,
        ttl,
        inner: base,
    })
}

struct HostsOverlayResolver {
    map: std::collections::HashMap<String, Vec<std::net::IpAddr>>,
    ttl: std::time::Duration,
    inner: Arc<dyn Resolver>,
}

#[async_trait::async_trait]
impl Resolver for HostsOverlayResolver {
    async fn resolve(&self, domain: &str) -> Result<crate::dns::DnsAnswer> {
        let key = domain.to_ascii_lowercase();
        if let Some(ips) = self.map.get(&key) {
            let ips = ips.clone();
            return Ok(crate::dns::DnsAnswer::new(
                ips,
                self.ttl,
                crate::dns::cache::Source::Static,
                crate::dns::cache::Rcode::NoError,
            ));
        }
        self.inner.resolve(domain).await
    }

    fn name(&self) -> &str {
        "hosts_overlay"
    }

    async fn explain(&self, domain: &str) -> Result<serde_json::Value> {
        let key = domain.to_ascii_lowercase();
        if let Some(ips) = self.map.get(&key) {
            return Ok(serde_json::json!({
                "domain": domain,
                "resolver": "hosts_overlay",
                "decision": "hosts",
                "ttl_secs": self.ttl.as_secs(),
                "ips": ips,
            }));
        }

        let inner = self.inner.explain(domain).await?;
        Ok(serde_json::json!({
            "domain": domain,
            "resolver": "hosts_overlay",
            "decision": "passthrough",
            "inner": inner
        }))
    }
}

fn maybe_wrap_cache(
    dns: &sb_config::ir::DnsIR,
    base: Arc<dyn Resolver>,
    options: &DnsRuntimeOptions,
) -> Arc<dyn Resolver> {
    if dns.disable_cache.unwrap_or(false) {
        return base;
    }

    let cap = dns
        .cache_capacity
        .map(|v| v as usize)
        .unwrap_or(options.cache_capacity);
    let cache =
        Arc::new(DnsCache::new(cap).with_disable_expire(dns.disable_expire.unwrap_or(false)));

    Arc::new(CachedResolver { inner: base, cache })
}

struct CachedResolver {
    inner: Arc<dyn Resolver>,
    cache: Arc<DnsCache>,
}

#[async_trait::async_trait]
impl Resolver for CachedResolver {
    async fn resolve(&self, domain: &str) -> Result<crate::dns::DnsAnswer> {
        let cache_key = CacheKey {
            name: domain.to_ascii_lowercase(),
            qtype: CacheQType::A,
            transport_tag: None,
        };

        if let Some(answer) = self.cache.get(&cache_key) {
            return Ok(answer);
        }

        let answer = self.inner.resolve(domain).await?;
        self.cache.put(cache_key, answer.clone());
        Ok(answer)
    }

    fn name(&self) -> &str {
        "cached_resolver"
    }

    async fn explain(&self, domain: &str) -> Result<serde_json::Value> {
        self.inner.explain(domain).await
    }

    async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {
        self.inner.start(stage).await
    }

    async fn close(&self) -> Result<()> {
        self.inner.close().await
    }

    fn cache_stats(&self) -> (usize, usize) {
        let stats = self.cache.stats();
        (stats.total_entries, stats.max_entries)
    }
}

fn hydrate_dns_ir_from_options(
    dns: &sb_config::ir::DnsIR,
    options: &DnsRuntimeOptions,
) -> sb_config::ir::DnsIR {
    let mut hydrated = dns.clone();

    hydrated.timeout_ms = hydrated.timeout_ms.or(Some(options.udp_timeout_ms));
    hydrated.ttl_default_s = hydrated.ttl_default_s.or(Some(options.default_ttl_s));
    hydrated.ttl_min_s = hydrated.ttl_min_s.or(Some(options.min_ttl_s));
    hydrated.ttl_max_s = hydrated.ttl_max_s.or(Some(options.max_ttl_s));
    hydrated.ttl_neg_s = hydrated.ttl_neg_s.or(Some(options.negative_ttl_s));

    if hydrated.fakeip_enabled.is_none() {
        hydrated.fakeip_enabled = Some(options.fakeip_enabled);
    }
    if hydrated.fakeip_v4_base.is_none() {
        hydrated.fakeip_v4_base = Some(options.fakeip_v4_base.to_string());
    }
    if hydrated.fakeip_v4_mask.is_none() {
        hydrated.fakeip_v4_mask = Some(options.fakeip_v4_mask);
    }
    if hydrated.fakeip_v6_base.is_none() {
        hydrated.fakeip_v6_base = Some(options.fakeip_v6_base.to_string());
    }
    if hydrated.fakeip_v6_mask.is_none() {
        hydrated.fakeip_v6_mask = Some(options.fakeip_v6_mask);
    }

    if hydrated.pool_strategy.is_none() {
        hydrated.pool_strategy = Some(options.pool_strategy.clone());
    }
    hydrated.pool_race_window_ms = hydrated
        .pool_race_window_ms
        .or(Some(options.race_window_ms));
    hydrated.pool_he_race_ms = hydrated
        .pool_he_race_ms
        .or(Some(options.happy_eyeballs_race_ms));
    if hydrated.pool_he_order.is_none() {
        hydrated.pool_he_order = Some(options.happy_eyeballs_order.clone());
    }
    hydrated.pool_max_inflight = hydrated
        .pool_max_inflight
        .or(Some(options.pool_max_inflight as u64));
    hydrated.pool_per_host_inflight = hydrated
        .pool_per_host_inflight
        .or(Some(options.per_host_inflight as u64));

    if hydrated.client_subnet.is_none() {
        hydrated.client_subnet.clone_from(&options.client_subnet);
    }
    hydrated.cache_capacity = hydrated
        .cache_capacity
        .or(Some(options.cache_capacity as u32));

    if hydrated.hosts_ttl_s.is_none() {
        hydrated.hosts_ttl_s = Some(options.static_ttl_s);
    }

    hydrated
}

fn build_ruleset_from_rule(
    r: &sb_config::ir::DnsRuleIR,
) -> std::sync::Arc<crate::router::ruleset::RuleSet> {
    use crate::router::ruleset::{
        DefaultRule, DomainRule, IpPrefixTree, LogicalMode, LogicalRule, Rule, RuleSet,
        RuleSetFormat, RuleSetSource,
    };
    use std::path::PathBuf;
    use std::sync::Arc as StdArc;
    use std::time::SystemTime;

    fn append_ip_version_query_types(
        rule: &sb_config::ir::DnsRuleIR,
        query_type: &mut Vec<String>,
    ) {
        for value in &rule.ip_version {
            match value.trim().to_ascii_lowercase().as_str() {
                "4" | "ipv4" => {
                    if !query_type.iter().any(|q| q.eq_ignore_ascii_case("A")) {
                        query_type.push("A".to_string());
                    }
                }
                "6" | "ipv6" => {
                    if !query_type.iter().any(|q| q.eq_ignore_ascii_case("AAAA")) {
                        query_type.push("AAAA".to_string());
                    }
                }
                _ => {}
            }
        }
    }

    fn build_rule(rule: &sb_config::ir::DnsRuleIR) -> Rule {
        if rule
            .rule_type
            .as_deref()
            .is_some_and(|t| t.eq_ignore_ascii_case("logical"))
        {
            let mode = match rule.mode.as_deref().map(str::to_ascii_lowercase).as_deref() {
                Some("and") => LogicalMode::And,
                _ => LogicalMode::Or,
            };
            return Rule::Logical(LogicalRule {
                mode,
                rules: rule.rules.iter().map(build_rule).collect(),
                invert: rule.invert,
            });
        }

        let mut query_type = rule.query_type.clone();
        append_ip_version_query_types(rule, &mut query_type);

        let mut port_range = parse_port_ranges(&rule.port_range);
        port_range.extend(parse_port_ranges(&rule.port));
        let mut source_port_range = parse_port_ranges(&rule.source_port_range);
        source_port_range.extend(parse_port_ranges(&rule.source_port));

        let mut default_rule = DefaultRule {
            domain_suffix: rule.domain_suffix.clone(),
            domain_keyword: rule.keyword.clone(),
            domain_regex: rule.domain_regex.clone(),
            geosite: rule.geosite.clone(),
            geoip: rule.geoip.clone(),
            source_geoip: rule.source_geoip.clone(),
            source_ip_cidr: parse_cidrs(&rule.source_ip_cidr),
            ip_cidr: parse_cidrs(&rule.ip_cidr),
            port: parse_ports(&rule.port),
            port_range,
            source_port: parse_ports(&rule.source_port),
            source_port_range,
            network: rule.network.clone(),
            auth_user: rule.auth_user.clone(),
            protocol: rule.protocol.clone(),
            process_name: rule.process_name.clone(),
            process_path: rule.process_path.clone(),
            process_path_regex: rule.process_path_regex.clone(),
            package_name: rule.package_name.clone(),
            user: rule.user.clone(),
            user_id: rule.user_id.clone(),
            outbound_tag: rule.outbound.clone(),
            network_type: rule.network_type.clone(),
            wifi_ssid: rule.wifi_ssid.clone(),
            wifi_bssid: rule.wifi_bssid.clone(),
            interface_address: rule.interface_address.clone(),
            network_interface_address: rule.network_interface_address.clone(),
            default_interface_address: rule.default_interface_address.clone(),
            inbound: rule.inbound.clone(),
            query_type,
            invert: rule.invert,
            ip_is_private: rule.ip_is_private.unwrap_or(false),
            source_ip_is_private: rule.source_ip_is_private.unwrap_or(false),
            ip_accept_any: rule.ip_accept_any.unwrap_or(false),
            rule_set_ip_cidr_match_source: rule.rule_set_ip_cidr_match_source.unwrap_or(false),
            rule_set_ip_cidr_accept_empty: rule.rule_set_ip_cidr_accept_empty.unwrap_or(false),
            clash_mode: rule.clash_mode.clone(),
            network_is_expensive: rule.network_is_expensive.unwrap_or(false),
            network_is_constrained: rule.network_is_constrained.unwrap_or(false),
            ..Default::default()
        };

        if !rule.domain.is_empty() {
            default_rule.domain = rule.domain.iter().cloned().map(DomainRule::Exact).collect();
        }

        Rule::Default(default_rule)
    }

    fn collect_suffixes(rule: &Rule, suffixes: &mut Vec<String>) {
        match rule {
            Rule::Default(default_rule) => suffixes.extend(default_rule.domain_suffix.clone()),
            Rule::Logical(logical_rule) => {
                for sub_rule in &logical_rule.rules {
                    collect_suffixes(sub_rule, suffixes);
                }
            }
        }
    }

    fn collect_ip_cidrs(rule: &Rule, ip_tree: &mut IpPrefixTree) {
        match rule {
            Rule::Default(default_rule) => {
                for cidr in &default_rule.ip_cidr {
                    ip_tree.insert(cidr);
                }
            }
            Rule::Logical(logical_rule) => {
                for sub_rule in &logical_rule.rules {
                    collect_ip_cidrs(sub_rule, ip_tree);
                }
            }
        }
    }

    let rule = build_rule(r);

    // Attach domain suffix indices for the matcher.

    let domain_trie = {
        let mut trie = crate::router::suffix_trie::SuffixTrie::new();
        let mut all_suffixes = Vec::new();
        collect_suffixes(&rule, &mut all_suffixes);
        for suffix in &all_suffixes {
            trie.insert(suffix);
        }
        trie
    };

    // Build IP prefix tree for validation
    let mut ip_tree = IpPrefixTree::new();
    collect_ip_cidrs(&rule, &mut ip_tree);
    // Also include source IP CIDRs in tree?
    // Wait, ip_tree in RuleSet is usually for destination IP matching optimization.
    // The Matcher uses it. If we put source IPs in there, it might match destination IPs incorrectly
    // if the tree doesn't distinguish.
    // The current RuleMatcher::matches_ip_cidrs uses self.ruleset.ip_tree.
    // Standard practice: ip_tree is for destination IPs.

    StdArc::new(RuleSet {
        source: RuleSetSource::Local(PathBuf::from("dns_rule_ir")),
        format: RuleSetFormat::Binary,
        version: 1,
        rules: vec![rule],

        domain_trie: StdArc::new(domain_trie),
        ip_tree: StdArc::new(ip_tree),
        last_updated: SystemTime::now(),
        etag: None,
    })
}

fn parse_cidrs(list: &[String]) -> Vec<crate::router::ruleset::IpCidr> {
    use crate::router::ruleset::IpCidr;
    list.iter().filter_map(|s| IpCidr::parse(s).ok()).collect()
}

fn parse_ports(list: &[String]) -> Vec<u16> {
    list.iter().filter_map(|s| s.parse().ok()).collect()
}

fn parse_port_ranges(list: &[String]) -> Vec<(u16, u16)> {
    list.iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            let (start, end) = trimmed
                .split_once(':')
                .or_else(|| trimmed.split_once('-'))?;
            let start = start.trim().parse::<u16>().ok()?;
            let end = end.trim().parse::<u16>().ok()?;
            Some((start.min(end), start.max(end)))
        })
        .collect()
}

#[cfg(not(feature = "dns_resolved"))]
fn build_resolved_dns_upstream(_spec: &str, _tag: Option<&str>) -> Result<Arc<dyn DnsUpstream>> {
    Err(anyhow::anyhow!(
        "resolved DNS upstream requires the `dns_resolved` feature; rebuild with `--features sb-core/dns_resolved`"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsAnswer;

    fn dns_server(tag: &str, address: &str) -> sb_config::ir::DnsServerIR {
        sb_config::ir::DnsServerIR {
            tag: tag.to_string(),
            address: address.to_string(),
            ..Default::default()
        }
    }

    fn dns_ir(servers: Vec<sb_config::ir::DnsServerIR>) -> sb_config::ir::DnsIR {
        sb_config::ir::DnsIR {
            servers,
            ..Default::default()
        }
    }

    fn build_manager(dns: &sb_config::ir::DnsIR) -> Result<DnsServerManager> {
        DnsServerManager::build(dns, &DnsRuntimeOptions::default())
    }

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
            client_subnet: None,
            ..Default::default()
        });
        ir.servers.push(sb_config::ir::DnsServerIR {
            tag: "dot1".into(),
            address: "dot://1.1.1.1:853".into(),
            sni: Some("cloudflare-dns.com".into()),
            ca_paths: vec![],
            ca_pem: vec![],
            skip_cert_verify: Some(false),
            client_subnet: None,
            ..Default::default()
        });
        ir.servers.push(sb_config::ir::DnsServerIR {
            tag: "doq1".into(),
            address: "doq://1.0.0.1:853@one.one.one.one".into(),
            sni: None,
            ca_paths: vec![],
            ca_pem: vec![],
            skip_cert_verify: Some(false),
            client_subnet: None,
            ..Default::default()
        });
        ir.default = Some("sys".into());

        let config = sb_config::ir::ConfigIR {
            dns: Some(ir),
            ..Default::default()
        };
        let res = resolver_from_ir(&config);
        assert!(res.is_ok());
    }

    #[test]
    fn resolver_supports_local_alias() {
        let mut ir = sb_config::ir::DnsIR::default();
        ir.servers.push(sb_config::ir::DnsServerIR {
            tag: "loc".into(),
            address: "local".into(),
            sni: None,
            ca_paths: vec![],
            ca_pem: vec![],
            skip_cert_verify: None,
            client_subnet: None,
            ..Default::default()
        });

        let config = sb_config::ir::ConfigIR {
            dns: Some(ir),
            ..Default::default()
        };
        let res = resolver_from_ir(&config);
        assert!(res.is_ok());
    }

    #[test]
    fn p1313_02_manager_builds_mixed_local_hosts_fakeip_and_tcp() {
        let mut hosts = dns_server("hosts", "hosts");
        hosts.server_type = Some("hosts".to_string());
        hosts.predefined = Some(serde_json::json!({"example.com": ["1.2.3.4"]}));

        let mut fakeip = dns_server("fakeip", "fakeip");
        fakeip.server_type = Some("fakeip".to_string());

        let mut dns = dns_ir(vec![
            dns_server("local", "local"),
            dns_server("udp", "udp://1.1.1.1:53"),
            dns_server("tcp", "tcp://1.1.1.1:53"),
            hosts,
            fakeip,
        ]);
        dns.default = Some("local".to_string());

        let manager = build_manager(&dns).expect("manager should build");
        assert_eq!(manager.default_tag, "local");
        assert!(manager.upstreams.contains_key("tcp"));
        assert_eq!(manager.fakeip_tags, vec!["fakeip".to_string()]);
    }

    #[test]
    fn p1313_02_manager_rejects_missing_default() {
        let mut dns = dns_ir(vec![dns_server("local", "local")]);
        dns.default = Some("ghost".to_string());

        let err = build_manager(&dns)
            .err()
            .expect("manager should reject missing default")
            .to_string();
        assert_eq!(err, "default DNS server not found: ghost");
    }

    #[test]
    fn p1313_02_manager_rejects_fakeip_default_and_multiple_fakeip() {
        let mut dns = dns_ir(vec![dns_server("fakeip", "fakeip")]);
        dns.servers[0].server_type = Some("fakeip".to_string());
        dns.default = Some("fakeip".to_string());
        let err = build_manager(&dns)
            .err()
            .expect("manager should reject fakeip default")
            .to_string();
        assert_eq!(err, "default server cannot be fakeip");

        let mut second = dns_server("fakeip2", "fakeip");
        second.server_type = Some("fakeip".to_string());
        dns.servers.push(second);
        dns.default = None;
        let err = build_manager(&dns)
            .err()
            .expect("manager should reject multiple fakeip servers")
            .to_string();
        assert_eq!(err, "multiple fakeip server are not supported");
    }

    #[test]
    fn p1313_02_manager_rejects_missing_dependency_and_cycle() {
        let mut dns = dns_ir(vec![dns_server("main", "udp://1.1.1.1:53")]);
        dns.servers[0].address_resolver = Some("missing".to_string());
        let err = build_manager(&dns)
            .err()
            .expect("manager should reject missing dependency")
            .to_string();
        assert_eq!(err, "dependency[missing] not found for server[main]");

        let mut a = dns_server("a", "udp://1.1.1.1:53");
        a.address_resolver = Some("b".to_string());
        let mut b = dns_server("b", "udp://8.8.8.8:53");
        b.address_resolver = Some("a".to_string());
        let err = build_manager(&dns_ir(vec![a, b]))
            .err()
            .expect("manager should reject dependency cycle")
            .to_string();
        assert_eq!(err, "circular server dependency: a -> b -> a");
    }

    #[test]
    fn p1313_02_manager_dependency_order_is_deterministic() {
        let mut main = dns_server("main", "udp://1.1.1.1:53");
        main.address_resolver = Some("bootstrap".to_string());
        let bootstrap = dns_server("bootstrap", "udp://8.8.8.8:53");

        let manager = build_manager(&dns_ir(vec![main, bootstrap])).unwrap();
        assert_eq!(manager.ordered_tags, vec!["bootstrap", "main"]);
    }

    #[test]
    fn p1313_02_manager_rejects_unknown_transport_type() {
        let mut dns = dns_ir(vec![dns_server("bad", "bogus://1.1.1.1")]);
        dns.servers[0].server_type = Some("bogus".to_string());
        let err = build_manager(&dns)
            .err()
            .expect("manager should reject unknown transport type")
            .to_string();
        assert_eq!(err, "unknown transport type: bogus");
    }

    #[test]
    fn p1313_02_manager_rejects_invalid_server_address() {
        let err = build_manager(&dns_ir(vec![dns_server("bad", "udp://")]))
            .err()
            .expect("manager should reject invalid server address")
            .to_string();
        assert!(
            err.contains("invalid socket address syntax"),
            "invalid address should be loud and deterministic, got: {err}"
        );
    }

    #[test]
    fn p1313_02_cache_capacity_prefers_config_and_disable_cache_bypasses() {
        let config = sb_config::ir::ConfigIR {
            dns: Some(sb_config::ir::DnsIR {
                servers: vec![dns_server("local", "local")],
                default: Some("local".to_string()),
                cache_capacity: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolver = resolver_from_ir(&config).unwrap();
        assert_eq!(resolver.cache_stats(), (0, 7));

        let disabled = sb_config::ir::ConfigIR {
            dns: Some(sb_config::ir::DnsIR {
                servers: vec![dns_server("local", "local")],
                default: Some("local".to_string()),
                disable_cache: Some(true),
                cache_capacity: Some(7),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolver = resolver_from_ir(&disabled).unwrap();
        assert_eq!(resolver.cache_stats(), (0, 0));
    }

    #[tokio::test]
    async fn p1313_02_legacy_rcode_rule_reaches_runtime() {
        let doc = serde_json::json!({
            "schema_version": 2,
            "dns": {
                "servers": [
                    {"tag": "reject-name", "address": "rcode://name_error"},
                    {"tag": "local", "address": "local"}
                ],
                "rules": [
                    {"domain_suffix": ["blocked.example"], "server": "reject-name"}
                ],
                "final": "local"
            }
        });
        let ir = sb_config::validator::v2::to_ir_v1(&doc);
        let dns = ir.dns.as_ref().expect("dns should lower");
        assert_eq!(dns.rules[0].action.as_deref(), Some("predefined"));
        assert_eq!(dns.rules[0].rcode.as_deref(), Some("NXDOMAIN"));
        assert!(dns.rules[0].server.is_none());

        let (_, router) = build_dns_components(&ir, None).expect("components should build");
        let query = crate::dns::udp::build_query("blocked.example", 1).unwrap();
        let response = router
            .expect("router should be present")
            .exchange(&crate::dns::dns_router::DnsQueryContext::new(), &query)
            .await
            .unwrap();
        assert_eq!(response[3] & 0x0f, 3);
    }

    #[test]
    fn build_upstream_returns_local_impl() {
        let registry = crate::dns::transport::TransportRegistry::new();
        let upstream = build_upstream("local", &registry)
            .expect("local upstream builder should not error")
            .expect("local upstream should be built");

        assert_eq!(upstream.name(), "local");
    }

    #[test]
    fn build_upstream_from_server_sets_local_tag_name() {
        let registry = crate::dns::transport::TransportRegistry::new();
        let upstream = build_upstream_from_server(
            &sb_config::ir::DnsServerIR {
                tag: "local_tag".into(),
                address: "local".into(),
                sni: None,
                ca_paths: vec![],
                ca_pem: vec![],
                skip_cert_verify: None,
                client_subnet: None,
                ..Default::default()
            },
            &registry,
        )
        .unwrap()
        .unwrap();

        assert_eq!(upstream.name(), "local::local_tag");
    }

    #[cfg(feature = "dns_dhcp")]
    #[test]
    fn build_upstream_from_server_supports_dhcp_without_tokio_runtime() {
        let registry = crate::dns::transport::TransportRegistry::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let resolv = dir.path().join("resolv.conf");
        std::fs::write(&resolv, "nameserver 1.1.1.1\n").expect("write resolv.conf");

        let upstream = build_upstream_from_server(
            &sb_config::ir::DnsServerIR {
                tag: "dhcp_tag".into(),
                address: format!("dhcp://eth0?resolv={}", resolv.display()),
                sni: None,
                ca_paths: vec![],
                ca_pem: vec![],
                skip_cert_verify: None,
                client_subnet: None,
                ..Default::default()
            },
            &registry,
        )
        .expect("dhcp upstream builder should not panic outside runtime")
        .expect("dhcp upstream should be built");

        assert_eq!(upstream.name(), "dhcp::dhcp_tag");
    }

    #[test]
    fn builder_keeps_special_upstream_wiring_in_specialized_helpers() {
        let source = include_str!("config_builder.rs");
        assert!(source.contains("build_dhcp_dns_upstream"));
        assert!(source.contains("build_tailscale_dns_upstream"));
        assert!(source.contains("build_resolved_dns_upstream"));
    }

    #[test]
    fn hydrate_dns_ir_reads_options() {
        let options = DnsRuntimeOptions {
            default_ttl_s: 900,
            udp_timeout_ms: 2500,
            fakeip_enabled: true,
            fakeip_v4_base: "198.18.0.0".parse().unwrap(),
            fakeip_v4_mask: 15,
            client_subnet: Some("1.2.3.0/24".into()),
            ..DnsRuntimeOptions::default()
        };
        let hydrated = hydrate_dns_ir_from_options(&sb_config::ir::DnsIR::default(), &options);
        assert_eq!(hydrated.timeout_ms, Some(2500));
        assert_eq!(hydrated.ttl_default_s, Some(900));
        assert_eq!(hydrated.fakeip_enabled, Some(true));
        assert_eq!(hydrated.fakeip_v4_base.as_deref(), Some("198.18.0.0"));
        assert_eq!(hydrated.fakeip_v4_mask, Some(15));
        assert_eq!(hydrated.client_subnet.as_deref(), Some("1.2.3.0/24"));
    }

    #[test]
    fn hydrate_dns_ir_does_not_override_ir_values() {
        let options = DnsRuntimeOptions {
            default_ttl_s: 900,
            ..DnsRuntimeOptions::default()
        };
        let ir = sb_config::ir::DnsIR {
            ttl_default_s: Some(120),
            ..Default::default()
        };
        let hydrated = hydrate_dns_ir_from_options(&ir, &options);
        assert_eq!(hydrated.ttl_default_s, Some(120));
    }

    struct DummyResolver;

    #[async_trait::async_trait]
    impl Resolver for DummyResolver {
        async fn resolve(&self, _domain: &str) -> Result<DnsAnswer> {
            anyhow::bail!("not implemented")
        }

        fn name(&self) -> &str {
            "dummy"
        }

        async fn explain(&self, domain: &str) -> Result<serde_json::Value> {
            Ok(serde_json::json!({
                "resolver": "dummy",
                "domain": domain
            }))
        }
    }

    #[tokio::test]
    async fn hosts_overlay_explain_reports_match_and_passthrough() {
        let mut map = std::collections::HashMap::new();
        map.insert("example.com".to_string(), vec!["1.2.3.4".parse().unwrap()]);
        let ttl = std::time::Duration::from_secs(123);
        let overlay = HostsOverlayResolver {
            map,
            ttl,
            inner: Arc::new(DummyResolver),
        };

        let matched = overlay.explain("example.com").await.unwrap();
        assert_eq!(matched["decision"], serde_json::json!("hosts"));
        assert_eq!(matched["ttl_secs"], serde_json::json!(123));
        assert_eq!(matched["ips"][0], serde_json::json!("1.2.3.4"));

        let passthrough = overlay.explain("other.com").await.unwrap();
        assert_eq!(passthrough["decision"], serde_json::json!("passthrough"));
        assert_eq!(passthrough["inner"]["resolver"], serde_json::json!("dummy"));
    }
}
