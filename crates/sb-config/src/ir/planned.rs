//! Planning layer — crate-private staged fact seam (WP-30as).
//!
//! ## Purpose
//!
//! This module sits in the future **Planned** position of the config pipeline:
//!
//! ```text
//! Raw → Validated (ConfigIR) → Planned (RuntimePlan) → Runtime owners
//! ```
//!
//! ## Current status (WP-30as staged seam)
//!
//! WP-30o consolidated the discrete helpers from WP-30l/m/n into a **crate-private
//! structured fact graph** (`PlannedFacts`). WP-30p absorbed inbound tag uniqueness
//! into the fact graph. WP-30q completed collect-phase uniqueness by adding
//! duplicate tag rejection to `DnsServerNamespace::scan()` and
//! `ServiceNamespace::scan()`. WP-30as keeps that fact graph private, but makes
//! the crate-private staged seam explicit:
//!
//! - `collect_planned_facts(&ConfigIR) -> Result<PlannedFacts>`
//! - `validate_with_planned_facts(&PlannedFacts, &ConfigIR) -> Result<()>`
//! - `validate_planned_facts(&ConfigIR) -> Result<()>`
//!
//! The fact graph cleanly separates two phases:
//!
//! 1. **Collect** — `PlannedFacts::collect(&ConfigIR)` scans all namespace facts
//!    from validated IR and checks tag uniqueness for all four namespaces.
//! 2. **Validate** — `PlannedFacts::validate(&self, &ConfigIR)` checks all 11
//!    reference categories against the collected namespace inventories.
//!
//! `Config::validate()` remains a thin facade over the orchestration entry
//! `validate_planned_facts(&ConfigIR)`.
//!
//! ## Namespace facts (4 domains, all with uniqueness)
//!
//! 1. **Outbound/endpoint shared** — `OutboundIR.name` + `EndpointIR.tag` (uniqueness checked)
//! 2. **Inbound** — `InboundIR.tag` (uniqueness checked, WP-30p)
//! 3. **DNS server** — `DnsServerIR.tag` (uniqueness checked, WP-30q)
//! 4. **Service** — `ServiceIR.tag` (uniqueness checked, WP-30q)
//!
//! Inbound and outbound/endpoint are **independent namespaces** — the same tag
//! string may appear in both without conflict (Go parity).
//!
//! ## Reference facts (11 categories)
//!
//!  1. Outbound/endpoint shared tag namespace uniqueness
//!  2. Selector/URLTest member reference existence
//!  3. Route rule outbound reference existence
//!  4. `route.default` reference existence
//!  5. `DnsServerIR.detour` → outbound/endpoint shared tag namespace
//!  6. `DnsServerIR.address_resolver` → DNS server tag namespace
//!  7. `DnsServerIR.service` → service tag namespace
//!  8. `ServiceIR.detour` → inbound tag namespace
//!  9. `DnsRuleIR.server` → DNS server tag namespace
//! 10. `DnsIR.default` → DNS server tag namespace
//! 11. `DnsIR.final_server` → DNS server tag namespace
//!
//! ## What this is NOT
//!
//! This is still a crate-private fact graph — **not** a public `RuntimePlan` or
//! `PlannedConfigIR`. The fact graph:
//!
//! - is `pub(crate)` only, not re-exported through `ir/mod.rs` or `lib.rs`
//! - consumes validated IR (`ConfigIR`) as input
//! - preserves all existing error messages verbatim (WP-30l/m/n/p)
//! - does not introduce new public types or builder API
//! - does not expose crate-internal namespace query API
//! - does not add exact read-only accessors yet, because there is still no
//!   stable crate-private consumer that needs them
//!
//! ## What is NOT yet implemented
//!
//! - No public `RuntimePlan`
//! - No public `PlannedConfigIR`
//! - No public builder/helper entry point
//! - No crate-internal namespace query API (no stable consumers yet)
//! - No exact private accessors yet (no stable consumers yet)
//! - No runtime connector binding
//! - No runtime-facing DNS env bridge (still in `app::run_engine`)
//! - `validator/v2`, `normalize`, `minimize`, `present` responsibilities not moved
//! - `bootstrap` / `run_engine` runtime responsibilities not moved
//!
//! ## Responsibilities that still stay elsewhere
//!
//! - `validated.rs`: planning-adjacent IR self-checks (selector/urltest non-empty
//!   members, transport conflict validation)
//! - `validator/v2/mod.rs`: parse-time defaults, alias fill, credential ENV
//!   resolution
//! - `normalize` / `minimize` / `present`: token canonicalization, minimization
//!   policy, legacy projection
//! - `app::bootstrap` / `app::run_engine`: runtime-side selector binding, router
//!   text emission, DNS env bridging

use std::collections::HashSet;

use anyhow::{anyhow, Result};

use super::outbound::OutboundType;
use super::validated::ConfigIR;

// ─────────────────────────────────────────────────────────────────────────────
// Namespace structs: tag inventories scanned from validated IR
// ─────────────────────────────────────────────────────────────────────────────

/// A scanned set of outbound + endpoint tags (shared namespace).
#[derive(Debug)]
pub(crate) struct TagNamespace {
    tags: HashSet<String>,
}

impl TagNamespace {
    /// Scan outbound and endpoint tags from validated IR.
    ///
    /// Returns `Err` on the first duplicate tag encountered (preserving the
    /// exact error message that `Config::validate()` has always produced).
    fn scan(ir: &ConfigIR) -> Result<Self> {
        let mut tags = HashSet::new();

        for ob in &ir.outbounds {
            if let Some(name) = &ob.name {
                if !name.is_empty() && !tags.insert(name.clone()) {
                    return Err(anyhow!("duplicate outbound/endpoint tag: {}", name));
                }
            }
        }

        for ep in &ir.endpoints {
            if let Some(tag) = &ep.tag {
                if !tag.is_empty() && !tags.insert(tag.clone()) {
                    return Err(anyhow!("duplicate outbound/endpoint tag: {}", tag));
                }
            }
        }

        Ok(Self { tags })
    }

    fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

/// A scanned set of inbound tags.
#[derive(Debug)]
pub(crate) struct InboundNamespace {
    tags: HashSet<String>,
}

impl InboundNamespace {
    /// Scan inbound tags from validated IR and check uniqueness (WP-30p).
    ///
    /// Returns `Err` on the first duplicate inbound tag encountered,
    /// preserving the exact error message that `Config::validate()` has
    /// always produced. Inbound tags use their own namespace — they are
    /// NOT merged with the outbound/endpoint shared namespace.
    fn scan(ir: &ConfigIR) -> Result<Self> {
        let mut tags = HashSet::new();
        for ib in &ir.inbounds {
            if let Some(tag) = &ib.tag {
                if !tag.is_empty() && !tags.insert(tag.clone()) {
                    return Err(anyhow!("duplicate inbound tag: {}", tag));
                }
            }
        }
        Ok(Self { tags })
    }

    fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

/// A scanned set of DNS server tags.
#[derive(Debug)]
pub(crate) struct DnsServerNamespace {
    tags: HashSet<String>,
}

impl DnsServerNamespace {
    /// Scan DNS server tags from validated IR and check uniqueness.
    ///
    /// Returns `Err` on the first duplicate DNS server tag encountered.
    fn scan(ir: &ConfigIR) -> Result<Self> {
        let mut tags = HashSet::new();
        if let Some(dns) = &ir.dns {
            for srv in &dns.servers {
                if !srv.tag.is_empty() && !tags.insert(srv.tag.clone()) {
                    return Err(anyhow!("duplicate dns server tag: {}", srv.tag));
                }
            }
        }
        Ok(Self { tags })
    }

    fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

/// A scanned set of service tags.
#[derive(Debug)]
pub(crate) struct ServiceNamespace {
    tags: HashSet<String>,
}

impl ServiceNamespace {
    /// Scan service tags from validated IR and check uniqueness.
    ///
    /// Returns `Err` on the first duplicate service tag encountered.
    fn scan(ir: &ConfigIR) -> Result<Self> {
        let mut tags = HashSet::new();
        for svc in &ir.services {
            if let Some(tag) = &svc.tag {
                if !tag.is_empty() && !tags.insert(tag.clone()) {
                    return Err(anyhow!("duplicate service tag: {}", tag));
                }
            }
        }
        Ok(Self { tags })
    }

    fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PlannedFacts: the crate-private structured fact graph
// ─────────────────────────────────────────────────────────────────────────────

/// Crate-private fact graph holding all namespace inventories collected from
/// validated IR.
///
/// This is the central object for WP-30o. It separates fact **collection**
/// (scanning namespaces from ConfigIR) from fact **validation** (checking that
/// all cross-references resolve to known tags).
///
/// This is NOT a public `RuntimePlan` — it is an internal precursor that could
/// evolve into one in the future.
#[derive(Debug)]
pub(crate) struct PlannedFacts {
    outbound_ns: TagNamespace,
    inbound_ns: InboundNamespace,
    dns_server_ns: DnsServerNamespace,
    service_ns: ServiceNamespace,
}

impl PlannedFacts {
    /// Collect all namespace facts from validated IR.
    ///
    /// This is the "build" phase of the fact graph. It scans all four namespace
    /// domains and checks tag uniqueness for each namespace independently.
    ///
    /// Returns `Err` if duplicate tags are detected in any namespace.
    fn collect(ir: &ConfigIR) -> Result<Self> {
        let outbound_ns = TagNamespace::scan(ir)?;
        let inbound_ns = InboundNamespace::scan(ir)?;
        let dns_server_ns = DnsServerNamespace::scan(ir)?;
        let service_ns = ServiceNamespace::scan(ir)?;

        Ok(Self {
            outbound_ns,
            inbound_ns,
            dns_server_ns,
            service_ns,
        })
    }

    /// Validate all reference facts against the collected namespace inventories.
    ///
    /// This is the "validate" phase of the fact graph. It checks all 11 reference
    /// categories, preserving existing error messages verbatim.
    fn validate(&self, ir: &ConfigIR) -> Result<()> {
        // ── WP-30l first-cut: outbound reference checks ──
        self.check_selector_members(ir)?;
        self.check_rule_outbounds(ir)?;
        self.check_route_default(ir)?;

        // ── WP-30m second-cut: cross-namespace reference checks ──
        self.check_dns_server_detour(ir)?;
        self.check_dns_server_address_resolver(ir)?;
        self.check_dns_server_service(ir)?;
        self.check_service_detour(ir)?;

        // ── WP-30n third-cut: DNS server tag references ──
        self.check_dns_rule_server(ir)?;
        self.check_dns_default(ir)?;
        self.check_dns_final_server(ir)?;

        Ok(())
    }

    // ── Reference validation methods ──

    /// Validate selector/urltest member references.
    fn check_selector_members(&self, ir: &ConfigIR) -> Result<()> {
        for ob in &ir.outbounds {
            if matches!(ob.ty, OutboundType::Selector | OutboundType::UrlTest) {
                if let Some(members) = &ob.members {
                    for member in members {
                        if !self.outbound_ns.contains(member) {
                            return Err(anyhow!(
                                "outbound '{}': member '{}' not found",
                                ob.name.as_deref().unwrap_or("unnamed"),
                                member
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate route rule outbound references.
    fn check_rule_outbounds(&self, ir: &ConfigIR) -> Result<()> {
        for r in &ir.route.rules {
            if let Some(outbound) = &r.outbound {
                if !self.outbound_ns.contains(outbound) {
                    return Err(anyhow!("rule outbound not found: {}", outbound));
                }
            }
        }
        Ok(())
    }

    /// Validate `route.default` reference.
    fn check_route_default(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(def) = &ir.route.default {
            if !self.outbound_ns.contains(def) {
                return Err(anyhow!("default_outbound not found in outbounds: {}", def));
            }
        }
        Ok(())
    }

    /// Check `DnsServerIR.detour` → outbound/endpoint shared tag namespace.
    fn check_dns_server_detour(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(dns) = &ir.dns {
            for srv in &dns.servers {
                if let Some(detour) = &srv.detour {
                    if !detour.is_empty() && !self.outbound_ns.contains(detour) {
                        return Err(anyhow!(
                            "dns server '{}': detour '{}' not found in outbounds",
                            srv.tag,
                            detour
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Check `DnsServerIR.address_resolver` → DNS server tag namespace.
    fn check_dns_server_address_resolver(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(dns) = &ir.dns {
            for srv in &dns.servers {
                if let Some(resolver) = &srv.address_resolver {
                    if !resolver.is_empty() && !self.dns_server_ns.contains(resolver) {
                        return Err(anyhow!(
                            "dns server '{}': address_resolver '{}' not found in dns servers",
                            srv.tag,
                            resolver
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Check `DnsServerIR.service` → service tag namespace.
    fn check_dns_server_service(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(dns) = &ir.dns {
            for srv in &dns.servers {
                if let Some(service) = &srv.service {
                    if !service.is_empty() && !self.service_ns.contains(service) {
                        return Err(anyhow!(
                            "dns server '{}': service '{}' not found in services",
                            srv.tag,
                            service
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Check `ServiceIR.detour` → inbound tag namespace.
    fn check_service_detour(&self, ir: &ConfigIR) -> Result<()> {
        for svc in &ir.services {
            if let Some(detour) = &svc.detour {
                if !detour.is_empty() && !self.inbound_ns.contains(detour) {
                    return Err(anyhow!(
                        "service '{}': detour '{}' not found in inbounds",
                        svc.tag.as_deref().unwrap_or("unnamed"),
                        detour
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check `DnsRuleIR.server` → DNS server tag namespace.
    fn check_dns_rule_server(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(dns) = &ir.dns {
            for rule in &dns.rules {
                if let Some(server) = &rule.server {
                    if !server.is_empty() && !self.dns_server_ns.contains(server) {
                        return Err(anyhow!(
                            "dns rule: server '{}' not found in dns servers",
                            server
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Check `DnsIR.default` → DNS server tag namespace.
    fn check_dns_default(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(dns) = &ir.dns {
            if let Some(default) = &dns.default {
                if !default.is_empty() && !self.dns_server_ns.contains(default) {
                    return Err(anyhow!(
                        "dns: default server '{}' not found in dns servers",
                        default
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check `DnsIR.final_server` → DNS server tag namespace.
    fn check_dns_final_server(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(dns) = &ir.dns {
            if let Some(final_srv) = &dns.final_server {
                if !final_srv.is_empty() && !self.dns_server_ns.contains(final_srv) {
                    return Err(anyhow!(
                        "dns: final server '{}' not found in dns servers",
                        final_srv
                    ));
                }
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public(crate) entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Run the full planned fact graph validation on validated IR.
///
/// This is the single crate-private entry point for `Config::validate()`.
/// It replaces the previous two-step `validate_outbound_references()` +
/// `validate_cross_references()` pattern with a unified collect-then-validate
/// approach via `PlannedFacts`.
///
/// The collect phase checks tag uniqueness for all four namespaces:
///   - outbound/endpoint shared namespace
///   - inbound namespace (WP-30p)
///   - DNS server namespace (WP-30q)
///   - service namespace (WP-30q)
///
/// The validate phase checks all 11 reference categories:
///   1) outbound/endpoint shared tag namespace uniqueness (collect phase)
///   2) selector/urltest member reference existence
///   3) route rule outbound reference existence
///   4) route.default reference existence
///   5) `DnsServerIR.detour` → outbound/endpoint shared tag namespace
///   6) `DnsServerIR.address_resolver` → DNS server tag namespace
///   7) `DnsServerIR.service` → service tag namespace
///   8) `ServiceIR.detour` → inbound tag namespace
///   9) `DnsRuleIR.server` → DNS server tag namespace
///  10) `DnsIR.default` → DNS server tag namespace
///  11) `DnsIR.final_server` → DNS server tag namespace
pub(crate) fn collect_planned_facts(ir: &ConfigIR) -> Result<PlannedFacts> {
    PlannedFacts::collect(ir)
}

/// Validate validated IR against a previously collected planned fact graph.
///
/// This is intentionally exact and staged, not a generic query API.
pub(crate) fn validate_with_planned_facts(facts: &PlannedFacts, ir: &ConfigIR) -> Result<()> {
    facts.validate(ir)
}

pub(crate) fn validate_planned_facts(ir: &ConfigIR) -> Result<()> {
    let facts = collect_planned_facts(ir)?;
    validate_with_planned_facts(&facts, ir)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal ConfigIR with given outbound names.
    fn ir_with_outbounds(names: &[&str]) -> ConfigIR {
        use super::super::outbound::OutboundIR;
        let mut ir = ConfigIR::default();
        for name in names {
            ir.outbounds.push(OutboundIR {
                name: Some(name.to_string()),
                ..Default::default()
            });
        }
        ir
    }

    /// Helper: build a minimal EndpointIR with a given tag.
    fn make_endpoint(tag: &str) -> super::super::endpoint::EndpointIR {
        use super::super::endpoint::{EndpointIR, EndpointType};
        EndpointIR {
            ty: EndpointType::Wireguard,
            tag: Some(tag.to_string()),
            network: None,
            wireguard_system: None,
            wireguard_name: None,
            wireguard_mtu: None,
            wireguard_address: None,
            wireguard_private_key: None,
            wireguard_listen_port: None,
            wireguard_peers: None,
            wireguard_udp_timeout: None,
            wireguard_workers: None,
            tailscale_state_directory: None,
            tailscale_auth_key: None,
            tailscale_control_url: None,
            tailscale_ephemeral: None,
            tailscale_hostname: None,
            tailscale_accept_routes: None,
            tailscale_exit_node: None,
            tailscale_exit_node_allow_lan_access: None,
            tailscale_advertise_routes: None,
            tailscale_advertise_exit_node: None,
            tailscale_udp_timeout: None,
        }
    }

    /// DNS server spec for test helper.
    struct DnsSpec {
        tag: &'static str,
        detour: Option<&'static str>,
        address_resolver: Option<&'static str>,
        service: Option<&'static str>,
    }

    impl DnsSpec {
        fn new(tag: &'static str) -> Self {
            Self {
                tag,
                detour: None,
                address_resolver: None,
                service: None,
            }
        }
        fn detour(mut self, d: &'static str) -> Self {
            self.detour = Some(d);
            self
        }
        fn resolver(mut self, r: &'static str) -> Self {
            self.address_resolver = Some(r);
            self
        }
        fn service(mut self, s: &'static str) -> Self {
            self.service = Some(s);
            self
        }
    }

    /// Helper: build a ConfigIR with DNS servers.
    fn ir_with_dns_servers(specs: &[DnsSpec]) -> ConfigIR {
        use super::super::dns::{DnsIR, DnsServerIR};
        let mut ir = ConfigIR::default();
        let mut dns = DnsIR::default();
        for spec in specs {
            dns.servers.push(DnsServerIR {
                tag: spec.tag.to_string(),
                address: "udp://8.8.8.8".to_string(),
                detour: spec.detour.map(String::from),
                address_resolver: spec.address_resolver.map(String::from),
                service: spec.service.map(String::from),
                ..Default::default()
            });
        }
        ir.dns = Some(dns);
        ir
    }

    /// Helper: add inbounds to IR.
    fn add_inbounds(ir: &mut ConfigIR, tags: &[&str]) {
        use super::super::inbound::{InboundIR, InboundType};
        for tag in tags {
            ir.inbounds.push(InboundIR {
                tag: Some(tag.to_string()),
                ty: InboundType::Mixed,
                listen: "127.0.0.1".to_string(),
                port: 1080,
                ..Default::default()
            });
        }
    }

    /// Helper: add services to IR.
    fn add_services(ir: &mut ConfigIR, tags: &[&str]) {
        use super::super::service::{ServiceIR, ServiceType};
        for tag in tags {
            ir.services.push(ServiceIR {
                ty: ServiceType::Resolved,
                tag: Some(tag.to_string()),
                ..Default::default()
            });
        }
    }

    /// Helper: add DNS rules with given server references.
    fn add_dns_rules(ir: &mut ConfigIR, servers: &[Option<&str>]) {
        use super::super::dns::DnsRuleIR;
        let dns = ir.dns.get_or_insert_with(Default::default);
        for srv in servers {
            dns.rules.push(DnsRuleIR {
                server: srv.map(String::from),
                ..Default::default()
            });
        }
    }

    // ── Fact graph construction tests ──

    #[test]
    fn fact_graph_collect_happy_path() {
        // Build a multi-namespace config and verify PlannedFacts collects successfully.
        let mut ir = ir_with_outbounds(&["direct", "proxy"]);
        add_inbounds(&mut ir, &["mixed-in"]);
        add_services(&mut ir, &["resolved-svc"]);
        ir.dns = ir_with_dns_servers(&[DnsSpec::new("dns1")]).dns;

        let facts = PlannedFacts::collect(&ir).unwrap();
        assert!(facts.outbound_ns.contains("direct"));
        assert!(facts.outbound_ns.contains("proxy"));
        assert!(facts.inbound_ns.contains("mixed-in"));
        assert!(facts.dns_server_ns.contains("dns1"));
        assert!(facts.service_ns.contains("resolved-svc"));
    }

    #[test]
    fn fact_graph_collect_with_endpoints() {
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.endpoints.push(make_endpoint("wg-ep"));
        let facts = PlannedFacts::collect(&ir).unwrap();
        assert!(facts.outbound_ns.contains("direct"));
        assert!(facts.outbound_ns.contains("wg-ep"));
    }

    #[test]
    fn fact_graph_collect_duplicate_inbound_rejected() {
        let mut ir = ConfigIR::default();
        add_inbounds(&mut ir, &["dup-ib"]);
        add_inbounds(&mut ir, &["dup-ib"]);
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert!(
            err.to_string().contains("duplicate inbound tag: dup-ib"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn fact_graph_collect_duplicate_outbound_rejected() {
        let ir = ir_with_outbounds(&["dup", "dup"]);
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate outbound/endpoint tag: dup"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn fact_graph_collect_duplicate_endpoint_rejected() {
        let mut ir = ir_with_outbounds(&["shared"]);
        ir.endpoints.push(make_endpoint("shared"));
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate outbound/endpoint tag: shared"),
            "error message must match existing format: {}",
            err
        );
    }

    // ── Fact graph validation tests: outbound references (WP-30l) ──

    #[test]
    fn fact_graph_valid_selector_members() {
        use super::super::outbound::OutboundIR;
        let mut ir = ir_with_outbounds(&["direct", "proxy"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("select".to_string()),
            members: Some(vec!["direct".to_string(), "proxy".to_string()]),
            ..Default::default()
        });

        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_missing_selector_member_rejected() {
        use super::super::outbound::OutboundIR;
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("select".to_string()),
            members: Some(vec!["direct".to_string(), "missing".to_string()]),
            ..Default::default()
        });

        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("outbound 'select': member 'missing' not found"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn fact_graph_missing_rule_outbound_rejected() {
        use super::super::route::RuleIR;
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.route.rules.push(RuleIR {
            outbound: Some("nonexistent".to_string()),
            ..Default::default()
        });

        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("rule outbound not found: nonexistent"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn fact_graph_missing_route_default_rejected() {
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.route.default = Some("missing".to_string());

        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("default_outbound not found in outbounds: missing"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn fact_graph_full_outbound_happy_path() {
        use super::super::outbound::OutboundIR;
        use super::super::route::RuleIR;

        let mut ir = ir_with_outbounds(&["direct", "proxy"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("select".to_string()),
            members: Some(vec!["direct".to_string(), "proxy".to_string()]),
            ..Default::default()
        });
        ir.route.rules.push(RuleIR {
            outbound: Some("proxy".to_string()),
            ..Default::default()
        });
        ir.route.default = Some("direct".to_string());

        assert!(validate_planned_facts(&ir).is_ok());
    }

    // ── Fact graph validation tests: cross-references (WP-30m) ──

    #[test]
    fn fact_graph_dns_detour_missing_outbound_rejected() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("missing-outbound")]);
        ir.outbounds = ir_with_outbounds(&["direct"]).outbounds;
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns server 'dns1': detour 'missing-outbound' not found in outbounds"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_dns_detour_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("direct")]);
        ir.outbounds = ir_with_outbounds(&["direct"]).outbounds;
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_address_resolver_missing_rejected() {
        let ir = ir_with_dns_servers(&[
            DnsSpec::new("dns1").resolver("nonexistent-dns"),
            DnsSpec::new("local"),
        ]);
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string().contains(
                "dns server 'dns1': address_resolver 'nonexistent-dns' not found in dns servers"
            ),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_dns_address_resolver_valid_passes() {
        let ir = ir_with_dns_servers(&[
            DnsSpec::new("dns1").resolver("local"),
            DnsSpec::new("local"),
        ]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_service_missing_rejected() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns1").service("missing-svc")]);
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns server 'dns1': service 'missing-svc' not found in services"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_dns_service_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").service("resolved")]);
        add_services(&mut ir, &["resolved"]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_service_detour_missing_inbound_rejected() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some("missing-inbound".to_string());
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("service 'svc1': detour 'missing-inbound' not found in inbounds"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_service_detour_valid_passes() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some("mixed-in".to_string());
        add_inbounds(&mut ir, &["mixed-in"]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_cross_reference_empty_string_ignored() {
        let mut ir =
            ir_with_dns_servers(&[DnsSpec::new("dns1").detour("").resolver("").service("")]);
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some(String::new());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_cross_reference_none_ignored() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns1")]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    // ── Fact graph validation tests: DNS server tag references (WP-30n) ──

    #[test]
    fn fact_graph_dns_rule_server_missing_rejected() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google"), DnsSpec::new("local")]);
        add_dns_rules(&mut ir, &[Some("nonexistent-dns")]);
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns rule: server 'nonexistent-dns' not found in dns servers"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_dns_rule_server_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google"), DnsSpec::new("local")]);
        add_dns_rules(&mut ir, &[Some("google"), Some("local")]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_rule_server_none_ignored() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        add_dns_rules(&mut ir, &[None]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_rule_server_empty_string_ignored() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        add_dns_rules(&mut ir, &[Some("")]);
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_default_missing_rejected() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        ir.dns.as_mut().unwrap().default = Some("ghost-default".to_string());
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns: default server 'ghost-default' not found in dns servers"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_dns_default_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        ir.dns.as_mut().unwrap().default = Some("google".to_string());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_default_none_ignored() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        assert!(ir.dns.as_ref().unwrap().default.is_none());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_default_empty_string_ignored() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        ir.dns.as_mut().unwrap().default = Some(String::new());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_final_server_missing_rejected() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        ir.dns.as_mut().unwrap().final_server = Some("ghost-final".to_string());
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns: final server 'ghost-final' not found in dns servers"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn fact_graph_dns_final_server_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google"), DnsSpec::new("fallback")]);
        ir.dns.as_mut().unwrap().final_server = Some("fallback".to_string());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_final_server_none_ignored() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        assert!(ir.dns.as_ref().unwrap().final_server.is_none());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn fact_graph_dns_final_server_empty_string_ignored() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("google")]);
        ir.dns.as_mut().unwrap().final_server = Some(String::new());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    // ── Combined multi-namespace tests ──

    #[test]
    fn fact_graph_combined_valid_multi_namespace_config() {
        let mut ir = ir_with_dns_servers(&[
            DnsSpec::new("google").detour("proxy").resolver("local"),
            DnsSpec::new("local").service("resolved-svc"),
            DnsSpec::new("fallback"),
        ]);
        ir.outbounds = ir_with_outbounds(&["direct", "proxy"]).outbounds;
        add_inbounds(&mut ir, &["mixed-in"]);
        add_services(&mut ir, &["resolved-svc"]);
        ir.services[0].detour = Some("mixed-in".to_string());
        add_dns_rules(&mut ir, &[Some("google"), Some("local")]);
        ir.dns.as_mut().unwrap().default = Some("google".to_string());
        ir.dns.as_mut().unwrap().final_server = Some("fallback".to_string());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    // ── Fact graph collect tests: DNS server tag uniqueness (WP-30q) ──

    #[test]
    fn fact_graph_collect_duplicate_dns_server_rejected() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dup-dns"), DnsSpec::new("dup-dns")]);
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate dns server tag: dup-dns",
            "error message must be stable"
        );
    }

    #[test]
    fn fact_graph_collect_distinct_dns_servers_pass() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns-a"), DnsSpec::new("dns-b")]);
        assert!(PlannedFacts::collect(&ir).is_ok());
    }

    #[test]
    fn fact_graph_collect_empty_dns_tag_not_checked() {
        // Empty tags are silently skipped, not treated as duplicates.
        use super::super::dns::{DnsIR, DnsServerIR};
        let mut ir = ConfigIR::default();
        let mut dns = DnsIR::default();
        dns.servers.push(DnsServerIR {
            tag: String::new(),
            address: "udp://8.8.8.8".to_string(),
            ..Default::default()
        });
        dns.servers.push(DnsServerIR {
            tag: String::new(),
            address: "udp://1.1.1.1".to_string(),
            ..Default::default()
        });
        ir.dns = Some(dns);
        assert!(PlannedFacts::collect(&ir).is_ok());
    }

    // ── Fact graph collect tests: service tag uniqueness (WP-30q) ──

    #[test]
    fn fact_graph_collect_duplicate_service_rejected() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["dup-svc"]);
        add_services(&mut ir, &["dup-svc"]);
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate service tag: dup-svc",
            "error message must be stable"
        );
    }

    #[test]
    fn fact_graph_collect_distinct_services_pass() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["svc-a", "svc-b"]);
        assert!(PlannedFacts::collect(&ir).is_ok());
    }

    #[test]
    fn fact_graph_collect_empty_service_tag_not_checked() {
        use super::super::service::{ServiceIR, ServiceType};
        let mut ir = ConfigIR::default();
        ir.services.push(ServiceIR {
            ty: ServiceType::Resolved,
            tag: Some(String::new()),
            ..Default::default()
        });
        ir.services.push(ServiceIR {
            ty: ServiceType::Resolved,
            tag: Some(String::new()),
            ..Default::default()
        });
        assert!(PlannedFacts::collect(&ir).is_ok());
    }

    #[test]
    fn fact_graph_collect_none_service_tag_not_checked() {
        use super::super::service::{ServiceIR, ServiceType};
        let mut ir = ConfigIR::default();
        ir.services.push(ServiceIR {
            ty: ServiceType::Resolved,
            tag: None,
            ..Default::default()
        });
        ir.services.push(ServiceIR {
            ty: ServiceType::Resolved,
            tag: None,
            ..Default::default()
        });
        assert!(PlannedFacts::collect(&ir).is_ok());
    }

    // ── Pin tests: confirm current ownership ──

    /// Pin: `PlannedFacts` is the current owner of the planned fact graph seam.
    /// Tag namespace uniqueness + reference validation are now unified under
    /// `PlannedFacts::collect()` + `PlannedFacts::validate()`.
    #[test]
    fn planned_pin_fact_graph_owns_tag_namespace() {
        let ir = ir_with_outbounds(&["dup", "dup"]);
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string().contains("duplicate outbound/endpoint tag"),
            "tag namespace check must be owned by planned fact graph"
        );
    }

    /// Pin: `PlannedFacts` is the current owner of selector/urltest member
    /// existence checks via the fact graph.
    #[test]
    fn planned_pin_fact_graph_owns_member_refs() {
        use super::super::outbound::OutboundIR;
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::UrlTest,
            name: Some("auto".to_string()),
            members: Some(vec!["ghost".to_string()]),
            ..Default::default()
        });

        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string().contains("member 'ghost' not found"),
            "member reference check must be owned by planned fact graph"
        );
    }

    /// Pin: `PlannedFacts` is the current owner of DNS/service cross-reference
    /// checks via the fact graph.
    #[test]
    fn planned_pin_fact_graph_owns_cross_refs() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("ghost-outbound")]);
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("detour 'ghost-outbound' not found"),
            "dns detour cross-reference check must be owned by planned fact graph"
        );
    }

    /// Pin: `PlannedFacts` owns DNS rule server + DnsIR.default/final_server
    /// reference checks via the fact graph.
    #[test]
    fn planned_pin_fact_graph_owns_dns_server_refs() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1")]);
        add_dns_rules(&mut ir, &[Some("phantom-dns")]);
        let err = validate_planned_facts(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("server 'phantom-dns' not found in dns servers"),
            "dns rule server reference check must be owned by planned fact graph"
        );
    }

    /// Pin: runtime-facing DNS env bridge is NOT in planned.rs — it still lives
    /// in `app::run_engine::apply_dns_env_from_config()`. This test confirms
    /// that planned.rs only does reference existence checks, not env binding.
    #[test]
    fn planned_pin_dns_env_bridge_not_in_planned() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("direct")]);
        ir.outbounds = ir_with_outbounds(&["direct"]).outbounds;
        assert!(
            validate_planned_facts(&ir).is_ok(),
            "planned.rs must not attempt DNS env binding — that stays in run_engine"
        );
    }

    #[test]
    fn wp30ar_pin_planned_dns_scope_remains_reference_only() {
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ir/planned.rs"))
                .expect("planned.rs source should be readable");
        assert!(source.contains("DnsServerIR.detour"));
        assert!(source.contains("DnsServerIR.address_resolver"));
        assert!(source.contains("DnsServerIR.service"));
        assert!(source.contains("DnsRuleIR.server"));
        assert!(source.contains("DnsIR.default"));
        assert!(source.contains("DnsIR.final_server"));
        assert!(source.contains("No runtime-facing DNS env bridge"));
        assert!(
            source.contains("not** a public `RuntimePlan`")
                || source.contains("not a public `RuntimePlan`"),
            "planned.rs should keep documenting that this seam is not a public RuntimePlan"
        );
    }

    /// Pin (WP-30p): inbound tag uniqueness IS now owned by the planned fact
    /// graph. `PlannedFacts::collect()` checks inbound uniqueness during the
    /// scan phase, rejecting duplicate inbound tags with the same error message
    /// that `Config::validate()` previously produced.
    #[test]
    fn planned_pin_fact_graph_owns_inbound_uniqueness() {
        let mut ir = ConfigIR::default();
        add_inbounds(&mut ir, &["dup-ib"]);
        add_inbounds(&mut ir, &["dup-ib"]);
        // PlannedFacts.collect() must now reject duplicate inbound tags
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate inbound tag: dup-ib",
            "inbound uniqueness must be owned by planned fact graph (WP-30p)"
        );
    }

    /// Pin (WP-30p): `Config::validate()` is now a thin entry point — it no
    /// longer holds the inbound tag uniqueness rule itself. The rule lives in
    /// `PlannedFacts::collect()`.
    #[test]
    fn planned_pin_validate_is_thin_entry_point() {
        // A valid config should pass through the thin entry point
        let mut ir = ir_with_outbounds(&["direct"]);
        add_inbounds(&mut ir, &["mixed-in"]);
        let facts = PlannedFacts::collect(&ir).unwrap();
        assert!(
            facts.validate(&ir).is_ok(),
            "Config::validate() delegates entirely to planned fact graph"
        );
    }

    /// Pin: inbound and outbound/endpoint are independent namespaces —
    /// the same tag string appearing in both is allowed (Go parity).
    #[test]
    fn planned_pin_inbound_outbound_independent_namespaces() {
        let mut ir = ir_with_outbounds(&["shared-tag"]);
        add_inbounds(&mut ir, &["shared-tag"]);
        // Both namespaces contain "shared-tag" — this must be allowed
        assert!(
            validate_planned_facts(&ir).is_ok(),
            "inbound and outbound namespaces must be independent"
        );
    }

    /// Pin (WP-30q): DNS server tag uniqueness IS now owned by the planned fact
    /// graph. `PlannedFacts::collect()` checks DNS server uniqueness during the
    /// scan phase, rejecting duplicate DNS server tags.
    #[test]
    fn planned_pin_fact_graph_owns_dns_server_uniqueness() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dup-dns"), DnsSpec::new("dup-dns")]);
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate dns server tag: dup-dns",
            "dns server uniqueness must be owned by planned fact graph (WP-30q)"
        );
    }

    /// Pin (WP-30q): service tag uniqueness IS now owned by the planned fact
    /// graph. `PlannedFacts::collect()` checks service uniqueness during the
    /// scan phase, rejecting duplicate service tags.
    #[test]
    fn planned_pin_fact_graph_owns_service_uniqueness() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["dup-svc"]);
        add_services(&mut ir, &["dup-svc"]);
        let err = PlannedFacts::collect(&ir).unwrap_err();
        assert_eq!(
            err.to_string(),
            "duplicate service tag: dup-svc",
            "service uniqueness must be owned by planned fact graph (WP-30q)"
        );
    }

    #[test]
    fn wp30as_pin_staged_private_facade_matches_orchestration_entry() {
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.dns = ir_with_dns_servers(&[
            DnsSpec::new("dns-main").detour("direct"),
            DnsSpec::new("dns-bootstrap"),
        ])
        .dns;
        let facts = collect_planned_facts(&ir).unwrap();
        assert!(validate_with_planned_facts(&facts, &ir).is_ok());
        assert!(validate_planned_facts(&ir).is_ok());
    }

    #[test]
    fn wp30as_pin_staged_collect_error_surface_is_stable() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dup-dns"), DnsSpec::new("dup-dns")]);
        let err = collect_planned_facts(&ir).unwrap_err();
        assert_eq!(err.to_string(), "duplicate dns server tag: dup-dns");
    }

    #[test]
    fn wp30as_pin_private_staged_seam_not_reexported_or_generalized() {
        let planned = include_str!("planned.rs");
        let ir_mod = include_str!("mod.rs");
        let lib = include_str!("../lib.rs");

        assert!(planned.contains("collect_planned_facts(&ConfigIR) -> Result<PlannedFacts>"));
        assert!(planned.contains("validate_with_planned_facts(&PlannedFacts, &ConfigIR)"));
        assert!(planned.contains("No crate-internal namespace query API"));
        assert!(planned.contains("No exact private accessors yet"));
        assert!(ir_mod.contains("pub(crate) mod planned;"));
        assert!(!ir_mod.contains("pub use planned::PlannedFacts"));
        assert!(!ir_mod.contains("pub use planned::collect_planned_facts"));
        assert!(!ir_mod.contains("pub use planned::validate_with_planned_facts"));
        assert!(!lib.contains("pub use crate::ir::planned::PlannedFacts"));
    }

    #[test]
    fn wp30as_pin_non_consumers_stay_outside_planned_owner_boundary() {
        let ir_normalize = include_str!("normalize.rs");
        let ir_minimize = include_str!("minimize.rs");
        let present = include_str!("../present.rs");
        let runtime_groups = include_str!("../../../../app/src/outbound_groups.rs");
        let runtime_router = include_str!("../../../../app/src/router_text.rs");
        let runtime_dns_env = include_str!("../../../../app/src/dns_env.rs");
        let runtime_run_engine = include_str!("../../../../app/src/run_engine.rs");

        assert!(ir_normalize.contains("does **not** touch planned-layer references"));
        assert!(ir_minimize.contains("Not a planning-layer owner"));
        assert!(present.contains("projection layer"));
        assert!(present.contains("not a planned consumer owner"));
        assert!(runtime_groups.contains("not a planned consumer owner"));
        assert!(runtime_router.contains("runtime concern"));
        assert!(runtime_dns_env.contains("Runtime-facing DNS environment bridge"));
        assert!(runtime_run_engine.contains("runtime orchestration owners"));
    }
}
