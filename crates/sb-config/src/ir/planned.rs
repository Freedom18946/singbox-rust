//! Planning layer — private inventory seam (WP-30l first-cut + WP-30m second-cut expansion).
//!
//! ## Purpose
//!
//! This module sits in the future **Planned** position of the config pipeline:
//!
//! ```text
//! Raw → Validated (ConfigIR) → Planned (RuntimePlan) → Runtime owners
//! ```
//!
//! ## Current status (WP-30l + WP-30m)
//!
//! WP-30l implemented a **crate-private** tag/reference inventory seam that
//! `Config::validate()` delegates to for four categories of post-validated
//! semantic checks (first-cut):
//!
//! 1. Outbound/endpoint shared tag namespace uniqueness
//! 2. Selector/URLTest member reference existence
//! 3. Route rule outbound reference existence
//! 4. `route.default` reference existence
//!
//! WP-30m expanded the seam with **multi-namespace cross-reference inventory**
//! (second-cut), adding four more categories:
//!
//! 5. `DnsServerIR.detour` → outbound/endpoint shared tag namespace
//! 6. `DnsServerIR.address_resolver` → DNS server tag namespace
//! 7. `DnsServerIR.service` → service tag namespace
//! 8. `ServiceIR.detour` → inbound tag namespace
//!
//! This is still a crate-private seam — **not** a public `RuntimePlan` or
//! `PlannedConfigIR`. The seam:
//!
//! - is `pub(crate)` only, not re-exported through `ir/mod.rs` or `lib.rs`
//! - consumes validated IR (`ConfigIR`) as input
//! - reuses existing error messages verbatim (WP-30l checks)
//! - does not introduce new public types or builder API
//!
//! ## Namespace domains
//!
//! The seam distinguishes four tag namespaces:
//!
//! 1. **Outbound/endpoint shared** — `OutboundIR.name` + `EndpointIR.tag`
//! 2. **Inbound** — `InboundIR.tag`
//! 3. **DNS server** — `DnsServerIR.tag`
//! 4. **Service** — `ServiceIR.tag`
//!
//! ## What is NOT yet implemented
//!
//! - No public `RuntimePlan`
//! - No public `PlannedConfigIR`
//! - No public builder/helper entry point
//! - No runtime connector binding
//! - No runtime-facing DNS env bridge (still in `app::run_engine`)
//!
//! ## Responsibilities that still stay elsewhere
//!
//! - `Config::validate()` in `lib.rs`: inbound tag uniqueness (intentionally kept
//!   separate — inbound tags use their own namespace, not the outbound/endpoint one)
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
// Tag scan: builds the outbound/endpoint shared tag namespace
// ─────────────────────────────────────────────────────────────────────────────

/// A scanned set of outbound + endpoint tags (shared namespace).
///
/// This is the first half of the planned inventory: it collects every tag that
/// can be referenced by selectors, route rules, or `route.default`.
#[derive(Debug)]
pub(crate) struct TagNamespace {
    tags: HashSet<String>,
}

impl TagNamespace {
    /// Scan outbound and endpoint tags from validated IR.
    ///
    /// Returns `Err` on the first duplicate tag encountered (preserving the
    /// exact error message that `Config::validate()` has always produced).
    pub(crate) fn scan(ir: &ConfigIR) -> Result<Self> {
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

    /// Check whether a given tag exists in the namespace.
    fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional namespace scans (WP-30m): inbound, DNS server, service
// ─────────────────────────────────────────────────────────────────────────────

/// A scanned set of inbound tags.
#[derive(Debug)]
pub(crate) struct InboundNamespace {
    tags: HashSet<String>,
}

impl InboundNamespace {
    /// Scan inbound tags from validated IR (no uniqueness check here —
    /// that responsibility stays in `Config::validate()` in lib.rs).
    pub(crate) fn scan(ir: &ConfigIR) -> Self {
        let mut tags = HashSet::new();
        for ib in &ir.inbounds {
            if let Some(tag) = &ib.tag {
                if !tag.is_empty() {
                    tags.insert(tag.clone());
                }
            }
        }
        Self { tags }
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
    /// Scan DNS server tags from validated IR.
    pub(crate) fn scan(ir: &ConfigIR) -> Self {
        let mut tags = HashSet::new();
        if let Some(dns) = &ir.dns {
            for srv in &dns.servers {
                if !srv.tag.is_empty() {
                    tags.insert(srv.tag.clone());
                }
            }
        }
        Self { tags }
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
    /// Scan service tags from validated IR.
    pub(crate) fn scan(ir: &ConfigIR) -> Self {
        let mut tags = HashSet::new();
        for svc in &ir.services {
            if let Some(tag) = &svc.tag {
                if !tag.is_empty() {
                    tags.insert(tag.clone());
                }
            }
        }
        Self { tags }
    }

    fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reference scan: validates that all cross-references resolve to known tags
// ─────────────────────────────────────────────────────────────────────────────

/// Validates outbound-tag references from selectors, route rules, and
/// `route.default` against a previously scanned [`TagNamespace`].
///
/// This is the second half of the planned inventory: given a known set of
/// tags, it checks every reference site for existence.
pub(crate) struct ReferenceValidator<'a> {
    namespace: &'a TagNamespace,
}

impl<'a> ReferenceValidator<'a> {
    pub(crate) fn new(namespace: &'a TagNamespace) -> Self {
        Self { namespace }
    }

    /// Validate selector/urltest member references.
    pub(crate) fn check_selector_members(&self, ir: &ConfigIR) -> Result<()> {
        for ob in &ir.outbounds {
            if matches!(ob.ty, OutboundType::Selector | OutboundType::UrlTest) {
                if let Some(members) = &ob.members {
                    for member in members {
                        if !self.namespace.contains(member) {
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
    pub(crate) fn check_rule_outbounds(&self, ir: &ConfigIR) -> Result<()> {
        for r in &ir.route.rules {
            if let Some(outbound) = &r.outbound {
                if !self.namespace.contains(outbound) {
                    return Err(anyhow!("rule outbound not found: {}", outbound));
                }
            }
        }
        Ok(())
    }

    /// Validate `route.default` reference.
    pub(crate) fn check_route_default(&self, ir: &ConfigIR) -> Result<()> {
        if let Some(def) = &ir.route.default {
            if !self.namespace.contains(def) {
                return Err(anyhow!("default_outbound not found in outbounds: {}", def));
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-reference validation (WP-30m): DNS/service detour references
// ─────────────────────────────────────────────────────────────────────────────

/// Validates cross-namespace references from DNS servers and services against
/// their respective target namespaces.
///
/// WP-30m second-cut: four new reference checks that span different tag domains.
pub(crate) struct CrossReferenceValidator<'a> {
    outbound_ns: &'a TagNamespace,
    dns_server_ns: &'a DnsServerNamespace,
    service_ns: &'a ServiceNamespace,
    inbound_ns: &'a InboundNamespace,
}

impl<'a> CrossReferenceValidator<'a> {
    pub(crate) fn new(
        outbound_ns: &'a TagNamespace,
        dns_server_ns: &'a DnsServerNamespace,
        service_ns: &'a ServiceNamespace,
        inbound_ns: &'a InboundNamespace,
    ) -> Self {
        Self {
            outbound_ns,
            dns_server_ns,
            service_ns,
            inbound_ns,
        }
    }

    /// Check `DnsServerIR.detour` → outbound/endpoint shared tag namespace.
    pub(crate) fn check_dns_server_detour(&self, ir: &ConfigIR) -> Result<()> {
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
    pub(crate) fn check_dns_server_address_resolver(&self, ir: &ConfigIR) -> Result<()> {
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
    pub(crate) fn check_dns_server_service(&self, ir: &ConfigIR) -> Result<()> {
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
    pub(crate) fn check_service_detour(&self, ir: &ConfigIR) -> Result<()> {
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
}

// ─────────────────────────────────────────────────────────────────────────────
// Public(crate) entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Run the WP-30l outbound/endpoint tag/reference inventory check on validated IR.
///
/// This covers the first-cut four categories:
///   1) outbound/endpoint shared tag namespace uniqueness
///   2) selector/urltest member reference existence
///   3) route rule outbound reference existence
///   4) route.default reference existence
///
/// Inbound tag uniqueness is intentionally **not** included here — it stays
/// in `Config::validate()`.
pub(crate) fn validate_outbound_references(ir: &ConfigIR) -> Result<()> {
    let namespace = TagNamespace::scan(ir)?;
    let validator = ReferenceValidator::new(&namespace);
    validator.check_selector_members(ir)?;
    validator.check_rule_outbounds(ir)?;
    validator.check_route_default(ir)?;
    Ok(())
}

/// Run the WP-30m cross-reference inventory check on validated IR.
///
/// This covers the second-cut four categories:
///   5) `DnsServerIR.detour` → outbound/endpoint shared tag namespace
///   6) `DnsServerIR.address_resolver` → DNS server tag namespace
///   7) `DnsServerIR.service` → service tag namespace
///   8) `ServiceIR.detour` → inbound tag namespace
///
/// This must be called **after** `validate_outbound_references` so that the
/// outbound/endpoint tag namespace is already known to be duplicate-free.
pub(crate) fn validate_cross_references(ir: &ConfigIR) -> Result<()> {
    let outbound_ns = TagNamespace::scan(ir)?;
    let dns_server_ns = DnsServerNamespace::scan(ir);
    let service_ns = ServiceNamespace::scan(ir);
    let inbound_ns = InboundNamespace::scan(ir);

    let validator =
        CrossReferenceValidator::new(&outbound_ns, &dns_server_ns, &service_ns, &inbound_ns);
    validator.check_dns_server_detour(ir)?;
    validator.check_dns_server_address_resolver(ir)?;
    validator.check_dns_server_service(ir)?;
    validator.check_service_detour(ir)?;
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

    #[test]
    fn tag_namespace_scan_unique() {
        let ir = ir_with_outbounds(&["a", "b", "c"]);
        let ns = TagNamespace::scan(&ir).unwrap();
        assert!(ns.contains("a"));
        assert!(ns.contains("b"));
        assert!(ns.contains("c"));
        assert!(!ns.contains("d"));
    }

    #[test]
    fn tag_namespace_scan_duplicate_outbound_rejected() {
        let ir = ir_with_outbounds(&["dup", "dup"]);
        let err = TagNamespace::scan(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate outbound/endpoint tag: dup"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn tag_namespace_scan_duplicate_endpoint_rejected() {
        let mut ir = ir_with_outbounds(&["shared"]);
        ir.endpoints.push(make_endpoint("shared"));
        let err = TagNamespace::scan(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate outbound/endpoint tag: shared"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn reference_validator_valid_members() {
        use super::super::outbound::OutboundIR;
        let mut ir = ir_with_outbounds(&["direct", "proxy"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("select".to_string()),
            members: Some(vec!["direct".to_string(), "proxy".to_string()]),
            ..Default::default()
        });

        let ns = TagNamespace::scan(&ir).unwrap();
        let rv = ReferenceValidator::new(&ns);
        assert!(rv.check_selector_members(&ir).is_ok());
    }

    #[test]
    fn reference_validator_missing_member_rejected() {
        use super::super::outbound::OutboundIR;
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("select".to_string()),
            members: Some(vec!["direct".to_string(), "missing".to_string()]),
            ..Default::default()
        });

        let ns = TagNamespace::scan(&ir).unwrap();
        let rv = ReferenceValidator::new(&ns);
        let err = rv.check_selector_members(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("outbound 'select': member 'missing' not found"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn reference_validator_missing_rule_outbound_rejected() {
        use super::super::route::RuleIR;
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.route.rules.push(RuleIR {
            outbound: Some("nonexistent".to_string()),
            ..Default::default()
        });

        let ns = TagNamespace::scan(&ir).unwrap();
        let rv = ReferenceValidator::new(&ns);
        let err = rv.check_rule_outbounds(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("rule outbound not found: nonexistent"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn reference_validator_missing_route_default_rejected() {
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.route.default = Some("missing".to_string());

        let ns = TagNamespace::scan(&ir).unwrap();
        let rv = ReferenceValidator::new(&ns);
        let err = rv.check_route_default(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("default_outbound not found in outbounds: missing"),
            "error message must match existing format: {}",
            err
        );
    }

    #[test]
    fn validate_outbound_references_happy_path() {
        use super::super::outbound::OutboundIR;
        use super::super::route::RuleIR;

        let mut ir = ir_with_outbounds(&["direct", "proxy"]);

        // Add selector referencing existing outbounds
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("select".to_string()),
            members: Some(vec!["direct".to_string(), "proxy".to_string()]),
            ..Default::default()
        });

        // Add rule referencing existing outbound
        ir.route.rules.push(RuleIR {
            outbound: Some("proxy".to_string()),
            ..Default::default()
        });

        // Set route default
        ir.route.default = Some("direct".to_string());

        assert!(validate_outbound_references(&ir).is_ok());
    }

    // ── WP-30m: cross-reference unit tests ──

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

    #[test]
    fn dns_server_detour_missing_outbound_rejected() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("missing-outbound")]);
        ir.outbounds = ir_with_outbounds(&["direct"]).outbounds;
        let err = validate_cross_references(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns server 'dns1': detour 'missing-outbound' not found in outbounds"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn dns_server_detour_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("direct")]);
        ir.outbounds = ir_with_outbounds(&["direct"]).outbounds;
        assert!(validate_cross_references(&ir).is_ok());
    }

    #[test]
    fn dns_server_address_resolver_missing_rejected() {
        let ir = ir_with_dns_servers(&[
            DnsSpec::new("dns1").resolver("nonexistent-dns"),
            DnsSpec::new("local"),
        ]);
        let err = validate_cross_references(&ir).unwrap_err();
        assert!(
            err.to_string().contains(
                "dns server 'dns1': address_resolver 'nonexistent-dns' not found in dns servers"
            ),
            "actual: {}",
            err
        );
    }

    #[test]
    fn dns_server_address_resolver_valid_passes() {
        let ir = ir_with_dns_servers(&[
            DnsSpec::new("dns1").resolver("local"),
            DnsSpec::new("local"),
        ]);
        assert!(validate_cross_references(&ir).is_ok());
    }

    #[test]
    fn dns_server_service_missing_rejected() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns1").service("missing-svc")]);
        let err = validate_cross_references(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("dns server 'dns1': service 'missing-svc' not found in services"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn dns_server_service_valid_passes() {
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").service("resolved")]);
        add_services(&mut ir, &["resolved"]);
        assert!(validate_cross_references(&ir).is_ok());
    }

    #[test]
    fn service_detour_missing_inbound_rejected() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some("missing-inbound".to_string());
        let err = validate_cross_references(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("service 'svc1': detour 'missing-inbound' not found in inbounds"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn service_detour_valid_passes() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some("mixed-in".to_string());
        add_inbounds(&mut ir, &["mixed-in"]);
        assert!(validate_cross_references(&ir).is_ok());
    }

    #[test]
    fn cross_reference_empty_string_ignored() {
        let mut ir =
            ir_with_dns_servers(&[DnsSpec::new("dns1").detour("").resolver("").service("")]);
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some(String::new());
        assert!(validate_cross_references(&ir).is_ok());
    }

    #[test]
    fn cross_reference_none_ignored() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns1")]);
        assert!(validate_cross_references(&ir).is_ok());
    }

    #[test]
    fn cross_reference_combined_valid_config() {
        let mut ir = ir_with_dns_servers(&[
            DnsSpec::new("google").detour("proxy").resolver("local"),
            DnsSpec::new("local").service("resolved-svc"),
        ]);
        ir.outbounds = ir_with_outbounds(&["direct", "proxy"]).outbounds;
        add_inbounds(&mut ir, &["mixed-in"]);
        add_services(&mut ir, &["resolved-svc"]);
        ir.services[0].detour = Some("mixed-in".to_string());
        assert!(validate_cross_references(&ir).is_ok());
    }

    // ── Pin tests: confirm current ownership ──

    /// Pin: `validate_outbound_references` is the current owner of outbound/endpoint
    /// tag namespace checks, delegated from `Config::validate()` as of WP-30l.
    #[test]
    fn planned_pin_tag_namespace_owned_by_planned_seam() {
        // Duplicate outbound tag detection now lives in planned.rs, not lib.rs
        let ir = ir_with_outbounds(&["dup", "dup"]);
        let err = validate_outbound_references(&ir).unwrap_err();
        assert!(
            err.to_string().contains("duplicate outbound/endpoint tag"),
            "tag namespace check must be owned by planned.rs seam"
        );
    }

    /// Pin: `validate_outbound_references` is the current owner of selector/urltest
    /// member existence checks, delegated from `Config::validate()` as of WP-30l.
    #[test]
    fn planned_pin_member_ref_owned_by_planned_seam() {
        use super::super::outbound::OutboundIR;
        let mut ir = ir_with_outbounds(&["direct"]);
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::UrlTest,
            name: Some("auto".to_string()),
            members: Some(vec!["ghost".to_string()]),
            ..Default::default()
        });

        let err = validate_outbound_references(&ir).unwrap_err();
        assert!(
            err.to_string().contains("member 'ghost' not found"),
            "member reference check must be owned by planned.rs seam"
        );
    }

    /// Pin: `validate_cross_references` is the current owner of DNS/service
    /// cross-reference checks, added in WP-30m.
    #[test]
    fn planned_pin_cross_ref_owned_by_planned_seam() {
        let ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("ghost-outbound")]);
        let err = validate_cross_references(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("detour 'ghost-outbound' not found"),
            "dns detour cross-reference check must be owned by planned.rs seam"
        );
    }

    /// Pin: `validate_cross_references` owns service.detour → inbound namespace
    /// check, added in WP-30m.
    #[test]
    fn planned_pin_service_detour_owned_by_planned_seam() {
        let mut ir = ConfigIR::default();
        add_services(&mut ir, &["svc1"]);
        ir.services[0].detour = Some("phantom-inbound".to_string());
        let err = validate_cross_references(&ir).unwrap_err();
        assert!(
            err.to_string()
                .contains("detour 'phantom-inbound' not found in inbounds"),
            "service detour cross-reference check must be owned by planned.rs seam"
        );
    }

    /// Pin: runtime-facing DNS env bridge is NOT in planned.rs — it still lives
    /// in `app::run_engine::apply_dns_env_from_config()`. This test confirms
    /// that planned.rs only does reference existence checks, not env binding.
    #[test]
    fn planned_pin_dns_env_bridge_not_in_planned() {
        // A valid DNS config with detour should pass planned.rs checks —
        // no env variable binding happens here.
        let mut ir = ir_with_dns_servers(&[DnsSpec::new("dns1").detour("direct")]);
        ir.outbounds = ir_with_outbounds(&["direct"]).outbounds;
        assert!(
            validate_cross_references(&ir).is_ok(),
            "planned.rs must not attempt DNS env binding — that stays in run_engine"
        );
    }
}
