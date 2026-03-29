//! Planning layer — first-cut private inventory seam (WP-30l).
//!
//! ## Purpose
//!
//! This module sits in the future **Planned** position of the config pipeline:
//!
//! ```text
//! Raw → Validated (ConfigIR) → Planned (RuntimePlan) → Runtime owners
//! ```
//!
//! ## Current status (WP-30l)
//!
//! WP-30l implemented a **crate-private** tag/reference inventory seam that
//! `Config::validate()` now delegates to for four categories of post-validated
//! semantic checks:
//!
//! 1. Outbound/endpoint shared tag namespace uniqueness
//! 2. Selector/URLTest member reference existence
//! 3. Route rule outbound reference existence
//! 4. `route.default` reference existence
//!
//! This is intentionally the first-cut private seam — **not** a public
//! `RuntimePlan` or `PlannedConfigIR`. The seam:
//!
//! - is `pub(crate)` only, not re-exported through `ir/mod.rs` or `lib.rs`
//! - consumes validated IR (`ConfigIR`) as input
//! - reuses existing error messages verbatim
//! - does not introduce new public types or builder API
//!
//! ## What is NOT yet implemented
//!
//! - No public `RuntimePlan`
//! - No public `PlannedConfigIR`
//! - No public builder/helper entry point
//! - No cross-reference expansion for DNS detour, service detour, address_resolver
//! - No runtime connector binding
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
// Public(crate) entry point: combined inventory check
// ─────────────────────────────────────────────────────────────────────────────

/// Run the full planned-layer tag/reference inventory check on validated IR.
///
/// This is the single entry point that `Config::validate()` calls for the four
/// categories of outbound/endpoint/reference checks. Inbound tag uniqueness is
/// intentionally **not** included here — it stays in `Config::validate()`.
pub(crate) fn validate_outbound_references(ir: &ConfigIR) -> Result<()> {
    let namespace = TagNamespace::scan(ir)?;
    let validator = ReferenceValidator::new(&namespace);
    validator.check_selector_members(ir)?;
    validator.check_rule_outbounds(ir)?;
    validator.check_route_default(ir)?;
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
}
