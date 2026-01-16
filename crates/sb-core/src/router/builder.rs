use crate::router::{
    decision_intern,
    rules::{CompositeRule, Decision},
    RouterIndex,
};
use sb_config::ir::ConfigIR;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::time::Instant;

/// Build RouterIndex directly from ConfigIR.
/// This replaces the legacy text-based builder for IR configurations,
/// allowing support for complex/logical rules.
pub fn build_index_from_ir(cfg: &ConfigIR) -> Result<Arc<RouterIndex>, String> {
    #[cfg(feature = "metrics")]
    let build_start = Instant::now();

    let exact = HashMap::new();
    let suffix = Vec::new();
    let suffix_map = HashMap::new();
    let port_rules = HashMap::new();
    let port_ranges = Vec::new();
    let transport_tcp: Option<&'static str> = Default::default();
    let transport_udp: Option<&'static str> = Default::default();
    let cidr4 = Vec::new();
    let cidr6 = Vec::new();
    let cidr4_buckets = vec![Vec::new(); 33];
    let cidr6_buckets = vec![Vec::new(); 129];
    let geoip_rules = Vec::new();
    let geosite_rules = Vec::new();
    let wifi_ssid_rules = Vec::new();
    let wifi_bssid_rules = Vec::new();
    let rule_set_rules = Vec::new();
    let process_rules = Vec::new();
    let process_path_rules = Vec::new();
    let protocol_rules = Vec::new();
    let network_rules = Vec::new();
    let source_rules = Vec::new();
    let dest_rules = Vec::new();
    let user_agent_rules = Vec::new();
    let mut composite_rules = Vec::new();

    // Helper for interning decisions (reserved for future use)
    #[allow(dead_code)]
    let _intern = |action: &sb_config::ir::RuleAction,
                   outbound: &Option<String>,
                   override_addr: &Option<String>,
                   override_port: Option<u16>|
     -> &'static str {
        let d = Decision::from_rule_action(
            action,
            outbound.clone(),
            override_addr.clone(),
            override_port,
        );
        decision_intern::intern_decision(d.as_str())
    };

    for rule in &cfg.route.rules {
        // Try to optimize simple rules into specific maps/vecs if possible?
        // For strict parity and to support all new fields properly, we currently
        // put everything into CompositeRule if it's not a special case we want to optimize.
        // However, existing optimized lookups are checked *after* CompositeRule in `engine.rs` usually?
        // Wait, `engine.rs` line 704 iterates `idx.rules`. If matched, returns.
        // THEN it checks `exact`, `suffix` etc IF `idx.rules` was empty?
        // No, `engine.rs`: "If idx.rules.is_empty() { ... }" (Line 720).
        // This means if we have ANY composite rules, the optimized maps are IGNORED in `decide()`!
        // This is a critical observation.
        // If we want to support mixing optimized maps and composite rules, we must change `engine.rs` logic.
        // Or we must put everything into `idx.rules` (CompositeRule).

        // Given that `engine.rs` conditionally checks optimized maps only if `rules` is empty,
        // we have two choices:
        // 1. Modify `engine.rs` to check optimized maps as well (or before/after).
        // 2. Put EVERYTHING in `CompositeRule`.

        // Option 2 is safest for correctness and feature support (Ref: Go implementation uses list of rules).
        // So we will convert ALL RuleIR to CompositeRule.

        match CompositeRule::try_from(rule) {
            Ok(c) => composite_rules.push(c),
            Err(e) => return Err(format!("Failed to build rule: {}", e)),
        }
    }

    let default_dec = cfg
        .route
        .default
        .as_deref()
        .or(cfg.route.final_outbound.as_deref())
        .unwrap_or("direct");
    let default = decision_intern::intern_decision(default_dec);

    // Calc checksum (simplified, using Default for now as we don't have text representation)
    let checksum = [0u8; 32];

    let idx = RouterIndex {
        exact,
        suffix,
        suffix_map,
        port_rules,
        port_ranges,
        transport_tcp,
        transport_udp,
        cidr4,
        cidr6,
        cidr4_buckets,
        cidr6_buckets,
        geoip_rules,
        geosite_rules,
        #[cfg(feature = "router_keyword")]
        keyword_rules: Vec::new(),
        #[cfg(feature = "router_keyword")]
        keyword_idx: None,
        wifi_ssid_rules,
        wifi_bssid_rules,
        rule_set_rules,
        process_rules,
        process_path_rules,
        protocol_rules,
        network_rules,
        source_rules,
        dest_rules,
        user_agent_rules,
        rules: composite_rules,
        default,
        gen: 1,
        checksum,
    };

    // Record build time metrics
    #[cfg(feature = "metrics")]
    {
        metrics::gauge!("router_rules_size", "kind" => "composite").set(idx.rules.len() as f64);
        let elapsed = build_start.elapsed().as_millis() as f64;
        metrics::histogram!("router_ir_build_ms_bucket").record(elapsed);
    }

    Ok(Arc::new(idx))
}
