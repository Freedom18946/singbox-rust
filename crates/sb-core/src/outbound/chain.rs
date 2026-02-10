use std::collections::HashSet;

use crate::outbound::{OutboundImpl, OutboundRegistryHandle};
use crate::router::rules::Decision;

/// Compute proxy chain in Go-compatible order: leaf -> ... -> matched.
///
/// The algorithm starts at `matched_tag` and follows OutboundGroup::now() until it
/// reaches a non-group leaf or cannot resolve the next hop.
///
/// Safety:
/// - bounded by `max_hops`
/// - cycle detection via `visited`
pub fn compute_chain_leaf_to_matched(
    outbounds: &OutboundRegistryHandle,
    matched_tag: &str,
) -> Vec<String> {
    if matched_tag.eq_ignore_ascii_case("direct") {
        return vec!["DIRECT".to_string()];
    }

    let mut visited: HashSet<String> = HashSet::new();
    let mut chain_matched_to_leaf: Vec<String> = Vec::new();
    let mut cur = matched_tag.to_string();

    const MAX_HOPS: usize = 16;
    for _ in 0..MAX_HOPS {
        if cur.trim().is_empty() {
            break;
        }
        if !visited.insert(cur.clone()) {
            break;
        }
        chain_matched_to_leaf.push(cur.clone());

        // Resolve the current outbound and see if it's a group.
        let next = {
            let reg = outbounds.read();
            match reg.get(&cur).cloned() {
                Some(OutboundImpl::Connector(conn)) => conn.as_group().map(|g| g.now()),
                _ => None,
            }
        };

        match next {
            Some(n) if !n.trim().is_empty() => cur = n,
            _ => break,
        }
    }

    if chain_matched_to_leaf.is_empty() {
        return vec!["DIRECT".to_string()];
    }

    chain_matched_to_leaf.reverse();
    chain_matched_to_leaf
}

/// Compute proxy chain for a routing decision.
///
/// - Direct -> ["DIRECT"]
/// - Proxy(Some(tag)) -> compute leaf->matched (if registry available) or [tag]
/// - Otherwise -> [outbound_tag] or ["PROXY"]
pub fn compute_chain_for_decision(
    outbounds: Option<&OutboundRegistryHandle>,
    decision: &Decision,
    outbound_tag: Option<&str>,
) -> Vec<String> {
    if let Some(tag) = outbound_tag {
        if tag.eq_ignore_ascii_case("direct") {
            return vec!["DIRECT".to_string()];
        }
    }
    match decision {
        Decision::Direct => vec!["DIRECT".to_string()],
        Decision::Proxy(Some(tag)) => {
            if let Some(reg) = outbounds {
                compute_chain_leaf_to_matched(reg, tag)
            } else {
                vec![tag.to_string()]
            }
        }
        Decision::Proxy(None) => outbound_tag
            .map(|t| vec![t.to_string()])
            .unwrap_or_else(|| vec!["PROXY".to_string()]),
        _ => outbound_tag
            .map(|t| vec![t.to_string()])
            .unwrap_or_else(|| vec!["PROXY".to_string()]),
    }
}
