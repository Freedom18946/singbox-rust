//! Metrics label whitelist and guard.
//!
//! This module enforces a repository-wide whitelist of Prometheus label keys
//! to avoid accidental label proliferation. Any new label keys must be added
//! here intentionally; otherwise registration will fail, catching issues in CI.

use std::collections::HashSet;
use std::sync::LazyLock;

/// Allowed label keys across all Prometheus vectors in this workspace.
///
/// Keep this list tight. If you need a new key, add it here with rationale.
static ALLOWED_LABEL_KEYS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // HTTP
        "method",
        "status",
        "class",
        // Outbound
        "kind",
        "result",
        "protocol",
        "cipher",
        "operation",
        // Selector / URLTest / misc
        "outbound",
        "reason",
        "mode",
        "place",
        // UDP / NAT
        "shard",
        "state",
        "dir",
        // DNS
        "qtype",
        "from_cache",
        // sb-metrics (shared conventions)
        "adapter",
        "category",
        "chan",
        "proxy",
        "tag",
        // Protocol/algorithm staging (QUIC CC, session open state)
        "algorithm",
        "proto",
        "stage",
    ])
});

/// Ensure provided label keys are in whitelist. Panics if a key is not allowed.
///
/// This is intentionally strict to catch issues early during tests/CI. At
/// runtime, the panic will surface during metric registration (startup), not in
/// a hot path.
pub fn ensure_allowed_labels(metric: &str, labels: &[&str]) {
    for &k in labels {
        if !ALLOWED_LABEL_KEYS.contains(k) {
            panic!(
                "metrics: label key '{}' not in whitelist for metric '{}'. \
                 If intentional, add it to ALLOWED_LABEL_KEYS in metrics/label_guard.rs",
                k, metric
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allows_known_keys() {
        ensure_allowed_labels("t", &["method", "status", "class"]);
    }

    #[test]
    #[should_panic]
    fn rejects_unknown_key() {
        ensure_allowed_labels("t", &["totally_new_key"]);
    }
}
