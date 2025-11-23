//! Metrics label whitelist for sb-metrics crate.
//!
//! Mirrors the core whitelist to ensure a single, predictable set of label keys
//! across exporters. New label keys must be registered here.

use std::collections::HashSet;
use std::sync::LazyLock;

static ALLOWED_LABEL_KEYS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        // Common keys
        "method",
        "status",
        "class",
        "kind",
        "result",
        "protocol",
        "cipher",
        "operation",
        "outbound",
        "reason",
        "mode",
        "place",
        "shard",
        "state",
        "dir",
        "qtype",
        "from_cache",
        "adapter",
        "category",
        "chan",
        "proxy",
        "tag",
    ])
});

pub fn ensure_allowed_labels(metric: &str, labels: &[&str]) {
    for &k in labels {
        if !ALLOWED_LABEL_KEYS.contains(k) {
            panic!(
                "sb-metrics: label key '{}' not allowed for metric '{}'. Register it in labels.rs",
                k, metric
            );
        }
    }
}
