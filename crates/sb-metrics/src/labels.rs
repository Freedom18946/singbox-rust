//! Metrics label whitelist for sb-metrics crate.
//! sb-metrics crate 的指标标签白名单。
//!
//! Mirrors the core whitelist to ensure a single, predictable set of label keys
//! across exporters. New label keys must be registered here.
//! 镜像核心白名单，以确保跨导出器的一组单一、可预测的标签键。新的标签键必须在此处注册。
//!
//! ## Strategic Logic / 战略逻辑
//! Uncontrolled label keys lead to **"Label Chaos"** in Prometheus (e.g., `dest_ip` vs `dst_ip` vs `destination`).
//! This whitelist enforces a **Canonical Schema** across the entire project.
//!
//! 不受控制的标签键会导致 Prometheus 中的**"标签混乱"**（例如 `dest_ip` vs `dst_ip` vs `destination`）。
//! 此白名单在整个项目中强制执行**规范模式**。

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
        // Protocol/algorithm staging (QUIC CC, session open state)
        "algorithm",
        "proto",
        "stage",
    ])
});

/// # Panics
/// Panics if any label key is not in the allowed list.
pub fn ensure_allowed_labels(metric: &str, labels: &[&str]) {
    for &k in labels {
        assert!(ALLOWED_LABEL_KEYS.contains(k),
                "sb-metrics: label key '{k}' not allowed for metric '{metric}'. Register it in labels.rs"
            );
    }
}
