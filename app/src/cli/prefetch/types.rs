//! Minimal, feature-safe types for `prefetch` CLI.
//! Keep decoupled from `admin_debug` to avoid cross-layer feature coupling.
//! MSRV = 1.90.
#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};

/// A representative sample output for a single prefetch item.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(
    not(all(feature = "admin_debug", feature = "subs_http", feature = "prefetch")),
    allow(dead_code)
)]
pub struct SampleOut {
    /// Logical key or URL.
    pub key: String,
    /// Final status label: "ok" | "timeout" | "io" | "decode" | "`not_found`" | "canceled" | "other".
    pub status: String,
    /// Measured latency in ms (0 if not applicable).
    pub latency_ms: u32,
    /// Size in bytes (0 if unknown).
    pub size: u32,
    /// Optional hint for diagnostics.
    pub hint: Option<String>,
}
