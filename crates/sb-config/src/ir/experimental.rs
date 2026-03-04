use serde::{Deserialize, Serialize};
/// Experimental configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExperimentalIR {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<CacheFileIR>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApiIR>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2ray_api: Option<V2RayApiIR>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug: Option<DebugIR>,
    /// QUIC + ECH validation mode:
    /// - `reject` (default): reject QUIC+ECH config to avoid silent fallback risks
    /// - `experimental`: allow with warning for controlled interop experiments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_ech_mode: Option<String>,
}

/// Cache file configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CacheFileIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Identifier in the cache file.
    ///
    /// If not empty, configuration specified data will use a separate store keyed by it.
    /// Go parity: `experimental.cache_file.cache_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,
    #[serde(default)]
    pub store_fakeip: bool,
    #[serde(default)]
    pub store_rdrc: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdrc_timeout: Option<String>,
}

/// Clash API configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashApiIR {
    #[serde(default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub external_ui: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub external_ui_download_url: Option<String>,
    #[serde(default)]
    pub external_ui_download_detour: Option<String>,
    #[serde(default)]
    pub default_mode: Option<String>,
}

/// V2Ray API configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct V2RayApiIR {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub stats: Option<StatsIR>,
}

/// Debug/pprof controls (parity with Go `option/debug.go`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DebugIR {
    /// Debug HTTP/pprof listen address.
    #[serde(default)]
    pub listen: Option<String>,
    /// GC percent (Go parity; recorded only).
    #[serde(default)]
    pub gc_percent: Option<i32>,
    /// Max stack (Go parity; recorded only).
    #[serde(default)]
    pub max_stack: Option<i32>,
    /// Max threads (Go parity; recorded only).
    #[serde(default)]
    pub max_threads: Option<i32>,
    /// Panic on fault (Go parity; recorded only).
    #[serde(default)]
    pub panic_on_fault: Option<bool>,
    /// Traceback mode (Go parity; recorded only).
    #[serde(default)]
    pub trace_back: Option<String>,
    /// Memory limit bytes (Go parity; recorded only).
    #[serde(default)]
    pub memory_limit: Option<u64>,
    /// OOM killer toggle (Go parity; recorded only).
    #[serde(default)]
    pub oom_killer: Option<bool>,
}

/// V2Ray stats configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StatsIR {
    #[serde(default)]
    pub enabled: bool,
    /// Inbound tags to track.
    #[serde(default)]
    pub inbounds: Vec<String>,
    /// Outbound tags to track.
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
    /// Deprecated boolean flags (kept for compatibility with older configs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<bool>,
    /// Deprecated boolean flags (kept for compatibility with older configs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<bool>,
}
