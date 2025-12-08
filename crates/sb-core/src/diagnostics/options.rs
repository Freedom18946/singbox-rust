//! Debug options configuration.
//!
//! Mirrors Go's `option/debug.go`.

use serde::{Deserialize, Serialize};

/// Debug configuration options.
///
/// Note: Some Go options (gc_percent, max_stack, max_threads) are not directly
/// applicable to Rust. They are documented but marked as no-op.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DebugOptions {
    /// Listen address for debug HTTP server (e.g., "127.0.0.1:9090").
    #[serde(default)]
    pub listen: Option<String>,

    /// GC percentage (Go-only, no-op in Rust).
    ///
    /// In Go: `debug.SetGCPercent(n)`
    /// In Rust: No equivalent - Rust has no GC.
    #[serde(default)]
    pub gc_percent: Option<i32>,

    /// Max stack size (Go-only, no-op in Rust).
    ///
    /// In Go: `debug.SetMaxStack(n)`
    /// In Rust: Stack size is set per-thread via builder.
    #[serde(default)]
    pub max_stack: Option<i32>,

    /// Max threads (Go-only, limited in Rust).
    ///
    /// In Go: `debug.SetMaxThreads(n)`
    /// In Rust: Tokio runtime thread count is set at build time.
    #[serde(default)]
    pub max_threads: Option<i32>,

    /// Panic on fault (Go-only, no-op in Rust).
    #[serde(default)]
    pub panic_on_fault: Option<bool>,

    /// Traceback mode (Go-only, no-op in Rust).
    ///
    /// In Rust: Use `RUST_BACKTRACE=1` environment variable.
    #[serde(default)]
    pub trace_back: Option<String>,

    /// Memory limit in bytes.
    ///
    /// In both Go and Rust, this can be used to trigger OOM handling.
    #[serde(default)]
    pub memory_limit: Option<u64>,

    /// Enable OOM killer behavior.
    #[serde(default)]
    pub oom_killer: Option<bool>,
}

impl DebugOptions {
    /// Create new options with listen address.
    pub fn with_listen(listen: impl Into<String>) -> Self {
        Self {
            listen: Some(listen.into()),
            ..Default::default()
        }
    }

    /// Check if debug server should be started.
    pub fn should_start_server(&self) -> bool {
        self.listen.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_default() {
        let opts = DebugOptions::default();
        assert!(!opts.should_start_server());
    }

    #[test]
    fn test_options_with_listen() {
        let opts = DebugOptions::with_listen("127.0.0.1:9090");
        assert!(opts.should_start_server());
    }
}
