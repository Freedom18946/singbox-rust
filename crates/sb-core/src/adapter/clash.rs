//! Clash adapter interfaces (Go parity).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Clash operating mode (Go parity: constant.Mode)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClashMode {
    Global,
    #[default]
    Rule,
    Direct,
}

impl fmt::Display for ClashMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::Rule => write!(f, "rule"),
            Self::Direct => write!(f, "direct"),
        }
    }
}

impl std::str::FromStr for ClashMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "global" => Ok(Self::Global),
            "rule" => Ok(Self::Rule),
            "direct" => Ok(Self::Direct),
            _ => Err(format!("invalid mode: {}", s)),
        }
    }
}

/// Interface for interacting with Clash server state (Go parity).
pub trait ClashServerAdapter: Send + Sync {
    /// Get current mode
    fn mode(&self) -> ClashMode;

    /// Set current mode
    fn set_mode(&self, mode: ClashMode);

    /// Get available modes
    fn mode_list(&self) -> Vec<String> {
        vec![
            "global".to_string(),
            "rule".to_string(),
            "direct".to_string(),
        ]
    }
}

// Global state for Clash mode (Go parity: tunnel.Mode)
static CURRENT_MODE: once_cell::sync::Lazy<parking_lot::RwLock<ClashMode>> =
    once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(ClashMode::Rule));

/// Get current global clash mode
pub fn get_mode() -> ClashMode {
    *CURRENT_MODE.read()
}

/// Set current global clash mode
pub fn set_mode(mode: ClashMode) {
    let mut guard = CURRENT_MODE.write();
    if *guard != mode {
        *guard = mode;
        // Try to persist if cache service is available
        // Note: This requires access to the global context or cache service.
        // For now, we update the in-memory state.
        // Persistence should be handled by the caller or a service listener.
    }
}

/// Clashe server adapter that uses global state
#[derive(Debug, Clone, Default)]
pub struct GlobalClashServerAdapter;

impl ClashServerAdapter for GlobalClashServerAdapter {
    fn mode(&self) -> ClashMode {
        get_mode()
    }

    fn set_mode(&self, mode: ClashMode) {
        set_mode(mode);
        // Trigger cache update (Go parity: persistence)
        if let Some(registry) = crate::context::context_registry() {
            if let Some(cache) = &registry.cache_file {
                cache.set_clash_mode(mode.to_string());
            }
        }
    }
}
