//! Routing explain system
pub mod engine;
pub mod explain;
pub mod ir;
pub mod trace;

pub mod matcher;
pub mod router;
// Sniffing utilities live under `router::sniff`; re-export here for routing users.
pub use crate::router::sniff as sniff;

// Re-export commonly used types from submodules
pub use explain::{ExplainDto, ExplainEngine, ExplainResult};
pub use trace::Trace;
