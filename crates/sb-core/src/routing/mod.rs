//! Routing explain system
pub mod engine;
pub mod explain;
pub mod ir;
pub mod trace;

pub mod matcher;
pub mod router;

// Re-export commonly used types from submodules
pub use explain::{ExplainDto, ExplainEngine, ExplainResult};
pub use trace::Trace;
