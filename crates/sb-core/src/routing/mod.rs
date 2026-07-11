//! MIG-03 WP08 compatibility facade.
//!
//! Implementations live in [`crate::router`]. Remove this module in WP14 after one
//! compatibility cycle; new code must use `crate::router`.

#[deprecated(note = "use crate::router::{Engine, Input}; scheduled for WP14 removal")]
pub mod engine {
    pub use crate::router::config_engine::*;
}

#[deprecated(note = "use crate::router::config_explain; scheduled for WP14 removal")]
pub mod explain {
    pub use crate::router::config_explain::*;
}

#[deprecated(note = "use crate::router::config_trace; scheduled for WP14 removal")]
pub mod trace {
    pub use crate::router::config_trace::*;
}

pub use crate::router::config_explain::{ExplainDto, ExplainEngine, ExplainResult};
pub use crate::router::config_trace::Trace;
pub use crate::router::sniff;
#[deprecated(note = "use crate::router::{Engine, Input}; scheduled for WP14 removal")]
pub use crate::router::{Engine, Input};
