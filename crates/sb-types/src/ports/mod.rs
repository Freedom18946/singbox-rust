//! Ports (traits) for cross-crate abstractions.
//!
//! # Strategic Purpose
//! Ports are the interface contracts between sb-core and its adapters.
//! sb-core depends ONLY on these traits; adapters implement them.
//!
//! # Note on async traits
//! These traits use the stable `async fn in traits` feature (Rust 1.75+).
//! For object-safety when needed, use the wrapper pattern (see templates/).

pub mod admin;
pub mod dns;
pub mod inbound;
pub mod metrics;
pub mod outbound;

pub use admin::*;
pub use dns::*;
pub use inbound::*;
pub use metrics::*;
pub use outbound::*;
