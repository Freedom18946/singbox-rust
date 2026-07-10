//! Public registration façade.  Builders live in a dedicated module so the
//! registry entry point remains a readable ownership boundary.

#[path = "register/builders.rs"]
mod builders;

pub use builders::{build_default_registry, register_all};
