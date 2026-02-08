//! Dangerous TLS certificate verifiers
//!
//! Re-exports from `sb_tls::danger`. The canonical implementations live in sb-tls;
//! this module provides backward-compatible access for sb-core internals.

pub use sb_tls::danger::{NoVerify, PinVerify};
