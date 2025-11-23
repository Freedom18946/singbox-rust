//! Legacy re-exports for the old `services::ntp` module.
//!
//! The new `service` module exposes stable trait/registry definitions,
//! while concrete implementations continue to live under `services`.
//! Keep re-exporting to avoid breaking older call sites that expect
//! `sb_core::service::ntp::*`.

pub use crate::services::ntp::*;
