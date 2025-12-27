//! Service implementations module.
//!
//! Contains actual service implementations for platforms that support them.

#[cfg(feature = "service_resolved")]
pub mod resolve1;
#[cfg(feature = "service_resolved")]
pub mod resolved_impl;
