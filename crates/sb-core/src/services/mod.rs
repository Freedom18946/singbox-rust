//! Runtime services (optional)

#[cfg(feature = "service_ntp")]
pub mod ntp;

#[cfg(feature = "service_ssmapi")]
pub mod ssmapi;

#[cfg(feature = "service_derp")]
pub mod derp;
#[cfg(feature = "service_resolved")]
pub mod resolved;
