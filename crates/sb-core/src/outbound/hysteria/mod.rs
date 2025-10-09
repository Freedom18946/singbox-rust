//! Hysteria v1 protocol implementation
//!
//! Provides Hysteria v1 protocol support for high-performance proxying
//! over QUIC with custom congestion control and UDP relay.

#[cfg(feature = "out_hysteria")]
pub mod v1;

#[cfg(feature = "out_hysteria")]
pub use v1::{HysteriaV1Config, HysteriaV1Outbound, HysteriaV1Inbound};
