//! Conntrack integration helpers (Clash API /connections wiring).
//!
//! sb-common contains the actual tracker and metadata types.
//! This module provides sb-core helpers for wiring tracker metadata into
//! real inbound I/O loops (cancel + byte counters + optional stats forwarding).

pub mod inbound_tcp;
pub mod inbound_udp;

pub use inbound_tcp::{
    register_inbound_tcp, register_inbound_tcp_with_tracker, ConntrackGuard, ConntrackWiring,
};
pub use inbound_udp::{register_inbound_udp, register_inbound_udp_with_tracker};
