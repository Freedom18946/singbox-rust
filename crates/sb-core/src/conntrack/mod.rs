//! Conntrack integration helpers (Clash API /connections wiring).
//!
//! sb-common contains the actual tracker and metadata types.
//! This module provides sb-core helpers for wiring tracker metadata into
//! real inbound I/O loops (cancel + byte counters + optional stats forwarding).

pub mod inbound_tcp;

pub use inbound_tcp::{register_inbound_tcp, ConntrackGuard, ConntrackWiring};

