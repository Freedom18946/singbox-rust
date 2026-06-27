//! DERP (Detached Encrypted Routing Protocol) service implementation.
//!
//! Implements the local DERP relay surface used by the service runtime,
//! including HTTP upgrade/websocket DERP, mesh forwarding, STUN, bootstrap DNS,
//! verify-client hooks, and Go-compatible service lifecycle wiring.

pub mod client_registry;
pub mod mesh_test;
pub mod server;
pub use sb_transport::derp::protocol;

pub use client_registry::{ClientHandle, ClientRegistry, DerpMetrics};
pub use protocol::{DerpFrame, FrameType, ProtocolError, PublicKey, PROTOCOL_VERSION};
pub use server::{build_derp_service, DerpService};
