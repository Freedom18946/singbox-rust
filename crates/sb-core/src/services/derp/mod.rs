//! DERP (Detached Encrypted Routing Protocol) service implementation.
//!
//! Currently implements a partial service with STUN server functionality.
//! Full DERP relay protocol is not yet implemented.

pub mod client_registry;
pub mod protocol;
pub mod server;
pub mod mesh_test;

pub use client_registry::{ClientHandle, ClientRegistry, DerpMetrics};
pub use protocol::{DerpFrame, FrameType, ProtocolError, PublicKey, PROTOCOL_VERSION};
pub use server::{build_derp_service, DerpService};
