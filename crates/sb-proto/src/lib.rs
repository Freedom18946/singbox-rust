//! Protocol implementations for various proxy protocols.
//!
//! This crate provides modular implementations of proxy protocols including
//! Shadowsocks 2022 and Trojan, designed for use in the singbox-rust project.
//!
//! # Architecture
//!
//! - **Core abstractions** ([`connector`]): Base traits (`OutboundConnector`, `Target`, etc.)
//! - **Shadowsocks 2022 variants**:
//!   - `ss2022_min`: Minimal implementation (feature: `proto_ss2022_min`)
//!   - `ss2022_core`: Core protocol logic (feature: `proto_ss2022_core`)
//!   - `ss2022_harness`: Testing harness (feature: `proto_ss2022_min`)
//! - **Trojan variants**:
//!   - `trojan_min`: Minimal implementation (feature: `proto_trojan_min`)
//!   - `trojan_dry`: Dry-run connector (feature: `proto_trojan_dry`)
//!   - `trojan_harness`: Testing harness (feature: `proto_trojan_min`)
//!
//! # Features
//!
//! - `proto_ss2022_min`: Enables minimal Shadowsocks 2022 implementation
//! - `proto_ss2022_core`: Enables core Shadowsocks 2022 protocol logic
//! - `proto_ss2022_tls_first`: Enables TLS-first Shadowsocks 2022 variant
//! - `proto_trojan_min`: Enables minimal Trojan implementation
//! - `proto_trojan_dry`: Enables dry-run Trojan connector (testing)
//! - `outbound_registry`: Enables protocol registry for dynamic dispatch
//!
//! # Example
//!
//! ```rust,no_run
//! use sb_proto::{Target, OutboundConnector};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a target
//! let target = Target::new("example.com", 443);
//!
//! // Use with any OutboundConnector implementation
//! // let connector = /* your connector */;
//! // let stream = connector.connect(&target).await?;
//! # Ok(())
//! # }
//! ```

// Explicit module declaration order to avoid unguarded references when features are disabled
pub mod connector;
#[cfg(feature = "outbound_registry")]
pub mod outbound_registry;

/// Legacy placeholder for Shadowsocks 2022 (returns `NotImplemented`).
/// Use feature-gated modules (`ss2022_min`, `ss2022_core`) for real implementations.
pub mod ss2022;

#[cfg(feature = "proto_ss2022_core")]
pub mod ss2022_core;
#[cfg(feature = "proto_ss2022_min")]
pub mod ss2022_harness;
#[cfg(feature = "proto_ss2022_min")]
pub mod ss2022_min;

/// Legacy placeholder for Trojan (returns `NotImplemented`).
/// Use feature-gated modules (`trojan_min`, `trojan_dry`) for real implementations.
pub mod trojan;

#[cfg(feature = "proto_trojan_min")]
pub mod trojan_connector;
#[cfg(feature = "proto_trojan_dry")]
pub mod trojan_dry;
#[cfg(feature = "proto_trojan_min")]
pub mod trojan_harness;
#[cfg(feature = "proto_trojan_min")]
pub mod trojan_min;

// Re-export core types for convenience
pub use connector::*;
#[cfg(feature = "outbound_registry")]
pub use outbound_registry::*;
#[cfg(feature = "proto_ss2022_core")]
pub use ss2022_core::*;
#[cfg(feature = "proto_ss2022_min")]
pub use ss2022_min::*;
#[cfg(feature = "proto_trojan_dry")]
pub use trojan_dry::*;
#[cfg(feature = "proto_trojan_min")]
pub use trojan_harness::*;
#[cfg(feature = "proto_trojan_min")]
pub use trojan_min::*;
