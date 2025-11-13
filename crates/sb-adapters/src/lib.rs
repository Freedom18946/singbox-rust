//! Proxy adapters for singbox-rust.
//!
//! This crate provides inbound and outbound adapters for various proxy protocols,
//! including SOCKS, HTTP, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria, and more.
//! It serves as the core protocol implementation layer for the singbox-rust proxy framework.
//!
//! # Architecture
//!
//! The crate follows a trait-based design pattern:
//! - [`OutboundConnector`]: Trait for establishing outbound connections
//! - [`OutboundDatagram`]: Trait for UDP-based protocols
//! - [`Target`]: Represents connection destinations (IP, domain, or FQDN)
//! - [`TransportConfig`]: Configures transport layers (TLS, mux, WebSocket, etc.)
//!
//! # Module Structure
//!
//! - [`error`]: Unified error types for all adapters
//! - [`inbound`]: Server-side protocol implementations (accept incoming connections)
//! - [`outbound`]: Client-side protocol implementations (initiate outgoing connections)
//! - [`traits`]: Core traits defining adapter behavior and interfaces
//! - [`transport_config`]: Transport layer configuration (TLS, mux, WebSocket, etc.)
//! - [`util`]: Utility functions and helpers
//! - [`testsupport`]: Testing utilities (only available with `test` or `e2e` feature)
//!
//! # Feature Flags
//!
//! This crate uses Cargo features extensively to enable specific protocols and functionality:
//!
//! ## Adapter Features
//! - `adapter-socks` / `adapter-http`: SOCKS5 and HTTP proxy support
//! - `adapter-shadowsocks` / `adapter-trojan` / `adapter-vmess` / `adapter-vless`: Crypto protocols
//! - `adapter-hysteria` / `adapter-hysteria2` / `adapter-tuic`: QUIC-based protocols
//! - `adapter-dns`: DNS outbound adapter
//! - `adapter-naive`: HTTP/2 CONNECT proxy with ECH support
//!
//! ## Transport Features
//! - `transport_tls` / `transport_reality`: TLS and REALITY transport
//! - `transport_mux`: Multiplexing support (smux/yamux)
//! - `transport_ws` / `transport_grpc` / `transport_httpupgrade`: Application-layer transports
//! - `transport_quic` / `transport_h2`: QUIC and HTTP/2 transports
//!
//! ## Utility Features
//! - `metrics`: Enable metrics collection via `sb-metrics`
//! - `e2e`: Enable end-to-end testing utilities
//!
//! # Quick Start
//!
//! ## Outbound Connection Example
//!
//! ```rust,ignore
//! use sb_adapters::{OutboundConnector, Target, Result};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! async fn connect_example(connector: &impl OutboundConnector) -> Result<()> {
//!     // Create a target (domain name, port)
//!     let target = Target::Domain("example.com".to_string(), 443);
//!
//!     // Establish connection
//!     let mut stream = connector.connect(&target).await?;
//!
//!     // Use the stream
//!     stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
//!     let mut buf = vec![0u8; 1024];
//!     let n = stream.read(&mut buf).await?;
//!     println!("Received {} bytes", n);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Creating an Outbound Adapter
//!
//! ```rust,ignore
//! use sb_adapters::outbound::socks5::Socks5Outbound;
//! use sb_adapters::{OutboundConnector, Target};
//!
//! async fn create_socks5_adapter() -> Result<()> {
//!     let socks5 = Socks5Outbound::new(
//!         "127.0.0.1:1080".parse()?,
//!         None, // No authentication
//!     );
//!
//!     let target = Target::Ip("93.184.216.34".parse()?, 80);
//!     let stream = socks5.connect(&target).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Minimum Supported Rust Version (MSRV)
//!
//! This crate requires Rust 1.90 or later, as specified in the workspace configuration.
//!
//! # Platform Support
//!
//! - **Linux**: Full support (including TUN, tproxy, redirect)
//! - **macOS**: Full support (including TUN via tun2socks)
//! - **Windows**: Partial support (TUN via wintun, some features unavailable)
//!
//! # Safety
//!
//! This crate minimizes `unsafe` usage. Where `unsafe` is necessary (e.g., platform-specific
//! TUN device operations), all unsafe blocks are documented with safety invariants.

#![allow(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(unreachable_pub)]
#![deny(unsafe_op_in_unsafe_fn)]

/// Unified error handling for all adapter operations.
pub mod error;

/// Inbound adapters (server-side protocol implementations).
///
/// Each inbound module implements server-side protocol handling, accepting incoming
/// connections and processing protocol-specific handshakes and authentication.
pub mod inbound;

/// Outbound adapters (client-side protocol implementations).
///
/// Each outbound module implements client-side protocol handling, initiating connections
/// to remote servers and performing necessary handshakes and encryption.
pub mod outbound;

/// Core traits defining adapter interfaces and behavior.
///
/// These traits provide a uniform abstraction over different proxy protocols,
/// enabling protocol-agnostic routing and connection management.
pub mod traits;

/// Transport layer configuration and types.
///
/// Defines how underlying connections are established and secured, supporting
/// various transport protocols like TLS, REALITY, WebSocket, gRPC, and more.
pub mod transport_config;

/// Registry helpers to integrate adapters with sb-core bridge.
pub mod register;

/// Endpoint stub implementations (WireGuard, Tailscale).
pub mod endpoint_stubs;

/// Service stub implementations (Resolved, DERP, SSM).
pub mod service_stubs;

/// Utility functions and helpers.
///
/// Contains shared utility code used across multiple adapters, including
/// parsing helpers, I/O utilities, and common algorithm implementations.
pub mod util;

/// Testing support utilities.
///
/// Provides mock adapters, test fixtures, and helper functions for writing
/// adapter tests. Only available when compiled with `test` or the `e2e` feature.
#[cfg(any(test, feature = "e2e"))]
pub mod testsupport;

// ============================================================================
// Public Re-exports
// ============================================================================

/// Re-exported error types for convenient access.
///
/// Import these to avoid writing `sb_adapters::error::AdapterError` repeatedly.
pub use error::{AdapterError, Result};

/// Re-exported core traits for adapter implementations.
///
/// These are the primary abstractions used throughout the singbox-rust ecosystem:
/// - [`OutboundConnector`]: Connect to remote targets via TCP streams
/// - [`OutboundDatagram`]: Send/receive UDP packets through a proxy
/// - [`Target`]: Represent connection destinations (IP, domain, or FQDN)
/// - [`BoxedStream`]: Type alias for boxed async TCP streams
/// - [`TransportKind`]: Enum representing different transport layer types
pub use traits::{BoxedStream, OutboundConnector, OutboundDatagram, Target, TransportKind};

/// Re-exported transport configuration types.
///
/// These types configure how connections are established at the transport layer:
/// - [`TransportConfig`]: Main transport configuration structure
/// - [`TransportType`]: Enum of available transport types (TLS, WS, gRPC, etc.)
pub use transport_config::{TransportConfig, TransportType};

/// Register adapter builders with sb-core registry (idempotent).
pub use register::register_all;
