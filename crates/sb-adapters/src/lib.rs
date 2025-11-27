//! Proxy adapters for singbox-rust.
//! singbox-rust 的代理适配器。
//!
//! This crate provides inbound and outbound adapters for various proxy protocols,
//! including SOCKS, HTTP, Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria, and more.
//! It serves as the core protocol implementation layer for the singbox-rust proxy framework.
//!
//! 此 crate 为各种代理协议提供入站和出站适配器，包括 SOCKS, HTTP, Shadowsocks, VMess,
//! VLESS, Trojan, TUIC, Hysteria 等。它是 singbox-rust 代理框架的核心协议实现层。
//!
//! # Architecture / 架构
//!
//! The crate follows a trait-based design pattern:
//! 本 crate 遵循基于 trait 的设计模式：
//!
//! - [`OutboundConnector`]: Trait for establishing outbound connections (建立出站连接的 Trait)
//! - [`OutboundDatagram`]: Trait for UDP-based protocols (基于 UDP 协议的 Trait)
//! - [`Target`]: Represents connection destinations (IP, domain, or FQDN) (表示连接目标：IP、域名或 FQDN)
//! - [`TransportConfig`]: Configures transport layers (TLS, mux, WebSocket, etc.) (配置传输层：TLS, mux, WebSocket 等)
//! - [`RetryPolicy`]: Configurable retry with exponential backoff (带指数退避的可配置重试策略)
//! - [`DialOpts`]: Connection options (timeouts, retry, DNS mode) (连接选项：超时、重试、DNS 模式)
//! - [`ResolveMode`]: DNS resolution strategy (local vs remote) (DNS 解析策略：本地 vs 远程)
//!
//! # Module Structure / 模块结构
//!
//! - [`error`]: Unified error types for all adapters (所有适配器的统一错误类型)
//! - [`inbound`]: Server-side protocol implementations (accept incoming connections) (服务端协议实现，接受传入连接)
//! - [`outbound`]: Client-side protocol implementations (initiate outgoing connections) (客户端协议实现，发起传出连接)
//! - [`traits`]: Core traits defining adapter behavior and interfaces (定义适配器行为和接口的核心 trait)
//! - [`transport_config`]: Transport layer configuration (TLS, mux, WebSocket, etc.) (传输层配置)
//! - [`util`]: Utility functions and helpers (实用函数和辅助工具)
//! - [`testsupport`]: Testing utilities (only available with `test` or `e2e` feature) (测试工具，仅在 `test` 或 `e2e` 特性下可用)
//!
//! # Feature Flags / 特性标志
//!
//! This crate uses Cargo features extensively to enable specific protocols and functionality:
//! 本 crate 广泛使用 Cargo特性来启用特定的协议和功能：
//!
//! ## Adapter Features / 适配器特性
//! - `adapter-socks` / `adapter-http`: SOCKS5 and HTTP proxy support (SOCKS5 和 HTTP 代理支持)
//! - `adapter-shadowsocks` / `adapter-trojan` / `adapter-vmess` / `adapter-vless`: Crypto protocols (加密协议)
//! - `adapter-hysteria` / `adapter-hysteria2` / `adapter-tuic`: QUIC-based protocols (基于 QUIC 的协议)
//! - `adapter-dns`: DNS outbound adapter (DNS 出站适配器)
//! - `adapter-naive`: HTTP/2 CONNECT proxy with ECH support (支持 ECH 的 HTTP/2 CONNECT 代理)
//!
//! ## Transport Features / 传输层特性
//! - `transport_tls` / `transport_reality`: TLS and REALITY transport (TLS 和 REALITY 传输)
//! - `transport_mux`: Multiplexing support (smux/yamux) (多路复用支持)
//! - `transport_ws` / `transport_grpc` / `transport_httpupgrade`: Application-layer transports (应用层传输)
//! - `transport_quic` / `transport_h2`: QUIC and HTTP/2 transports (QUIC 和 HTTP/2 传输)
//!
//! ## Utility Features / 实用工具特性
//! - `metrics`: Enable metrics collection via `sb-metrics` (通过 `sb-metrics` 启用指标收集)
//! - `e2e`: Enable end-to-end testing utilities (启用端到端测试工具)
//!
//! # Quick Start / 快速开始
//!
//! ## Outbound Connection Example / 出站连接示例
//!
//! ```rust,ignore
//! use sb_adapters::{OutboundConnector, Target, Result};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! async fn connect_example(connector: &impl OutboundConnector) -> Result<()> {
//!     // Create a target (domain name, port)
//!     // 创建目标（域名，端口）
//!     let target = Target::Domain("example.com".to_string(), 443);
//!
//!     // Establish connection
//!     // 建立连接
//!     let mut stream = connector.connect(&target).await?;
//!
//!     // Use the stream
//!     // 使用流
//!     stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
//!     let mut buf = vec![0u8; 1024];
//!     let n = stream.read(&mut buf).await?;
//!     println!("Received {} bytes", n);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Creating an Outbound Adapter / 创建出站适配器
//!
//! ```rust,ignore
//! use sb_adapters::outbound::socks5::Socks5Outbound;
//! use sb_adapters::{OutboundConnector, Target};
//!
//! async fn create_socks5_adapter() -> Result<()> {
//!     let socks5 = Socks5Outbound::new(
//!         "127.0.0.1:1080".parse()?,
//!         None, // No authentication / 无需认证
//!     );
//!
//!     let target = Target::Ip("93.184.216.34".parse()?, 80);
//!     let stream = socks5.connect(&target).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Minimum Supported Rust Version (MSRV) / 最低支持 Rust 版本
//!
//! This crate requires Rust 1.90 or later, as specified in the workspace configuration.
//! 本 crate 需要 Rust 1.90 或更高版本，如工作区配置中所述。
//!
//! # Platform Support / 平台支持
//!
//! - **Linux**: Full support (including TUN, tproxy, redirect) / 完全支持（包括 TUN, tproxy, redirect）
//! - **macOS**: Full support (including TUN via tun2socks) / 完全支持（包括通过 tun2socks 的 TUN）
//! - **Windows**: Partial support (TUN via wintun, some features unavailable) / 部分支持（通过 wintun 的 TUN，部分功能不可用）
//!
//! # Safety / 安全性
//!
//! This crate minimizes `unsafe` usage. Where `unsafe` is necessary (e.g., platform-specific
//! TUN device operations), all unsafe blocks are documented with safety invariants.
//! 本 crate 尽量减少 `unsafe` 的使用。在必须使用 `unsafe` 的地方（例如平台特定的 TUN 设备操作），
//! 所有 unsafe 块都记录了安全不变量。

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

/// Endpoint implementations.
pub mod endpoint;

/// Service stub implementations (Resolved, DERP, SSM).
pub mod service_stubs;

/// Service implementations.
pub mod service;

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
/// - [`RetryPolicy`]: Configurable retry with exponential backoff
/// - [`DialOpts`]: Connection options (timeouts, retry, DNS mode)
/// - [`ResolveMode`]: DNS resolution strategy (local vs remote)
pub use traits::{
    BoxedStream, DialOpts, OutboundConnector, OutboundDatagram, ResolveMode, RetryPolicy, Target,
    TransportKind,
};

/// Re-exported transport configuration types.
///
/// These types configure how connections are established at the transport layer:
/// - [`TransportConfig`]: Main transport configuration structure
/// - [`TransportType`]: Enum of available transport types (TLS, WS, gRPC, etc.)
pub use transport_config::{TransportConfig, TransportType};

/// Register adapter builders with sb-core registry (idempotent).
pub use register::register_all;
