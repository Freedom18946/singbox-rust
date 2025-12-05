//! # sb-transport: Transport Layer Abstraction Library / 传输层抽象库
//!
//! This crate provides the transport layer abstraction for the singbox-rust project, serving as the
//! foundation for all network communication. It abstracts over various protocols (TCP, TLS, QUIC, etc.)
//! to provide a unified interface for upper layers.
//!
//! 这个 crate 提供了 singbox-rust 项目的传输层抽象，作为所有网络通信的基础。
//! 它对各种协议（TCP, TLS, QUIC 等）进行了抽象，为上层提供统一的接口。
//!
//! ## Strategic Relevance / 战略关联
//! - **Core Abstraction**: Defines the `Dialer` trait, which is the contract used by `sb-outbound`
//!   and other crates to establish connections without knowing the underlying protocol details.
//!   **核心抽象**：定义了 `Dialer` trait，这是 `sb-outbound` 和其他 crate 用于建立连接的契约，
//!   无需了解底层协议细节。
//! - **Dependency Hub**: Centralizes dependencies on transport libraries like `tokio`, `rustls`, `quinn`,
//!   ensuring consistent versions and configuration across the workspace.
//!   **依赖中心**：集中管理 `tokio`, `rustls`, `quinn` 等传输库的依赖，确保工作区内版本和配置的一致性。
//! - **Reliability Layer**: Integrates `circuit_breaker` and `retry` logic, providing a standard way
//!   to handle network instability globally.
//!   **可靠性层**：集成了 `circuit_breaker` 和 `retry` 逻辑，提供了一种全局处理网络不稳定的标准方式。
//!
//! ## Modules /        let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>; abstraction and implementation / 网络连接拨号器抽象和实现
//! - `tls`: TLS connection wrapper (requires `transport_tls` feature) / TLS 连接包装器
//! - `util`: Transport utility functions (e.g., timeout handling) / 传输工具函数
//! - `mem`: In-memory transport (for testing) / 内存传输（用于测试）
//!
//! ## Features
//! - `transport_tls`: Enable TLS support based on rustls / 启用 TLS 支持
//!
//! ## Design Philosophy / 设计理念
//! This library follows the design philosophy of singbox-rust:
//! 该库遵循 singbox-rust 的设计理念：
//! - **boring clarity**: Simple and clear abstractions / 简单清晰的抽象
//! - **never break userspace**: Backward compatibility / 保持向后兼容
//! - **good taste**: Elegant API design / 优雅的 API 设计
//!
//! R96: Top-level module exports and re-exposures / 顶层模块导出和重新暴露

/// Network connection dialer module
/// Provides `Dialer` trait        let dialer = TcpDialer::default();mentations
///
/// 网络连接拨号器模块
/// 提供了 `Dialer` trait 和各种拨号器实现
pub mod derp;
pub mod dialer;
pub mod pool {
    pub mod circuit_breaker;
    pub mod limit;
}

#[cfg(feature = "failpoints")]
pub mod failpoint_dialer;

/// TLS transport layer module
/// Provides TLS connection wrapper based on rustls
/// Only available when `transport_tls` feature is enabled
///
/// TLS 传输层模块
/// 提供基于 rustls 的 TLS 连接包装器
/// 仅在启用 `transport_tls` feature 时可用
#[cfg(feature = "transport_tls")]
pub mod tls;

#[cfg(feature = "transport_tls")]
pub mod tls_secure;

/// WebSocket transport layer module
/// Provides WebSocket connection wrapper based on tokio-tungstenite
/// Only available when `transport_ws` feature is enabled
///
/// WebSocket 传输层模块
/// 提供基于 tokio-tungstenite 的 WebSocket 连接包装器
/// 仅在启用 `transport_ws` feature 时可用
#[cfg(feature = "transport_ws")]
pub mod websocket;

/// HTTP/2 transport layer module
/// Provides HTTP/2 connection wrapper based on h2
/// Only available when `transport_h2` feature is enabled
///
/// HTTP/2 传输层模块
/// 提供基于 h2 的 HTTP/2 连接包装器
/// 仅在启用 `transport_h2` feature 时可用
#[cfg(feature = "transport_h2")]
pub mod http2;

/// gRPC transport layer module
/// Provides gRPC tunnel service based on tonic
/// Only available when `transport_grpc` feature is enabled
///
/// gRPC 传输层模块
/// 提供基于 tonic 的 gRPC tunnel 服务
/// 仅在启用 `transport_grpc` feature 时可用
#[cfg(feature = "transport_grpc")]
pub mod grpc;

/// Multiplex transport layer module
/// Provides connection multiplexing based on yamux
/// Only available when `transport_mux` feature is enabled
///
/// Multiplex 传输层模块
/// 提供基于 yamux 的连接复用
/// 仅在启用 `transport_mux` feature 时可用
#[cfg(feature = "transport_mux")]
pub mod multiplex;

#[cfg(feature = "transport_mux")]
pub use yamux;

/// HTTPUpgrade transport layer module
/// Establishes byte stream tunnel via HTTP/1.1 Upgrade
///
/// HTTPUpgrade 传输层模块
/// 通过 HTTP/1.1 Upgrade 建立字节流隧道
#[cfg(feature = "transport_httpupgrade")]
pub mod httpupgrade;

/// QUIC transport layer module
/// Provides generic QUIC transport based on quinn
/// Only available when `transport_quic` feature is enabled
///
/// QUIC 传输层模块
/// 提供基于 quinn 的通用 QUIC 传输
/// 仅在启用 `transport_quic` feature 时可用
#[cfg(feature = "transport_quic")]
pub mod quic;

/// Simple obfuscation plugin module
/// Provides HTTP and TLS obfuscation for traffic disguising
/// Only available when `transport_obfs` feature is enabled
///
/// 简单混淆插件模块
/// 提供 HTTP 和 TLS 流量混淆
/// 仅在启用 `transport_obfs` feature 时可用
#[cfg(feature = "transport_obfs")]
pub mod simple_obfs;

/// UDP over TCP module
/// Provides UDP packet tunneling over TCP connections
/// Only available when `transport_uot` feature is enabled
///
/// UDP over TCP 模块
/// 提供通过 TCP 连接传输 UDP 数据包
/// 仅在启用 `transport_uot` feature 时可用
#[cfg(feature = "transport_uot")]
pub mod uot;

/// SIP003 plugin protocol module
/// Provides Shadowsocks plugin support
/// Only available when `transport_sip003` feature is enabled
///
/// SIP003 插件协议模块
/// 提供 Shadowsocks 插件支持
/// 仅在启用 `transport_sip003` feature 时可用
#[cfg(feature = "transport_sip003")]
pub mod sip003;

/// Trojan transport module
/// Provides Trojan protocol transport layer
/// Only available when `transport_trojan` feature is enabled
///
/// Trojan 传输模块
/// 提供 Trojan 协议传输层
/// 仅在启用 `transport_trojan` feature 时可用
#[cfg(feature = "transport_trojan")]
pub mod trojan;

/// Lightweight gRPC module
/// Provides minimal gRPC-like transport without full tonic
/// Only available when `transport_grpc_lite` feature is enabled
///
/// 轻量级 gRPC 模块
/// 提供无需完整 tonic 的简化 gRPC 传输
/// 仅在启用 `transport_grpc_lite` feature 时可用
#[cfg(feature = "transport_grpc_lite")]
pub mod grpc_lite;

/// WireGuard transport module
/// Provides userspace WireGuard tunnel transport based on boringtun
/// Only available when `transport_wireguard` feature is enabled
///
/// WireGuard 传输模块
/// 提供基于 boringtun 的用户空间 WireGuard 隧道传输
/// 仅在启用 `transport_wireguard` feature 时可用
#[cfg(feature = "transport_wireguard")]
pub mod wireguard;

/// Tailscale DNS transport module
/// Provides MagicDNS resolution and DERP relay support
/// Only available when `transport_tailscale` feature is enabled
///
/// Tailscale DNS 传输模块
/// 提供 MagicDNS 解析和 DERP 中继支持
/// 仅在启用 `transport_tailscale` feature 时可用
#[cfg(feature = "transport_tailscale")]
pub mod tailscale_dns;

/// Transport utility module
/// Provides common transport utility functions such as timeout handling
///
/// 传输工具模块
/// 提供超时处理等通用传输工具函数
pub mod util;

/// Memory transport module
/// Provides in-memory dialer implementation, mainly for testing
///
/// 内存传输模块
/// 提供基于内存的拨号器实现，主要用于测试
pub mod mem;

/// Retry and backoff strategy module
/// Provides unified retry policies to improve reliability of idempotent I/O operations
///
/// 重试和退避策略模块
/// 提供统一的重试策略，用于提高幂等 I/O 操作的可靠性
pub mod retry;

/// Circuit breaker module
/// Provides lightweight circuit breaker protection to prevent cascading failures
///
/// 熔断器模块
/// 提供轻量级熔断保护，防止级联故障
pub mod circuit_breaker;

/// Resource pressure detection module
/// Provides file descriptor and memory pressure detection and fallback strategies
///
/// 资源压力检测模块
/// 提供文件描述符和内存压力检测与回退策略
pub mod resource_pressure;

// Local metrics helpers to avoid depending on sb-core for registry utilities
#[cfg(feature = "metrics")]
mod metrics_ext;

/// Transport chain builder
/// Provides convenient builder for composing TCP -> TLS -> WebSocket/HTTP2 layers
///
/// 传输链构建器
/// 提供用于组合 TCP -> TLS -> WebSocket/HTTP2 等层的便捷构建器
pub mod builder;

// Re-exports for a stable public surface
// 重新导出核心类型，提供稳定的公开 API 接口
pub use dialer::*;

#[cfg(feature = "transport_tls")]
pub use tls::*;

#[cfg(feature = "transport_tls")]
pub use tls_secure::*;

#[cfg(feature = "transport_reality")]
pub use tls::RealityDialer;

#[cfg(feature = "transport_ech")]
pub use tls::EchDialer;

pub use circuit_breaker::*;
pub use mem::*;
pub use resource_pressure::*;
pub use retry::*;
pub use util::*;

// Re-export builder for convenience
pub use builder::TransportBuilder;

#[cfg(feature = "failpoints")]
pub use failpoint_dialer::*;
