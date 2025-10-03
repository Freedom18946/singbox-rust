//! # sb-transport: 传输层抽象库
//!
//! 这个 crate 提供了 singbox-rust 项目的传输层抽象，包括：
//! - `dialer`: 网络连接拨号器抽象和实现
//! - `tls`: TLS 连接包装器（需要 `transport_tls` feature）
//! - `util`: 传输工具函数（如超时处理）
//! - `mem`: 内存传输（用于测试）
//!
//! ## Features
//! - `transport_tls`: 启用 TLS 支持，基于 rustls
//!
//! ## Design Philosophy
//! 该库遵循 singbox-rust 的设计理念：
//! - **boring clarity**: 简单清晰的抽象
//! - **never break userspace**: 保持向后兼容
//! - **good taste**: 优雅的 API 设计
//!
//! R96: 顶层模块导出和重新暴露

/// 网络连接拨号器模块
/// 提供了 `Dialer` trait 和各种拨号器实现
pub mod dialer;
pub mod pool {
    pub mod circuit_breaker;
    pub mod limit;
}

#[cfg(feature = "failpoints")]
pub mod failpoint_dialer;

/// TLS 传输层模块
/// 提供基于 rustls 的 TLS 连接包装器
/// 仅在启用 `transport_tls` feature 时可用
#[cfg(feature = "transport_tls")]
pub mod tls;

#[cfg(feature = "transport_tls")]
pub mod tls_secure;

/// WebSocket 传输层模块
/// 提供基于 tokio-tungstenite 的 WebSocket 连接包装器
/// 仅在启用 `transport_ws` feature 时可用
#[cfg(feature = "transport_ws")]
pub mod websocket;

/// HTTP/2 传输层模块
/// 提供基于 h2 的 HTTP/2 连接包装器
/// 仅在启用 `transport_h2` feature 时可用
#[cfg(feature = "transport_h2")]
pub mod http2;

/// gRPC 传输层模块
/// 提供基于 tonic 的 gRPC tunnel 服务
/// 仅在启用 `transport_grpc` feature 时可用
#[cfg(feature = "transport_grpc")]
pub mod grpc;

/// Multiplex 传输层模块
/// 提供基于 yamux 的连接复用
/// 仅在启用 `transport_mux` feature 时可用
#[cfg(feature = "transport_mux")]
pub mod multiplex;

/// HTTPUpgrade 传输层模块
/// 通过 HTTP/1.1 Upgrade 建立字节流隧道
#[cfg(feature = "transport_httpupgrade")]
pub mod httpupgrade;

/// QUIC 传输层模块
/// 提供基于 quinn 的通用 QUIC 传输
/// 仅在启用 `transport_quic` feature 时可用
#[cfg(feature = "transport_quic")]
pub mod quic;

/// 传输工具模块
/// 提供超时处理等通用传输工具函数
pub mod util;

/// 内存传输模块
/// 提供基于内存的拨号器实现，主要用于测试
pub mod mem;

/// 重试和退避策略模块
/// 提供统一的重试策略，用于提高幂等 I/O 操作的可靠性
pub mod retry;

/// 熔断器模块
/// 提供轻量级熔断保护，防止级联故障
pub mod circuit_breaker;

/// 资源压力检测模块
/// 提供文件描述符和内存压力检测与回退策略
pub mod resource_pressure;

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

pub use circuit_breaker::*;
pub use mem::*;
pub use resource_pressure::*;
pub use retry::*;
pub use util::*;

// Re-export builder for convenience
pub use builder::TransportBuilder;

#[cfg(feature = "failpoints")]
pub use failpoint_dialer::*;
