//! Core protocol implementations and routing engine for `SingBox`
//! `SingBox` 的核心协议实现和路由引擎
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This crate is the **Heart** of the application, containing the business logic.
//! 本 crate 是应用程序的 **心脏**，包含业务逻辑。
//!
//! ## Strategic Architecture / 战略架构
//! - **Protocols / 协议**: Implements all Inbound/Outbound protocols (SOCKS, HTTP, VLESS, etc.).
//!   实现所有入站/出站协议（SOCKS, HTTP, VLESS 等）。
//! - **Routing / 路由**: The decision engine that matches traffic against rules and dispatches it to the correct outbound.
//!   决策引擎，将流量与规则匹配并将其分发到正确的出站。
//! - **Runtime / 运行时**: Manages the lifecycle of the proxy, including startup, hot-reload, and graceful shutdown.
//!   管理代理的生命周期，包括启动、热重载和优雅关闭。
//!
//! ## Module Organization / 模块组织
//! - [`inbound`] / [`outbound`]: Protocol implementations.
//!   协议实现。
//! - [`router`]: The routing logic (Rule matching, GeoIP/Geosite lookup).
//!   路由逻辑（规则匹配，GeoIP/Geosite 查找）。
//! - [`runtime`]: The supervisor and event loop.
//!   监督者和事件循环。
//!
//! ```rust,no_run
//! use sb_core::runtime::Supervisor;
//! use sb_config::Config;
//!
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! // Load config
//! let config = Config::load("config.json").unwrap();
//!
//! // Start runtime supervisor
//! let supervisor = Supervisor::start(config.ir().clone()).await.unwrap();
//!
//! // Shutdown gracefully
//! supervisor
//!     .shutdown_graceful(std::time::Duration::from_secs(1))
//!     .await
//!     .unwrap();
//! # });
//! ```

pub mod adapter;
pub mod adapter_error;
pub mod context;
pub mod error;
pub mod error_map;
pub mod errors;
pub mod health;
/// Inbound protocol implementations and manager.
/// 入站协议实现和管理器。
pub mod inbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod log;
pub mod metrics;
pub mod net;
/// Outbound protocol implementations and manager.
/// 出站协议实现和管理器。
pub mod outbound; // <— 新增导出，供 bridge/scaffold 使用
/// Pipeline utilities for adapters.
/// 适配器的管道工具。
pub mod pipeline; // <— 新增导出，供适配器使用
#[cfg(feature = "router")]
/// Routing engine and rule matching.
/// 路由引擎和规则匹配。
pub mod routing;
pub mod udp_nat_instrument;
// Expose legacy router module for compatibility with external crates
#[cfg(feature = "router")]
pub mod router;
/// Runtime supervisor and event loop.
/// 运行时监督者和事件循环。
pub mod runtime;
pub mod session;
pub mod socks5;
pub mod subscribe;
pub mod telemetry;
pub mod transport;
pub mod types;
pub mod util;
pub mod admin {
    pub mod http;
}
pub mod dns;
pub mod geoip;
pub mod http;

pub mod obs;

/// Debug and diagnostics HTTP server.
/// 调试和诊断 HTTP 服务器。
pub mod diagnostics;

// Endpoint management (WireGuard, Tailscale, etc.)
pub mod endpoint;

// Service management (Resolved, DERP, SSM, etc.) with trait definitions and registry
/// Background service management (Resolved, DERP, SSM, etc.).
/// 后台服务管理（Resolved, DERP, SSM 等）。
pub mod service;

// Optional runtime services (e.g., NTP). Legacy module for compatibility.
// New services should use the service module above.
pub mod services;

// 别名模块：为兼容性提供简短的模块名
pub mod observe {
    pub use crate::outbound::observe::*;
}

// TLS utilities
pub mod tls;

pub use adapter::*; // 兼容 re-export

#[cfg(test)]
mod testutil;
