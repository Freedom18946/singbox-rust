//! # sb-api: API Services for singbox-rust / singbox-rust API 服务
//!
//! This crate provides the control plane for the singbox-rust proxy server. It implements
//! HTTP and WebSocket APIs compatible with Clash and V2Ray, enabling external controllers
//! (dashboards, CLIs) to manage and monitor the system.
//!
//! 本 crate 提供了 singbox-rust 代理服务的控制平面。它实现了兼容 Clash 和 V2Ray 的
//! HTTP 和 WebSocket API，允许外部控制器（如仪表盘、命令行工具）管理和监控系统。
//!
//! ## Global Strategy / 全局战略
//!
//! - **Control Plane / 控制平面**: `sb-api` sits above `sb-core` (data plane). It does not handle
//!   actual traffic proxying but exposes the state of `sb-core` and allows dynamic configuration.
//!   `sb-api` 位于 `sb-core`（数据平面）之上。它不处理实际的流量代理，而是暴露 `sb-core`
//!   的状态并允许动态配置。
//!
//! - **Compatibility / 兼容性**: By implementing standard Clash and V2Ray APIs, it allows
//!   users to use existing ecosystems of tools (e.g., Yacd, Metacubexd) with singbox-rust.
//!   通过实现标准的 Clash 和 V2Ray API，它允许用户在 singbox-rust 上使用现有的工具生态系统
//!   （例如 Yacd, Metacubexd）。
//!
//! - **Module Relationships / 模块关系**:
//!   - Depends on `sb-core` for internal types and logic. / 依赖 `sb-core` 获取内部类型和逻辑。
//!   - Depends on `sb-config` for configuration structures. / 依赖 `sb-config` 获取配置结构。
//!   - Used by the main application entry point to spawn API servers. / 被主应用程序入口点用于启动 API 服务器。

#![deny(unused_must_use)]
#![warn(missing_docs)]

pub mod error;
pub mod managers;
pub mod monitoring;
pub mod types;

#[cfg(feature = "clash-api")]
pub mod clash;

pub mod v2ray;

// Re-export main API types
pub use error::{ApiError, ApiResult};
pub use monitoring::{MonitoringSystem, MonitoringSystemHandle, ReportConfig};
pub use types::*;

#[cfg(feature = "clash-api")]
pub use clash::ClashApiServer;

#[cfg(feature = "v2ray-api")]
pub use v2ray::V2RayApiServer;
