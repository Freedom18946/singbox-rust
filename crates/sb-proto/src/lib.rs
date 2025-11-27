//! Protocol implementations for various proxy protocols.
//! 各种代理协议的协议实现。
//!
//! This crate provides modular implementations of proxy protocols including
//! Shadowsocks 2022 and Trojan, designed for use in the singbox-rust project.
//! 本 crate 提供了包括 Shadowsocks 2022 和 Trojan 在内的代理协议的模块化实现，
//! 专为 singbox-rust 项目设计。
//!
//! # Architecture / 架构
//!
//! - **Core abstractions / 核心抽象** ([`connector`]):
//!   - Base traits for outbound connections.
//!   - 出站连接的基础 trait。
//!   - `OutboundConnector`, `Target`, etc.
//! - **Shadowsocks 2022 variants / Shadowsocks 2022 变体**:
//!   - `ss2022_min`: Minimal implementation (feature: `proto_ss2022_min`)
//!     - 最小化实现（特性：`proto_ss2022_min`）
//!   - `ss2022_core`: Core protocol logic (feature: `proto_ss2022_core`)
//!     - 核心协议逻辑（特性：`proto_ss2022_core`）
//!   - `ss2022_harness`: Testing harness (feature: `proto_ss2022_min`)
//!     - 测试工具（特性：`proto_ss2022_min`）
//! - **Trojan variants / Trojan 变体**:
//!   - `trojan_min`: Minimal implementation (feature: `proto_trojan_min`)
//!     - 最小化实现（特性：`proto_trojan_min`）
//!   - `trojan_dry`: Dry-run connector (feature: `proto_trojan_dry`)
//!     - 空跑连接器（特性：`proto_trojan_dry`）
//!   - `trojan_harness`: Testing harness (feature: `proto_trojan_min`)
//!     - 测试工具（特性：`proto_trojan_min`）
//!
//! # Strategic Role / 战略角色
//!
//! `sb-proto` sits above the transport layer (`sb-transport`) and provides the application-level
//! protocol logic. It decouples protocol implementation from the underlying transport (TCP/TLS/QUIC),
//! allowing for flexible composition of protocols and transports.
//! `sb-proto` 位于传输层 (`sb-transport`) 之上，提供应用层协议逻辑。
//! 它将协议实现与底层传输（TCP/TLS/QUIC）解耦，允许协议和传输的灵活组合。
//!
//! # Features / 特性
//!
//! - `proto_ss2022_min`: Enables minimal Shadowsocks 2022 implementation
//!   - 启用最小化 Shadowsocks 2022 实现
//! - `proto_ss2022_core`: Enables core Shadowsocks 2022 protocol logic
//!   - 启用核心 Shadowsocks 2022 协议逻辑
//! - `proto_ss2022_tls_first`: Enables TLS-first Shadowsocks 2022 variant
//!   - 启用 TLS 优先的 Shadowsocks 2022 变体
//! - `proto_trojan_min`: Enables minimal Trojan implementation
//!   - 启用最小化 Trojan 实现
//! - `proto_trojan_dry`: Enables dry-run Trojan connector (testing)
//!   - 启用空跑 Trojan 连接器（测试用）
//! - `outbound_registry`: Enables protocol registry for dynamic dispatch
//!   - 启用用于动态分发的协议注册表
//!
//! # Example / 示例
//!
//! ```rust,no_run
//! use sb_proto::{Target, OutboundConnector};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a target / 创建一个目标
//! let target = Target::new("example.com", 443);
//!
//! // Use with any OutboundConnector implementation
//! // 配合任何 OutboundConnector 实现使用
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
