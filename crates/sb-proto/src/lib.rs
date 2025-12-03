//! Protocol implementations for various proxy protocols.
//! 各种代理协议的协议实现。
//!
//! This crate provides minimal protocol abstractions and packet builders
//! for use in the singbox-rust project. The actual protocol implementations
//! are in the `sb-adapters` crate.
//! 本 crate 为 singbox-rust 项目提供最小化的协议抽象和数据包构建器。
//! 实际的协议实现位于 `sb-adapters` crate 中。
//!
//! # Architecture / 架构
//!
//! - **Core abstractions / 核心抽象** ([`connector`]):
//!   - Base traits for outbound connections.
//!   - 出站连接的基础 trait。
//!   - `OutboundConnector`, `Target`, `IoStream`
//! - **Protocol packet builders / 协议数据包构建器**:
//!   - [`ss2022`]: Shadowsocks 2022 handshake packet builder
//!     - Shadowsocks 2022 握手数据包构建器
//!   - [`trojan`]: Trojan handshake packet builder
//!     - Trojan 握手数据包构建器
//!   - [`trojan_connector`]: Minimal Trojan connector with injectable dialer
//!     - 带可注入拨号器的最小化 Trojan 连接器
//! - **Optional registry / 可选注册表** ([`outbound_registry`], feature-gated):
//!   - Protocol registry for dynamic dispatch in testing
//!   - 用于测试中动态分发的协议注册表
//!
//! # Strategic Role / 战略角色
//!
//! `sb-proto` sits above the transport layer (`sb-transport`) and provides minimal
//! protocol abstractions. It decouples protocol implementation from the underlying
//! transport (TCP/TLS/QUIC). Full protocol implementations are in `sb-adapters`.
//! `sb-proto` 位于传输层 (`sb-transport`) 之上，提供最小化的协议抽象。
//! 它将协议实现与底层传输（TCP/TLS/QUIC）解耦。完整的协议实现位于 `sb-adapters`。
//!
//! # Features / 特性
//!
//! - `outbound_registry`: Enables protocol registry for dynamic dispatch (testing only)
//!   - 启用用于动态分发的协议注册表（仅用于测试）
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

// Explicit module declaration order
pub mod connector;
#[cfg(feature = "outbound_registry")]
pub mod outbound_registry;

pub mod ss2022;
pub mod trojan;
pub mod trojan_connector;

// Re-export core types for convenience
pub use connector::*;
#[cfg(feature = "outbound_registry")]
pub use outbound_registry::*;
pub use ss2022::*;
pub use trojan::*;
pub use trojan_connector::*;
