//! Routing explain system
//! 路由解释系统
//!
//! # Routing Engine / 路由引擎
//! The routing engine is responsible for matching traffic against a set of rules
//! and deciding the target outbound.
//! 路由引擎负责将流量与一组规则进行匹配，并决定目标出站。
//!
//! ## Components / 组件
//! - [`matcher`]: Matches traffic against rules (Domain, IP, Protocol, etc.).
//!   将流量与规则（域名、IP、协议等）进行匹配。
//! - [`explain`]: Provides detailed explanation of routing decisions (for debugging/UI).
//!   提供路由决策的详细解释（用于调试/UI）。
//! - [`trace`]: Traces the path of a packet through the routing system.
//!   跟踪数据包在路由系统中的路径。

pub mod engine;
pub mod explain;
pub mod ir;
pub mod trace;

pub mod matcher;
pub mod router;
// Sniffing utilities live under `router::sniff`; re-export here for routing users.
// 嗅探工具位于 `router::sniff` 下；在此重新导出以供路由用户使用。
pub use crate::router::sniff;

// Re-export commonly used types from submodules
// 从子模块重新导出常用类型
pub use explain::{ExplainDto, ExplainEngine, ExplainResult};
pub use trace::Trace;
