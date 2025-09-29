//! sb-core 顶层 HTTP 聚合模块
//!
//! 目标：
//! - 为 `lib.rs` 中的 `pub mod http;` 提供实体文件，解除编译阻塞。
//! - 以"重导出"的方式**聚合**已有实现，不改变现有模块结构与依赖。
//! - 后续如需通用 HTTP 工具，可在此模块内逐步补充。
//!
//! 现有实现位置：
//! - `crate::metrics::http`    —— 指标导出/抓取相关
//! - `crate::admin::http`      —— 管理端点相关

// 重导出现有子模块，便于上层通过 `sb_core::http::metrics` / `sb_core::http::admin` 访问
pub use crate::admin::http as admin;
pub use crate::metrics::http as metrics;

// 将来可在此扩展通用 HTTP 组件：
// pub mod client;
// pub mod server;
