//! Config loading and hot-reload functionality
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module manages the **Configuration Lifecycle** and **Dynamic Updates**.
//! 本模块管理 **配置生命周期** 和 **动态更新**。
//!
//! ## Key Concepts / 核心概念
//! - **Loading / 加载**: Reads configuration from file or arguments.
//! - **Validation / 验证**: Ensures the configuration is semantically correct before applying.
//! - **Hot Reload / 热重载**: Watches the configuration file for changes and applies updates transactionally without restarting the process.
//!   监视配置文件的更改，并在不重启进程的情况下事务性地应用更新。
//!
//! ## Hot Reload Strategy / 热重载策略
//! The hot reload mechanism uses a "Watcher" loop:
//! 1. **Watch**: Monitor file system events for the config file.
//! 2. **Debounce**: Wait for a short period to ensure the write is complete.
//! 3. **Reload**: Load the new config -> Validate -> Build IR -> Update Router/Registry.
//!    If any step fails, the update is aborted, and the old configuration remains active (Safe Fallback).
//!    如果任何步骤失败，更新将被中止，旧配置保持活动状态（安全回退）。

#![allow(clippy::missing_errors_doc, clippy::cognitive_complexity)]

#[cfg(feature = "dev-cli")]
use anyhow::Result;
#[cfg(feature = "dev-cli")]
use std::path::Path;

#[cfg(feature = "router")]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub fn load_from_path(path: &Path) -> Result<sb_config::Config> {
    sb_config::Config::load(path)
}

#[cfg(not(feature = "router"))]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub fn load_from_path(path: &Path) -> Result<sb_config::Config> {
    // minimal 与 router 一致的读法，保持签名不变
    Ok(sb_config::Config::load(path)?)
}

/// 仅用于 `--check`：解析并构建 Router/Outbound，不触发任何 IO/监听。
/// 返回 (inbounds, outbounds, rules) 便于主程序打印摘要。
#[cfg(feature = "dev-cli")]
pub fn check_only<P: AsRef<Path>>(path: P) -> Result<(usize, usize, usize)> {
    let cfg = sb_config::Config::load(&path)?;
    cfg.validate()?;
    // 构建以验证引用完整性/默认值语义，但不启动任何任务
    cfg.build_registry_and_router()?; // Stub validation
    Ok(cfg.stats())
}
