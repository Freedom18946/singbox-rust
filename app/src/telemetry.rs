//! Telemetry and Tracing Abstraction
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module provides a **Unified Abstraction Layer** for telemetry (metrics and tracing).
//! It abstracts away the differences between "Observe" (full telemetry) and "Minimal" (no-op) builds.
//!
//! 本模块为遥测（指标和链路追踪）提供了一个 **统一抽象层**。
//! 它抽象了“观测”（全量遥测）和“最小化”（无操作）构建之间的差异。
//!
//! ## Strategic Design / 战略设计
//! - **Conditional Compilation / 条件编译**: Uses `#[cfg(feature = "observe")]` to switch implementations at compile time.
//!   使用 `#[cfg(feature = "observe")]` 在编译时切换实现。
//! - **Zero-Cost Abstraction / 零成本抽象**: In minimal builds, functions are `const` or empty, ensuring zero runtime overhead.
//!   在最小化构建中，函数是 `const` 或空的，确保零运行时开销。

#[cfg(feature = "observe")]
mod imp {
    use anyhow::Result;

    #[must_use]
    pub fn next_trace_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
        static CTR: AtomicU64 = AtomicU64::new(1);
        let n = CTR.fetch_add(1, SeqCst);
        format!("{:016x}", n ^ fastrand::u64(..))
    }

    pub fn init_tracing() {
        #[cfg(feature = "dev-cli")]
        crate::tracing_init::init_tracing_once();
    }

    /// Initialize metrics exporter.
    ///
    /// # Errors
    /// Currently never fails, but returns `Result` for future extensibility.
    pub fn init_metrics_exporter() -> Result<()> {
        #[cfg(feature = "dev-cli")]
        crate::tracing_init::init_metrics_exporter_once();
        Ok(())
    }

    pub async fn init_and_listen() {
        // Metrics exporter integration point - admin_debug provides HTTP metrics endpoint
        #[cfg(feature = "admin_debug")]
        crate::admin_debug::init(None).await;
    }
}

#[cfg(not(feature = "observe"))]
mod imp {
    use anyhow::Result;

    #[must_use]
    pub const fn next_trace_id() -> String {
        String::new()
    }

    pub const fn init_tracing() {
        // NOP for minimal
    }

    /// Initialize metrics exporter.
    ///
    /// # Errors
    /// Currently never fails, but returns `Result` for future extensibility.
    pub const fn init_metrics_exporter() -> Result<()> {
        // NOP for minimal
        Ok(())
    }

    #[allow(clippy::unused_async)] // Conditional: async needed for observe feature
    pub async fn init_and_listen() {
        // NOP for minimal
    }
}

pub use imp::*;
