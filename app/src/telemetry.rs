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
    use std::sync::Arc;

    #[must_use]
    pub fn next_trace_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
        static CTR: AtomicU64 = AtomicU64::new(1);
        let n = CTR.fetch_add(1, SeqCst);
        format!("{:016x}", n ^ fastrand::u64(..))
    }

    /// Initialize tracing for the current runtime.
    ///
    /// # Errors
    ///
    /// Returns the subscriber installation error when tracing setup fails.
    pub fn init_tracing(_deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {
        #[cfg(feature = "dev-cli")]
        {
            crate::tracing_init::init_tracing_once()?;
        }
        Ok(())
    }

    /// Initialize metrics exporter.
    /// Initialize the metrics exporter for the current runtime.
    ///
    /// # Errors
    ///
    /// Returns any exporter startup error from the explicit metrics bootstrap.
    pub fn init_metrics_exporter(deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {
        #[cfg(feature = "dev-cli")]
        {
            crate::tracing_init::init_metrics_exporter_once(deps.metrics_registry())
        }
        #[cfg(not(feature = "dev-cli"))]
        {
            let _ = deps;
            Ok(())
        }
    }

    #[must_use]
    pub fn init_and_listen(
        deps: &crate::runtime_deps::AppRuntimeDeps,
    ) -> Option<crate::admin_debug::http_server::AdminDebugHandle> {
        // Metrics exporter integration point - admin_debug provides HTTP metrics endpoint
        #[cfg(feature = "admin_debug")]
        {
            Some(crate::admin_debug::init(None, Arc::clone(&deps.admin_state())))
        }
        #[cfg(not(feature = "admin_debug"))]
        {
            let _ = deps;
            None
        }
    }
}

#[cfg(not(feature = "observe"))]
mod imp {
    use anyhow::Result;

    #[must_use]
    pub const fn next_trace_id() -> String {
        String::new()
    }

    pub const fn init_tracing(_deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {
        // NOP for minimal
        Ok(())
    }

    /// Initialize metrics exporter.
    pub const fn init_metrics_exporter(_deps: &crate::runtime_deps::AppRuntimeDeps) -> Result<()> {
        // NOP for minimal
        Ok(())
    }

    pub fn init_and_listen(_deps: &crate::runtime_deps::AppRuntimeDeps) {
        // NOP for minimal
    }
}

pub use imp::*;
