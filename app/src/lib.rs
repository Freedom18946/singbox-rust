#![cfg_attr(feature = "strict_warnings", deny(warnings))]
#![cfg_attr(
    not(any(
        feature = "metrics",
        feature = "explain",
        feature = "bench",
        feature = "rule_coverage"
    )),
    allow(dead_code, unused_imports, unused_variables)
)]

//! singbox-rust library crate
//! 说明：真正的引导流程已经迁到 `bin/main.rs`；
//! 这里仅保留必要模块的公共导出，避免历史代码拉入过时依赖。

#[cfg(feature = "admin_debug")]
pub mod admin_debug;
#[cfg(any(feature="router", feature="sbcore_rules_tool"))]
pub mod analyze;
pub mod cli;
pub mod config_loader;
pub mod env_dump;
#[cfg(feature = "hardening")]
pub mod hardening;
#[cfg(any(feature = "explain", feature = "rule_coverage"))]
pub mod http_util;
#[cfg(feature = "panic_log")]
pub mod panic;
pub mod telemetry;
pub mod tracing_init;

// 兼容占位：保留 bootstrap 模块（空壳），防止其他地方 `mod bootstrap;` 报错。
#[cfg(feature = "router")]
pub mod bootstrap;
