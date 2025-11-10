// Enforce critical lints; keep pedantic/nursery as warnings to avoid over-failing workspace runs
#![cfg_attr(not(test), deny(clippy::panic))]
#![warn(clippy::unwrap_used, clippy::expect_used)]
#![warn(clippy::pedantic, clippy::nursery, warnings)]
// Allow relaxed linting for tests and non-critical code
#![cfg_attr(
    test,
    allow(
        warnings,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::float_cmp,
        clippy::panic
    )
)]
#![cfg_attr(
    not(any(
        feature = "metrics",
        feature = "explain",
        feature = "bench",
        feature = "rule_coverage"
    )),
    allow(dead_code, unused_imports, unused_variables)
)]
// Allow specific pedantic/nursery lints that are too strict for this project's style
#![allow(clippy::unnecessary_debug_formatting, clippy::useless_let_if_seq)]

//! singbox-rust library crate
//! 说明：真正的引导流程已经迁到 `bin/main.rs`；
//! 这里仅保留必要模块的公共导出，避免历史代码拉入过时依赖。

#[cfg(feature = "admin_debug")]
pub mod admin_debug;
#[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
pub mod analyze;
pub mod cli;
pub mod config_loader;
#[cfg(feature = "dev-cli")]
pub mod env_dump;
#[cfg(feature = "hardening")]
pub mod hardening;
#[cfg(any(feature = "explain", feature = "rule_coverage"))]
pub mod http_util;
#[cfg(feature = "panic_log")]
pub mod panic;
pub mod telemetry;
#[cfg(feature = "dev-cli")]
pub mod tracing_init;
pub mod util;

// Router facade - available always, but functionality gated by feature
pub mod router;

// 兼容占位：保留 bootstrap 模块（空壳），防止其他地方 `mod bootstrap;` 报错。
#[cfg(feature = "router")]
pub mod bootstrap;

// Allow referencing the crate by name `app` within this crate as well
extern crate self as app;
