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
//!
//! # Global Strategic Logic / 全局战略逻辑
//!
//! This crate serves as the **Library Core** of the application. Unlike `main.rs` which is the executable entry point,
//! this library exposes the functional modules that can be reused or tested independently.
//!
//! 本 crate 充当应用程序的 **库核心**。与作为可执行入口点的 `main.rs` 不同，
//! 本库暴露了可以独立复用或测试的功能模块。
//!
//! ## Strategic Design / 战略设计
//! - **Modularity / 模块化**: Features are heavily gated (e.g., `router`, `admin_debug`) to allow for minimal builds.
//!   This is crucial for mobile or embedded targets where binary size matters.
//!   特性被严格门控（例如 `router`, `admin_debug`），以允许最小化构建。这对于关注二进制大小的移动或嵌入式目标至关重要。
//! - **Facade Pattern / 外观模式**: It re-exports core functionality from `sb-core` and other crates, acting as a unified facade for the binary.
//!   它重新导出 `sb-core` 和其他 crate 的核心功能，充当二进制文件的统一外观。
//!
//! ## Note / 说明
//! The actual bootstrap logic has moved to `bin/main.rs` and `bootstrap.rs`.
//! This file now primarily manages module exports and lint configurations.
//! 真正的引导流程已经迁到 `bin/main.rs` 和 `bootstrap.rs`。
//! 本文件现在主要管理模块导出和 lint 配置。

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
pub mod run_engine;
#[cfg(feature = "router")]
pub mod reqwest_http;
pub mod telemetry;
#[cfg(feature = "dev-cli")]
pub mod tracing_init;
pub mod util;

// Router facade - available always, but functionality gated by feature
pub mod router;

pub mod inbound_starter;

// Allow referencing the crate by name `app` within this crate as well
extern crate self as app;
