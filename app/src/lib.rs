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
// Allow specific pedantic/nursery lints that are too strict for this project's style
#![allow(clippy::unnecessary_debug_formatting, clippy::useless_let_if_seq)]

//! singbox-rust library crate.
//!
//! Exposes feature-gated runtime, CLI, telemetry, and admin modules for the
//! binaries and integration tests. The active runtime entry is
//! `run_engine::run_supervisor`; legacy bootstrap helpers are retired from
//! production entrypoints and kept only as test-only owner modules where needed.

#[cfg(feature = "admin_debug")]
pub mod admin_debug;
#[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
pub mod analyze;
#[cfg(all(feature = "router", test))]
mod bootstrap_runtime;
pub mod capability_probe;
pub mod cli;
pub mod config_loader;
pub mod core_env;
#[cfg(feature = "router")]
pub(crate) mod dns_env;
#[cfg(feature = "dev-cli")]
pub mod env_dump;
#[cfg(feature = "hardening")]
pub mod hardening;
#[cfg(any(feature = "explain", feature = "rule_coverage"))]
pub mod http_util;
#[cfg(all(feature = "router", test))]
mod outbound_builder;
#[cfg(all(feature = "router", test))]
mod outbound_groups;
#[cfg(feature = "panic_log")]
pub mod panic;
pub mod redact;
#[cfg(feature = "router")]
pub mod reqwest_http;
#[cfg(feature = "router")]
mod router_text;
pub mod run_engine;
pub(crate) mod run_engine_runtime;
pub mod runtime_deps;
// App-level sidecar runtime snapshot adapter + run-engine event bridge
// (APP-SIDECAR-LIVENESS-01F/01G-B/01H-B). Only the run-engine consumes it, and run-engine is
// router-gated, so the module requires `router` plus a sidecar source feature. No blanket
// `allow(dead_code)` — every item is exercised by the run-engine bridge or its tests.
#[cfg(all(feature = "router", any(feature = "clash_api", feature = "v2ray_api")))]
pub(crate) mod sidecar_runtime;
pub mod telemetry;
pub mod tls_provider;
pub mod tracing_init;
pub mod util;

// Router facade - available always, but functionality gated by feature
pub mod router;

pub mod inbound_starter;

// Allow referencing the crate by name `app` within this crate as well
extern crate self as app;
