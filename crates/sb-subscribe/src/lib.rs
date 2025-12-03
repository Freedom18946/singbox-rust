//! # sb-subscribe: Subscription Processing Engine / 订阅处理引擎
//!
//! [English]
//! This crate serves as the core engine for processing proxy subscriptions. It abstracts the complexity
//! of different subscription formats (Clash, Sing-box) into a unified Intermediate Representation (IR).
//! It provides a suite of "offline" utilities including parsing, conversion, diffing, linting, and
//! previewing, which are essential for the upper-layer application logic.
//!
//! [Chinese]
//! 本 crate 是代理订阅处理的核心引擎。它将不同订阅格式（Clash, Sing-box）的复杂性抽象为统一的
//! 中间表示（IR）。它提供了一套“离线”工具，包括解析、转换、差异对比、Lint 检查和预演，
//! 这些对于上层应用逻辑至关重要。
//!
//! ## Feature Flags / 特性开关
//!
//! - `subs_http`: Enables HTTP fetching capabilities. / 启用 HTTP 获取能力。
//! - `subs_clash`: Enables parsing of Clash format subscriptions. / 启用 Clash 格式订阅解析。
//! - `subs_singbox`: Enables parsing of Sing-box format subscriptions. / 启用 Sing-box 格式订阅解析。
//! - `subs_view`: Enables generation of JSON views for UI. / 启用用于 UI 的 JSON 视图生成。
//! - `subs_full`: Enables full aggregation (DSL + View + Bindings). / 启用全量聚合（DSL + 视图 + 绑定）。
//! - `subs_diff`: Enables subscription diffing logic. / 启用订阅差异对比逻辑。
//! - `subs_lint`: Enables static analysis (linting) of rules. / 启用规则静态分析（Lint）。
//! - `subs_preview_plan`: Enables previewing changes before applying. / 启用应用前的变更预演。

#[cfg(feature = "subs_bindings")]
pub mod bindings;
#[cfg(feature = "subs_full")]
pub mod convert_full;
#[cfg(any(feature = "subs_view", feature = "subs_hash"))]
pub mod convert_view;
#[cfg(feature = "subs_diff")]
pub mod diff_full;
#[cfg(feature = "subs_http")]
pub mod http;
#[cfg(feature = "subs_lint")]
pub mod lint;
#[cfg(any(feature = "subs_lint_patch", feature = "subs_lint"))]
pub mod lint_fix;
pub mod model;
#[cfg(feature = "subs_clash")]
pub mod parse_clash;
#[cfg(feature = "subs_singbox")]
pub mod parse_singbox;
#[cfg(feature = "subs_preview_plan")]
pub mod preview_plan;
#[cfg(feature = "subs_ruleset_cache")]
pub mod providers;

/// Read-only merge statistics helper (can be connected to metrics later).
/// [Chinese] 只读合并辅助计数（可后续接 metrics）。
#[derive(Default, Debug, Clone)]
pub struct MergeStats {
    pub applied_ruleset: usize,
    pub applied_geosite: usize,
    pub skipped_unknown: usize,
}

#[cfg(test)]
fn _hash_for_test(_s: &str) -> String {
    #[cfg(feature = "subs_hash")]
    {
        format!("{}", blake3::hash(_s.as_bytes()).to_hex())
    }
    #[cfg(not(feature = "subs_hash"))]
    {
        "disabled".to_string()
    }
}
