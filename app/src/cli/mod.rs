//! CLI Module / 命令行模块
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module acts as the **User Interface Layer** of the application.
//! It is responsible for parsing user inputs, dispatching commands, and formatting outputs.
//!
//! 本模块充当应用程序的 **用户界面层**。
//! 它负责解析用户输入、分发命令和格式化输出。
//!
//! ## Architectural Role / 架构角色
//! - **Parser**: Uses `clap` to define and parse the command-line interface.
//! - **Dispatcher**: Routes parsed commands to specific handlers (e.g., `run`, `check`, `route`).
//! - **Facade**: Hides the complexity of the underlying core modules from the end user.
//!
//! ## Strategic Decision: Lint Relaxation / 战略决策：Lint 放宽
//! CLI tools often require more flexible coding styles (e.g., printing to stdout, complex arguments).
//! Therefore, we intentionally relax certain lints here to prioritize **Ergonomics** over strict purity.
//! CLI 工具通常需要更灵活的编码风格（例如，打印到 stdout，复杂的参数）。
//! 因此，我们在此有意放宽某些 lint，以优先考虑 **易用性** 而非严格的纯洁性。

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::implicit_hasher,
    clippy::field_reassign_with_default,
    // Additional relaxations for CLI tools
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    clippy::needless_pass_by_value,
    clippy::enum_variant_names,
    clippy::vec_init_then_push,
    clippy::double_must_use,
    clippy::used_underscore_binding,
    clippy::significant_drop_tightening,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_wraps,
    clippy::redundant_else,
    clippy::match_same_arms,
    clippy::if_not_else,
    clippy::map_unwrap_or,
    clippy::let_underscore_untyped,
    // Additional style relaxations
    clippy::ref_option,
    clippy::use_debug,
    clippy::format_push_string,
    clippy::assigning_clones,
    clippy::fn_params_excessive_bools,
    clippy::ifs_same_cond,
    clippy::if_same_then_else,
    clippy::option_if_let_else,
    clippy::manual_let_else,
    clippy::items_after_statements,
    clippy::single_match_else,
    clippy::should_implement_trait,
    clippy::struct_excessive_bools,
    clippy::branches_sharing_code,
    clippy::trivial_regex,
    clippy::if_then_some_else_none,
    clippy::collection_is_never_read,
    clippy::future_not_send,
    clippy::missing_docs_in_private_items,
    // Style/ergonomics often noisy in CLI/test helpers
    clippy::redundant_clone,
    clippy::single_char_pattern
)] // CLI tools allow relaxed linting

pub mod auth;
#[cfg(feature = "bench-cli")]
pub mod bench;
pub mod buildinfo;
pub mod check;
pub mod completion;
#[cfg(feature = "router")]
pub mod dns_cli;
pub mod format;
#[cfg(feature = "dev-cli")]
pub mod fs_scan;
pub mod generate;
#[cfg(feature = "router")]
pub mod geoip;
#[cfg(feature = "router")]
pub mod geosite;
#[cfg(feature = "dev-cli")]
pub mod health;
pub mod help;
pub mod json;
#[cfg(feature = "manpage")]
pub mod man;
pub mod merge;
pub mod output;
#[cfg(feature = "prefetch")]
pub mod prefetch;
pub mod prom;
#[cfg(feature = "dev-cli")]
pub mod report;
#[cfg(feature = "router")]
pub mod route;
#[cfg(feature = "router")]
pub mod ruleset;
#[cfg(feature = "router")]
pub mod run;
#[cfg(feature = "tools")]
pub mod tools;
pub mod version;

use clap::{Parser, Subcommand, ValueEnum};

/// Output format for CLI commands
#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum Format {
    /// Human-readable output
    Human,
    /// JSON output
    Json,
    /// SARIF output (for check command)
    Sarif,
}

#[derive(Parser, Debug)]
#[command(name = "app")]
#[command(about = "Sing CLI", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Validate configuration without starting I/O
    Check(check::CheckArgs),
    /// 预取相关工具
    #[cfg(feature = "prefetch")]
    Prefetch(prefetch::PrefetchArgs),
    /// 鉴权相关工具（签名/重放）
    Auth(auth::AuthArgs),
    /// Prometheus 指标工具（抓取/直方图）
    Prom(prom::PromArgs),
    /// 简易 I/O 基准（HTTP）
    #[cfg(feature = "bench-cli")]
    Bench(bench::BenchArgs),
    /// 生成 shell 补全脚本
    GenCompletions(completion::CompletionArgs),
    /// Generate cryptographic keys (REALITY, ECH)
    Generate(generate::GenerateArgs),
    /// Merge configuration files/directories
    Merge(merge::MergeArgs),
    /// Format configuration files
    Format(format::FormatArgs),
    /// `GeoIP` tooling (list/lookup/export)
    #[cfg(feature = "router")]
    Geoip(geoip::GeoipArgs),
    /// Geosite tooling (list/lookup/export/matcher)
    #[cfg(feature = "router")]
    Geosite(geosite::GeositeArgs),
    /// Rule-set management (validate/compile/etc.)
    #[cfg(feature = "router")]
    Ruleset(ruleset::RulesetArgs),
    /// 生成 man page
    #[cfg(feature = "manpage")]
    Man(man::ManArgs),
    /// Run main service (existing)
    #[cfg(feature = "router")]
    Run(run::RunArgs),
    #[cfg(feature = "router")]
    /// Route explain and test
    Route(route::RouteArgs),
    /// DNS tools (query/cache/upstream)
    #[cfg(feature = "router")]
    Dns(dns_cli::DnsArgs),
    /// Utility helpers (connect/fetch/synctime)
    #[cfg(feature = "tools")]
    Tools(tools::ToolsArgs),
    /// Display version information
    Version(VersionArgs),
}

#[derive(Parser, Debug, Clone, Copy)]
pub struct VersionArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}
