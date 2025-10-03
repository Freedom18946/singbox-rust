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
    clippy::missing_docs_in_private_items
)] // CLI tools allow relaxed linting

pub mod auth;
#[cfg(feature = "bench-cli")]
pub mod bench;
pub mod buildinfo;
pub mod check;
pub mod completion;
pub mod generate;
#[cfg(feature = "dev-cli")]
pub mod fs_scan;
#[cfg(feature = "dev-cli")]
pub mod health;
pub mod json;
#[cfg(feature = "manpage")]
pub mod man;
pub mod output;
#[cfg(feature = "prefetch")]
pub mod prefetch;
pub mod prom;
#[cfg(feature = "dev-cli")]
pub mod report;
#[cfg(feature = "router")]
pub mod route;
#[cfg(feature = "router")]
pub mod run;
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
    /// 生成 man page
    #[cfg(feature = "manpage")]
    Man(man::ManArgs),
    /// Run main service (existing)
    #[cfg(feature = "router")]
    Run(run::RunArgs),
    #[cfg(feature = "router")]
    /// Route explain and test
    Route(route::RouteArgs),
    /// Display version information
    Version(VersionArgs),
}

#[derive(Parser, Debug, Clone, Copy)]
pub struct VersionArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}
