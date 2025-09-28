pub mod check;
pub mod buildinfo;
pub mod version;
pub mod output;
#[cfg(feature = "dev-cli")]
pub mod fs_scan;
#[cfg(feature = "dev-cli")]
pub mod report;
#[cfg(feature = "dev-cli")]
pub mod health;
pub mod json;
#[cfg(feature = "prefetch")]
pub mod prefetch;
pub mod auth;
pub mod prom;
#[cfg(feature = "bench-cli")]
pub mod bench;
pub mod completion;
#[cfg(feature = "manpage")]
pub mod man;
#[cfg(feature = "router")]
pub mod route;
#[cfg(feature = "router")]
pub mod run;

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

#[derive(Parser, Debug)]
pub struct VersionArgs {
    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}
