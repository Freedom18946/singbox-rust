pub mod check;
pub mod buildinfo;
#[cfg(feature = "dev-cli")]
pub mod fs_scan;
#[cfg(feature = "dev-cli")]
pub mod report;
#[cfg(feature = "dev-cli")]
pub mod health;
pub mod json;
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

use clap::{Parser, Subcommand};

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
}
