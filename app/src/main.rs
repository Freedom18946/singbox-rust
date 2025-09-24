//! singbox-rust — entrypoint（P1.2）
//! - tracing 初始化
//! - （可选）Prometheus /metrics 暴露（feature=metrics）
//! - 路由 + OutboundRegistry：配置加载 & 热更新
//! - 入站：HTTP CONNECT（真实路由 + 上游出站）

#[cfg(feature = "admin_debug")]
mod admin_debug;
#[cfg(feature = "router")]
mod bootstrap;
mod cli;
mod config_loader;
mod env_dump;
mod tracing_init;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse();

    #[cfg(feature = "chaos")]
    sb_core::util::failpoint::init_from_env();

    #[cfg(feature = "panic_log")]
    singbox_rust::panic::install();

    #[cfg(feature = "hardening")]
    singbox_rust::hardening::apply();

    let ga = std::env::var("SB_GA_GUARD").unwrap_or_else(|_| "1".to_string());
    if ga == "0" {
        std::env::remove_var("SB_SELECT_P3");
        std::env::remove_var("SB_RULE_COVERAGE");
        std::env::remove_var("SB_DEBUG_ADDR");
    }

    match args.command {
        cli::Commands::Run(a) => cli::run::run(a).await,
        cli::Commands::Check(a) => {
            let code = cli::check::run(a)?;
            std::process::exit(code);
        }
        cli::Commands::Route(a) => {
            cli::route::run(a)?;
            Ok(())
        }
    }
}
