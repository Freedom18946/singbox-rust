//! singbox-rust — entrypoint（P1.2）
//! - tracing 初始化
//! - （可选）Prometheus /metrics 暴露（feature=metrics）
//! - 路由 + OutboundRegistry：配置加载 & 热更新
//! - 入站：HTTP CONNECT（真实路由 + 上游出站）

#[cfg(feature = "admin_debug")]
mod admin_debug;
#[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
mod analyze;
#[cfg(feature = "router")]
mod bootstrap;
mod cli;
mod config_loader;
mod env_dump;
mod logging;
mod router;
mod tracing_init;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize enhanced logging system
    logging::init_logging()?;

    let args = cli::Args::parse();

    #[cfg(feature = "failpoints")]
    sb_core::util::failpoint::init_from_env();

    #[cfg(feature = "panic_log")]
    app::panic::install();

    #[cfg(feature = "hardening")]
    app::hardening::apply();

    let ga = std::env::var("SB_GA_GUARD").unwrap_or_else(|_| "1".to_string());
    if ga == "0" {
        std::env::remove_var("SB_SELECT_P3");
        std::env::remove_var("SB_RULE_COVERAGE");
        std::env::remove_var("SB_DEBUG_ADDR");
    }

    match args.command {
        cli::Commands::Check(a) => {
            let code = cli::check::run(a)?;
            std::process::exit(code);
        }
        #[cfg(feature = "prefetch")]
        cli::Commands::Prefetch(a) => cli::prefetch::main(a),
        cli::Commands::Auth(a) => cli::auth::main(a),
        cli::Commands::Prom(a) => cli::prom::main(a).await,
        #[cfg(feature = "bench-cli")]
        cli::Commands::Bench(a) => cli::bench::main(a).await,
        cli::Commands::GenCompletions(a) => {
            cli::completion::main(a)?;
            Ok(())
        }
        cli::Commands::Generate(a) => {
            cli::generate::run(a)?;
            Ok(())
        }
        cli::Commands::Merge(a) => {
            cli::merge::run(a).await?;
            Ok(())
        }
        cli::Commands::Format(a) => {
            cli::format::run(a).await?;
            Ok(())
        }
        #[cfg(feature = "router")]
        cli::Commands::Geoip(a) => {
            cli::geoip::run(a).await?;
            Ok(())
        }
        #[cfg(feature = "router")]
        cli::Commands::Geosite(a) => {
            cli::geosite::run(a).await?;
            Ok(())
        }
        #[cfg(feature = "router")]
        cli::Commands::Ruleset(a) => {
            cli::ruleset::run(a).await?;
            Ok(())
        }
        #[cfg(feature = "manpage")]
        cli::Commands::Man(a) => {
            cli::man::main(a)?;
            Ok(())
        }
        #[cfg(feature = "router")]
        cli::Commands::Run(a) => cli::run::run(a).await,
        #[cfg(feature = "router")]
        cli::Commands::Route(a) => {
            cli::route::run(a)?;
            Ok(())
        }
        #[cfg(feature = "tools")]
        cli::Commands::Tools(a) => {
            cli::tools::run(a).await?;
            Ok(())
        }
        cli::Commands::Version(a) => {
            cli::version::run(a)?;
            Ok(())
        }
    }
}
