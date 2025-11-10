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
mod redact;
mod router;
mod tracing_init;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI first so we can optionally derive logging from config
    let args = cli::Args::parse();

    // Best-effort: derive logging from config before initializing
    if let Some((level_opt, format_opt, timestamp_opt)) = try_extract_log_from_args(&args) {
        if let Some(level) = level_opt {
            std::env::set_var("SB_LOG_LEVEL", level);
        }
        if let Some(format) = format_opt {
            // Accept only known values
            if matches!(format.as_str(), "json" | "compact") {
                std::env::set_var("SB_LOG_FORMAT", format);
            }
        }
        if let Some(ts) = timestamp_opt {
            std::env::set_var("SB_LOG_TIMESTAMP", if ts { "1" } else { "0" });
        }
    }

    // Initialize enhanced logging system (env + optional overrides above)
    logging::init_logging()?;

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
        cli::Commands::Prom(a) => cli::prom::main(a),
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
            cli::merge::run(a)?;
            Ok(())
        }
        cli::Commands::Format(a) => {
            cli::format::run(a)?;
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

// Try to locate a config path from CLI args, load it, and extract log overrides.
// Returns (level, format, timestamp) if config contains a top-level `log` block.
fn try_extract_log_from_args(
    args: &cli::Args,
) -> Option<(Option<String>, Option<String>, Option<bool>)> {
    // Determine config path from subcommand
    let path_opt: Option<String> = match &args.command {
        // check -c <path>
        cli::Commands::Check(a) => Some(a.config.clone()),
        // route --config <path>
        #[cfg(feature = "router")]
        cli::Commands::Route(a) => Some(a.config.clone()),
        // run --config <path> or SB_CONFIG env (best-effort)
        #[cfg(feature = "router")]
        cli::Commands::Run(a) => a
            .config_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| std::env::var("SB_CONFIG").ok()),
        _ => None,
    };

    let path = match path_opt {
        Some(p) => p,
        None => return None,
    };

    // If stdin indicated, skip (cannot pre-read here safely)
    if path.trim() == "-" { return None; }

    // Try loading config; ignore errors silently and fall back to env-only logging
    let cfg = match sb_config::Config::load(&path) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let ir = match sb_config::present::to_ir(&cfg) {
        Ok(ir) => ir,
        Err(_) => return None,
    };
    if let Some(log) = ir.log {
        return Some((log.level, log.format, log.timestamp));
    }
    None
}
