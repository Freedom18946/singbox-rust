//! singbox-rust — Entrypoint (P1.2)
//!
//! # Global Strategic Logic / 全局战略逻辑
//!
//! This is the application entry point. Its primary responsibility is **Lifecycle Management** and **Environment Initialization**.
//! It acts as the "Command Dispatcher" rather than the core logic engine.
//!
//! 本文件是应用程序入口点。其主要职责是 **生命周期管理** 和 **环境初始化**。
//! 它充当“命令分发器”，而非核心逻辑引擎。
//!
//! ## Key Responsibilities / 核心职责
//! 1. **Tracing Initialization / 链路追踪初始化**: Sets up the global logging and telemetry system before any logic runs.
//! 2. **CLI Parsing / 命令行解析**: Parses arguments to determine the operation mode (Check, Run, Route, etc.).
//! 3. **Config Loading / 配置加载**: For the `run` command, it triggers the loading of the configuration file.
//! 4. **Feature Gating / 特性门控**: Dispatches commands based on enabled compile-time features (e.g., `router`, `admin_debug`).
//!
//! ## Strategic Relations / 战略关联
//! - **Upstream**: Invoked by the OS process manager.
//! - **Downstream**:
//!     - `app::bootstrap`: Used by `run` command to initialize the actual proxy runtime.
//!     - `app::cli`: Delegates specific command logic to submodules.
//!     - `sb_config`: Used for configuration parsing and validation.

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
    // 优先解析 CLI，以便我们可以选择性地从配置中派生日志设置
    let args = cli::Args::parse();

    // Best-effort: derive logging from config before initializing
    // 尽力而为：在初始化之前从配置中派生日志设置
    // This allows the user to control logging levels via the config file,
    // which is critical for debugging startup issues.
    // 这允许用户通过配置文件控制日志级别，这对于调试启动问题至关重要。
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
    // 初始化增强日志系统（环境变量 + 上述可选覆盖）
    logging::init_logging()?;

    #[cfg(feature = "failpoints")]
    sb_core::util::failpoint::init_from_env();

    app::panic::install();

    #[cfg(feature = "hardening")]
    app::hardening::apply();

    // Global Guard: Remove sensitive env vars if GA guard is active (default)
    // 全局守卫：如果 GA 守卫处于活动状态（默认），则移除敏感环境变量
    let ga = std::env::var("SB_GA_GUARD").unwrap_or_else(|_| "1".to_string());
    if ga == "0" {
        std::env::remove_var("SB_SELECT_P3");
        std::env::remove_var("SB_RULE_COVERAGE");
        std::env::remove_var("SB_DEBUG_ADDR");
    }

    // Command Dispatch / 命令分发
    // Routes execution to the appropriate submodule based on the parsed command.
    // 根据解析的命令将执行路由到相应的子模块。
    match args.command {
        cli::Commands::Check(a) => {
            let code = cli::check::run(a)?;
            std::process::exit(code);
        }
        #[cfg(feature = "prefetch")]
        cli::Commands::Prefetch(a) => cli::prefetch::main(a),
        cli::Commands::Auth(a) => cli::auth::main(a),
        cli::Commands::Prom(a) => cli::prom::main(a),
        #[cfg(feature = "dev-cli")]
        cli::Commands::Report(a) => cli::report::main(a),
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
        #[cfg(feature = "router")]
        cli::Commands::Dns(a) => {
            cli::dns_cli::run(a)?;
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

    let path = path_opt?;

    // If stdin indicated, skip (cannot pre-read here safely)
    if path.trim() == "-" {
        return None;
    }

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
