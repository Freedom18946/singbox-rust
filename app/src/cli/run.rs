//! Service Daemon / 服务守护进程
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module implements the **Main Service Loop** of the application.
//! 本模块实现了应用程序的 **主服务循环**。
//!
//! ## Core Responsibilities / 核心职责
//! 1. **Initialization / 初始化**: Sets up panic hooks, observability, and loads the initial configuration.
//! 2. **Bootstrapping / 引导**: Invokes `app::bootstrap` to start the proxy runtime.
//! 3. **Hot Reload / 热重载**: Monitors the configuration file for changes and reloads the runtime dynamically.
//! 4. **Signal Handling / 信号处理**: Gracefully handles OS signals (Ctrl+C, SIGTERM) to ensure proper shutdown.
//!
//! ## Strategic Flow / 战略流程
//! `CLI Args` -> `Config Load` -> `Bootstrap` -> `Event Loop (Watch/Signal)` -> `Shutdown`

use anyhow::Result;
use clap::Args;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

use crate::cli::GlobalArgs;
#[cfg(feature = "dev-cli")]
use crate::env_dump;
use app::config_loader;

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(long = "http", value_parser = parse_addr)]
    http_listen: Option<SocketAddr>,

    /// Subscription import path
    #[arg(short = 'i', long = "import")]
    import_path: Option<PathBuf>,

    /// Watch configuration files for changes (polling)
    #[arg(short = 'w', long = "watch", default_value_t = false)]
    watch: bool,

    /// 只做配置检查：解析+构建，零副作用；成功返回 0，否则返回非 0
    #[arg(long, default_value_t = false)]
    check: bool,

    #[arg(long, default_value_t = false)]
    no_banner: bool,

    /// Admin HTTP listen address (e.g. 127.0.0.1:19090). Falls back to `ADMIN_LISTEN` env.
    #[arg(long = "admin-listen")]
    admin_listen: Option<String>,

    /// Admin HTTP token (optional). Falls back to `ADMIN_TOKEN` env.
    #[arg(long = "admin-token")]
    admin_token: Option<String>,
}

fn parse_addr(s: &str) -> std::result::Result<SocketAddr, String> {
    s.parse().map_err(|e| format!("invalid addr `{s}`: {e}"))
}

// Use shared run_engine helpers
use app::run_engine::{load_config_with_import, ReloadOutputMode, RunOptions};

pub async fn run(global: &GlobalArgs, args: RunArgs) -> Result<()> {
    // --check：零副作用配置校验
    if args.check {
        let entries =
            config_loader::collect_config_entries(&global.config, &global.config_directory)?;
        let (cfg, _ir) = load_config_with_import(&entries, args.import_path.as_deref())?;
        crate::cli::check::run::check_config(&cfg)?;
        return Ok(());
    }

    if !args.no_banner {
        info!("singbox-rust booting…");
    }

    // Initialize observability (tracing + metrics) once
    #[cfg(feature = "dev-cli")]
    crate::tracing_init::init_observability_once();

    // Optional one-shot ENV dump for troubleshooting (SB_PRINT_ENV=1)
    #[cfg(feature = "dev-cli")]
    env_dump::print_once_if_enabled();

    // Initialize admin debug server if enabled (separate from core admin)
    #[cfg(all(feature = "observe", feature = "admin_debug"))]
    crate::admin_debug::init(None).await;

    // Build ConfigInputs (entries collected dynamically in run_supervisor)
    let config_inputs = app::run_engine::ConfigInputs {
        config_paths: global.config.clone(),
        config_dirs: global.config_directory.clone(),
    };

    // Resolve admin listen (CLI arg with env fallback)
    let admin_listen = args
        .admin_listen
        .clone()
        .or_else(|| std::env::var("ADMIN_LISTEN").ok());
    let admin_token = args
        .admin_token
        .clone()
        .or_else(|| std::env::var("ADMIN_TOKEN").ok());

    // Construct RunOptions and delegate to run_supervisor
    let opts = RunOptions {
        config_inputs,
        import_path: args.import_path,
        watch: args.watch,
        reload_path: None, // CLI run doesn't have --reload-path
        admin_listen,
        admin_token,
        admin_impl: app::run_engine::AdminImpl::Core,
        print_startup: true,
        startup_output: app::run_engine::StartupOutputMode::LogOnly,
        reload_output: ReloadOutputMode::LogOnly,
        grace_ms: 10_000, // 10s grace period
        prom_listen: None,
        dns_from_env: false,
        print_transport: false,
        health_enable: false,
        dns_env_bridge: false,
    };

    app::run_engine::run_supervisor(opts).await
}
