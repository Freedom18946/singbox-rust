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

use anyhow::{Context, Result};
use clap::Args;
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::bootstrap;
use crate::cli::GlobalArgs;
use crate::config_loader::{self, ConfigEntry};
#[cfg(feature = "dev-cli")]
use crate::env_dump;
use sb_config::ir::ConfigIR;
use sb_core::outbound::{OutboundRegistry, OutboundRegistryHandle};
// Temporarily disabled for minimal CLI
//use sb_core::router::engine::Router as CoreRouter;
//use sb_core::router::RouterHandle;

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
}

const FATAL_STOP_TIMEOUT: Duration = Duration::from_secs(10);

enum RunSignal {
    Reload,
    Terminate,
}

fn parse_addr(s: &str) -> std::result::Result<SocketAddr, String> {
    s.parse().map_err(|e| format!("invalid addr `{s}`: {e}"))
}

// --- 信号等待封装，避免在 select! 分支上使用 #[cfg] ---
#[cfg(unix)]
async fn term_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sig = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    sig.recv().await;
}

#[cfg(unix)]
async fn hup_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sig = signal(SignalKind::hangup()).expect("install SIGHUP handler");
    sig.recv().await;
}

#[cfg(not(unix))]
async fn term_signal() {
    // 非 Unix 平台没有 SIGTERM，这里做一个永不完成的占位 future
    std::future::pending::<()>().await;
}

#[cfg(not(unix))]
async fn hup_signal() {
    std::future::pending::<()>().await;
}

struct WatchHandle {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl WatchHandle {
    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.join.await;
    }
}

struct CloseMonitor {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl CloseMonitor {
    fn start() -> Self {
        let (stop, mut stop_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(FATAL_STOP_TIMEOUT) => {
                    error!("sing-box did not close!");
                    std::process::exit(1);
                }
                _ = &mut stop_rx => {}
            }
        });
        Self { stop, join }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.join.await;
    }
}

#[allow(dead_code)]
fn file_mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn snapshot_mtimes(entries: &[ConfigEntry]) -> HashMap<PathBuf, SystemTime> {
    let mut snapshot = HashMap::new();
    for path in config_loader::entry_files(entries) {
        snapshot.insert(path.clone(), file_mtime(&path));
    }
    snapshot
}

fn snapshot_changed(
    prev: &HashMap<PathBuf, SystemTime>,
    entries: &[ConfigEntry],
) -> (bool, HashMap<PathBuf, SystemTime>) {
    let mut changed = false;
    let mut current = HashMap::new();
    for path in config_loader::entry_files(entries) {
        let now = file_mtime(&path);
        match prev.get(&path) {
            Some(old) => {
                if now > *old {
                    changed = true;
                }
            }
            None => changed = true,
        }
        current.insert(path, now);
    }
    if prev.len() != current.len() {
        changed = true;
    }
    (changed, current)
}

fn apply_debug_options(ir: &ConfigIR) {
    if let Some(exp) = ir.experimental.as_ref() {
        if let Some(debug) = exp.debug.as_ref() {
            if let Some(listen) = debug.listen.as_ref() {
                std::env::set_var("SB_DEBUG_ADDR", listen);
                // Enable pprof collection path in sb-explaind if present.
                std::env::set_var("SB_PPROF", "1");
                // Provide sane defaults for sb-explaind if not set.
                if std::env::var("SB_PPROF_FREQ").is_err() {
                    std::env::set_var("SB_PPROF_FREQ", "100"); // 100 Hz sampling
                }
                if std::env::var("SB_PPROF_MAX_SEC").is_err() {
                    std::env::set_var("SB_PPROF_MAX_SEC", "60"); // align with docs default
                }
            }
            if let Some(freq) = debug.gc_percent {
                tracing::info!(
                    gc_percent = freq,
                    "debug option gc_percent recorded (Go parity, no-op)"
                );
            }
            if let Some(limit) = debug.memory_limit {
                tracing::info!(
                    memory_limit = limit,
                    "debug option memory_limit recorded (Go parity, no-op)"
                );
            }
            if debug.panic_on_fault.is_some()
                || debug.max_stack.is_some()
                || debug.max_threads.is_some()
                || debug.trace_back.is_some()
                || debug.oom_killer.is_some()
            {
                tracing::info!("debug options recorded for parity; behavior is platform-dependent/no-op in Rust build");
            }
        }
    }
}

fn load_config_with_import(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> Result<sb_config::Config> {
    let mut cfg = config_loader::load_config(entries)?;
    if let Some(subfile) = import_path {
        info!(path=%subfile.display(), "importing subscription");
        let text = fs::read_to_string(subfile)
            .with_context(|| format!("read subscription file {}", subfile.display()))?;
        let subcfg = sb_config::subscribe::from_subscription(&text)
            .with_context(|| "parse subscription failed")?;
        cfg.merge_in_place(subcfg);
        cfg.validate().with_context(|| "config after import invalid")?;
    }
    Ok(cfg)
}

fn check_reload_config(global: &GlobalArgs, import_path: Option<&Path>) -> Result<()> {
    let entries = config_loader::collect_config_entries(&global.config, &global.config_directory)?;
    let cfg = load_config_with_import(&entries, import_path)?;
    crate::cli::check::run::check_config(&cfg)?;
    Ok(())
}

pub async fn run(global: &GlobalArgs, args: RunArgs) -> Result<()> {
    // Global Panic Hook / 全局 Panic 钩子
    // Handled by app::panic::install() called in main.rs
    // 确保 panic 同时记录到 stderr 和 tracing 由全局 hook 处理

    // --check：零副作用配置校验
    if args.check {
        let entries =
            config_loader::collect_config_entries(&global.config, &global.config_directory)?;
        let cfg = load_config_with_import(&entries, args.import_path.as_deref())?;
        crate::cli::check::run::check_config(&cfg)?;
        return Ok(());
    }

    if !args.no_banner {
        info!("singbox-rust booting…");
    }

    // 句柄
    // Temporarily disabled for minimal CLI
    //let _rh = Arc::new(RouterHandle::from_env());
    let _oh = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::default()));

    loop {
        let entries =
            config_loader::collect_config_entries(&global.config, &global.config_directory)?;
        let cfg = load_config_with_import(&entries, args.import_path.as_deref())?;

        // Apply debug/pprof options from config (experimental.debug)
        apply_debug_options(cfg.ir());

        // Initialize observability (tracing + metrics) once
        #[cfg(feature = "dev-cli")]
        crate::tracing_init::init_observability_once();

        // Optional one-shot ENV dump for troubleshooting (SB_PRINT_ENV=1)
        #[cfg(feature = "dev-cli")]
        env_dump::print_once_if_enabled();

        // Initialize admin debug server if enabled (after debug options applied)
        #[cfg(all(feature = "observe", feature = "admin_debug"))]
        crate::admin_debug::init(None).await;

        let rt = bootstrap::start_from_config(cfg).await?;

        let watch_handle = if args.watch {
            let config_paths = global.config.clone();
            let config_dirs = global.config_directory.clone();
            let import_clone = args.import_path.clone();
            #[cfg(feature = "router")]
            let rh = rt.router.clone();
            let oh = rt.outbounds.clone();
            let (stop_tx, mut stop_rx) = oneshot::channel();
            let join = tokio::spawn(async move {
                let mut snapshot = snapshot_mtimes(&entries);
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        _ = tokio::time::sleep(Duration::from_secs(2)) => {
                            let current_entries = match config_loader::collect_config_entries(&config_paths, &config_dirs) {
                                Ok(entries) => entries,
                                Err(e) => {
                                    error!(error=%e, "reload config failed");
                                    continue;
                                }
                            };
                            let (changed, next_snapshot) = snapshot_changed(&snapshot, &current_entries);
                            snapshot = next_snapshot;
                            if !changed {
                                continue;
                            }
                            info!("config change detected; reloading…");
                            match load_config_with_import(&current_entries, import_clone.as_deref()) {
                                Ok(base) => {
                                    if let Err(e) = base.validate() {
                                        error!(error=%e, "config invalid after reload");
                                        continue;
                                    }
                                    match sb_config::present::to_ir(&base) {
                                        Ok(ir) => {
                                            let reg = bootstrap::build_outbound_registry_from_ir(&ir);
                                            oh.replace(reg);
                                            #[cfg(feature = "router")]
                                            {
                                                match bootstrap::build_router_index_from_config(&base) {
                                                    Ok(idx) => {
                                                        if let Err(e) = rh.replace_index(idx).await {
                                                            error!(error=%e, "router index replace failed");
                                                        } else {
                                                            info!("hot-reload applied");
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(error=%e, "router index build failed on reload");
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => error!(error=%e, "to_ir failed on reload"),
                                    }
                                }
                                Err(e) => error!(error=%e, "reload config failed"),
                            }
                        }
                    }
                }
            });
            Some(WatchHandle { stop: stop_tx, join })
        } else {
            None
        };

        info!("singbox-rust booted; press Ctrl+C to quit");
        let restart = loop {
            match wait_for_signal().await {
                RunSignal::Reload => match check_reload_config(global, args.import_path.as_deref()) {
                    Ok(()) => break true,
                    Err(e) => {
                        error!(error=%e, "reload service");
                        continue;
                    }
                },
                RunSignal::Terminate => break false,
            }
        };

        let close_monitor = CloseMonitor::start();
        if let Some(watch) = watch_handle {
            watch.shutdown().await;
        }

        let shutdown_result = rt.shutdown(FATAL_STOP_TIMEOUT).await;
        close_monitor.shutdown().await;
        if let Err(e) = shutdown_result {
            error!(error=%e, "singbox-rust did not close properly");
            std::process::exit(1);
        }

        if !restart {
            break;
        }
    }

    Ok(())
}

async fn wait_for_signal() -> RunSignal {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => RunSignal::Terminate,
        () = term_signal() => RunSignal::Terminate,
        () = hup_signal() => RunSignal::Reload,
    }
}
