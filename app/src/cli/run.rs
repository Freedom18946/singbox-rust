use anyhow::{Context, Result};
use clap::Args;
use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{error, info, warn};

use crate::{bootstrap, config_loader, env_dump};
use sb_core::outbound::{OutboundRegistry, OutboundRegistryHandle};
// Temporarily disabled for minimal CLI
//use sb_core::router::engine::Router as CoreRouter;
//use sb_core::router::RouterHandle;

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(long = "http", value_parser = parse_addr)]
    http_listen: Option<SocketAddr>,

    #[arg(long = "config")]
    config_path: Option<PathBuf>,

    /// 只做配置检查：解析+构建，零副作用；成功返回 0，否则返回非 0
    #[arg(long, default_value_t = false)]
    check: bool,

    #[arg(long, default_value_t = false)]
    no_banner: bool,
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

#[cfg(not(unix))]
async fn term_signal() {
    // 非 Unix 平台没有 SIGTERM，这里做一个永不完成的占位 future
    std::future::pending::<()>().await;
}

fn file_mtime(path: &str) -> SystemTime {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

pub async fn run(args: RunArgs) -> Result<()> {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[PANIC] {info}"); // 兜底到 stderr
                                     // 如果你们全局已 init tracing，则同时打到 tracing：
        tracing::error!("panic: {}", info);
    }));

    // --check：零副作用配置校验
    if args.check {
        let cfg_path = args
            .config_path
            .clone()
            .context("--check 需要指定 --config <path>")?;
        match crate::config_loader::check_only(&cfg_path) {
            Ok((ib, ob, rules)) => {
                println!("CONFIG_OK: inbounds={ib} outbounds={ob} rules={rules}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("CONFIG_BAD: {e}");
                std::process::exit(1);
            }
        }
    }

    // Initialize observability (tracing + metrics) once
    crate::tracing_init::init_observability_once();

    // Optional one-shot ENV dump for troubleshooting (SB_PRINT_ENV=1)
    env_dump::print_once_if_enabled();

    // Initialize admin debug server if enabled
    #[cfg(all(feature = "observe", feature = "admin_debug"))]
    crate::admin_debug::init(None).await;

    if !args.no_banner {
        info!("singbox-rust booting…");
    }

    // 句柄
    // Temporarily disabled for minimal CLI
    //let _rh = Arc::new(RouterHandle::from_env());
    let _oh = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::default()));

    // 解析简单 CLI：--config <path> [--import <subfile>] [--watch]
    let mut args_iter = env::args().skip(1);
    let mut config_path = None::<String>;
    let mut import_path = None::<String>;
    let mut do_watch = false;
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--config" | "-c" => {
                config_path = args_iter.next();
            }
            "--import" | "-i" => {
                import_path = args_iter.next();
            }
            "--watch" | "-w" => {
                do_watch = true;
            }
            _ => {}
        }
    }
    let cfg_path = config_path.unwrap_or_else(|| {
        // 回落到环境变量/默认
        std::env::var("SB_CONFIG").unwrap_or_else(|_| "./config.yaml".to_string())
    });

    // 加载本地配置 - simplified for minimal CLI
    let mut cfg = sb_config::Config::load(&cfg_path)?;

    // 避免部分移动，使用借用；后续还要 clone 给 watch 线程
    if let Some(ref subfile) = import_path {
        info!(path=%subfile, "importing subscription");
        match fs::read_to_string(subfile) {
            Ok(text) => {
                match sb_config::subscribe::from_subscription(&text) {
                    Ok(subcfg) => {
                        // 合并：保留本地 inbounds，用订阅 outbounds/rules/default 覆盖
                        cfg.merge_in_place(subcfg);
                        // 再次校验（如果订阅规则指向的出站不在合并后的集合中，会报错）
                        if let Err(e) = cfg.validate() {
                            error!(error=%e, "config after import invalid");
                            return Err(e);
                        }
                    }
                    Err(e) => {
                        error!(error=%e, "parse subscription failed");
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                error!(error=%e, "read subscription file failed");
                return Err(e.into());
            }
        }
    }

    // 进入引导
    let boot = async {
        let rt = bootstrap::start_from_config(cfg).await?;

        // watch: 轮询 mtime，热替换 Router/Outbound
        if do_watch {
            // Temporarily disabled hot reload functionality
            eprintln!("Hot reload functionality temporarily disabled");
            /*
            let cfg_path_clone = cfg_path.clone();
            let import_clone = import_path.clone(); // 此时 import_path 仍可用（上面用的是借用）
            let rh = rt.router.clone();
            let oh = rt.outbounds.clone();
            tokio::spawn(async move {
                let mut last = file_mtime(&cfg_path_clone);
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let now = file_mtime(&cfg_path_clone);
                    if now > last {
                        last = now;
                        info!("config change detected; reloading…");
                        // 重新加载 + 合并订阅
                        match sb_config::Config::load(&cfg_path_clone) {
                            Ok(mut base) => {
                                if let Some(subfile) = import_clone.clone() {
                                    match fs::read_to_string(&subfile) {
                                        Ok(text) => {
                                            match sb_config::subscribe::from_subscription(&text) {
                                                Ok(subcfg) => base.merge_in_place(subcfg),
                                                Err(e) => {
                                                    error!(error=%e, "parse subscription on reload failed");
                                                    continue;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!(error=%e, "read subscription on reload failed");
                                            continue;
                                        }
                                    }
                                }
                                if let Err(e) = base.validate() {
                                    error!(error=%e, "config invalid after reload");
                                    continue;
                                }
                                match base.build_registry_and_router() {
                                    Ok((reg, router)) => {
                                        rh.replace(router);
                                        oh.replace(reg);
                                        info!("hot-reload applied");
                                    }
                                    Err(e) => error!(error=%e, "rebuild on reload failed"),
                                }
                            }
                            Err(e) => error!(error=%e, "reload config failed"),
                        }
                    }
                }
            });
            */
        }

        // 永远等待（让 watch 任务在后台运行）
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    // === 驻留：等待 Ctrl+C 或 SIGTERM，确保服务常驻 ===
    info!("singbox-rust booted; press Ctrl+C to quit");
    // 等待 Ctrl+C 或（Unix）SIGTERM
    tokio::select! {
        r = boot => { r?; }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("signal: Ctrl+C received, shutting down…");
        }
        _ = term_signal() => {
            tracing::info!("signal: SIGTERM received, shutting down…");
        }
    }
    Ok(())
}
