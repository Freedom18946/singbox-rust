use anyhow::Result;
use clap::Parser;
use sb_config::validator::v2::to_ir_v1;
// Removed unused bridge import
use sb_core::admin::http::spawn_admin;
use sb_core::runtime::{supervisor::Supervisor, Runtime};
use serde_json::json;
use std::{fs, sync::Arc, thread, time::Duration};
use tokio::signal;

#[cfg(feature = "admin_debug")]
use app;

#[derive(Parser, Debug, Clone)]
struct Args {
    /// config path
    #[arg(short = 'c', long = "config")]
    config: String,
    /// optional prometheus exporter listen addr, e.g., 127.0.0.1:19090
    #[arg(long = "prom-listen")]
    prom_listen: Option<String>,
    /// output format text|json
    #[arg(long = "format", default_value = "text")]
    format: String,
    /// enable outbound health task (also can set HEALTH=1)
    #[arg(long = "health", default_value_t = false)]
    health: bool,
    /// enable DNS stub+cache via env (DNS_STUB=1)
    #[arg(long = "dns-from-env", default_value_t = false)]
    dns_from_env: bool,
    /// admin http listen (e.g. 127.0.0.1:19090). Also can be set via ADMIN_LISTEN env var.
    #[arg(long = "admin-listen")]
    admin_listen: Option<String>,
    /// admin http token (optional). Also can be set via ADMIN_TOKEN env var.
    #[arg(long = "admin-token")]
    admin_token: Option<String>,
    /// graceful shutdown timeout in milliseconds
    #[arg(long = "grace", default_value = "1500")]
    grace: u64,
    /// config path for SIGHUP reload (optional)
    #[arg(long = "reload-path")]
    reload_path: Option<String>,
    /// admin implementation: core|debug (default: core). Also can be set via SB_ADMIN_IMPL env var.
    #[arg(long = "admin-impl", default_value = "core")]
    admin_impl: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 1) 可选 Prom 导出器
    if let Some(addr) = args
        .prom_listen
        .clone()
        .or_else(|| std::env::var("PROM_LISTEN").ok())
    {
        thread::spawn(move || {
            let _ = sb_core::metrics::http_exporter::run_exporter(&addr);
        });
    }

    // 2) 可选 DNS stub+cache 初始化（behind env）
    if args.dns_from_env || std::env::var("DNS_STUB").ok().as_deref() == Some("1") {
        let ttl_secs: u64 = std::env::var("DNS_CACHE_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        sb_core::dns::stub::init_global(ttl_secs);
    }

    // 3) 配置→IR→Supervisor 启动
    let raw = fs::read(&args.config).unwrap_or_else(|_| b"{}".to_vec());
    let val: serde_json::Value = serde_json::from_slice(&raw).unwrap_or(serde_json::json!({}));
    let ir = to_ir_v1(&val);

    // Start supervisor with initial configuration
    let supervisor = Arc::new(Supervisor::start(ir).await?);

    // 3.1) Admin HTTP （可选）
    let admin_addr = args
        .admin_listen
        .or_else(|| std::env::var("ADMIN_LISTEN").ok());
    if let Some(addr) = admin_addr {
        let admin_impl = std::env::var("SB_ADMIN_IMPL").unwrap_or(args.admin_impl.clone());

        match admin_impl.as_str() {
            "debug" => {
                #[cfg(feature = "admin_debug")]
                {
                    let socket_addr: std::net::SocketAddr = addr.parse()
                        .map_err(|e| anyhow::anyhow!("Invalid admin listen address: {}", e))?;

                    let tls_conf = app::admin_debug::http::TlsConf::from_env();
                    let auth_conf = app::admin_debug::http::AuthConf::from_env();

                    let tls_opt = if tls_conf.enabled { Some(tls_conf) } else { None };

                    app::admin_debug::http::spawn(socket_addr, tls_opt, auth_conf)
                        .map_err(|e| anyhow::anyhow!("Failed to start admin debug server: {}", e))?;
                    tracing::info!(addr = %socket_addr, impl = "debug", "Started admin debug server");
                }
                #[cfg(not(feature = "admin_debug"))]
                {
                    return Err(anyhow::anyhow!("admin_debug feature not enabled, cannot use --admin-impl=debug"));
                }
            }
            "core" => {
                // Admin HTTP 仅依赖 supervisor 与运行时句柄
                let token = args
                    .admin_token
                    .clone()
                    .or_else(|| std::env::var("ADMIN_TOKEN").ok());
                let supervisor_for_admin = Some(supervisor.clone());
                let handle = tokio::runtime::Handle::current();
                let _ = spawn_admin(
                    &addr,
                    /*engine:*/ Runtime::dummy_engine(),
                    /*bridge:*/ Runtime::dummy_bridge(),
                    token,
                    supervisor_for_admin,
                    Some(handle),
                );
                tracing::info!(addr = %addr, impl = "core", "Started core admin server");
            }
            _ => {
                return Err(anyhow::anyhow!("Invalid --admin-impl value: '{}'. Must be 'core' or 'debug'", admin_impl));
            }
        }
    }

    // 4) 启动反馈（锁死字段集；供 GUI/脚本感知状态）
    if args.format == "json" {
        let obj = json!({
            "event":"started",
            "pid": std::process::id(),
            "fingerprint": env!("CARGO_PKG_VERSION")
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else {
        println!(
            "started pid={} fingerprint={}",
            std::process::id(),
            env!("CARGO_PKG_VERSION")
        );
    }

    // 5) 信号处理
    let supervisor_handle = supervisor.handle();
    let grace_duration = Duration::from_millis(args.grace);
    let reload_path = args.reload_path.clone();

    tokio::select! {
        // Handle SIGTERM/SIGINT for graceful shutdown
        _ = signal::ctrl_c() => {
            handle_shutdown_signal(supervisor_handle.clone(), grace_duration).await?;
        }
        // Handle SIGHUP for reload
        _ = handle_sighup(supervisor.clone(), reload_path) => {
            // SIGHUP handler completed, continue running
        }
        // Handle SIGTERM
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                // Windows doesn't have SIGTERM, wait indefinitely
                std::future::pending::<()>().await;
            }
            Ok::<(), anyhow::Error>(())
        } => {
            handle_shutdown_signal(supervisor_handle, grace_duration).await?;
        }
    }

    Ok(())
}

/// Handle shutdown signals (SIGTERM/SIGINT)
async fn handle_shutdown_signal(
    supervisor_handle: sb_core::runtime::supervisor::SupervisorHandle,
    grace_duration: Duration,
) -> Result<()> {
    supervisor_handle.shutdown_graceful(grace_duration).await?;
    Ok(())
}

/// Handle SIGHUP signal for reload
async fn handle_sighup(supervisor: Arc<Supervisor>, reload_path: Option<String>) -> Result<()> {
    #[cfg(unix)]
    {
        let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())?;

        loop {
            sighup.recv().await;

            if let Some(path) = &reload_path {
                match perform_sighup_reload(&supervisor, path).await {
                    Ok(()) => {
                        let success_obj = json!({
                            "event": "reload",
                            "ok": true,
                            "source": "SIGHUP",
                            "fingerprint": env!("CARGO_PKG_VERSION")
                        });
                        eprintln!(
                            "{}",
                            serde_json::to_string(&success_obj).unwrap_or_default()
                        );
                    }
                    Err(e) => {
                        let error_obj = json!({
                            "event": "reload",
                            "ok": false,
                            "source": "SIGHUP",
                            "error": format!("{}", e),
                            "fingerprint": env!("CARGO_PKG_VERSION")
                        });
                        eprintln!("{}", serde_json::to_string(&error_obj).unwrap_or_default());
                    }
                }
            } else {
                let error_obj = json!({
                    "event": "reload",
                    "ok": false,
                    "source": "SIGHUP",
                    "error": "no --reload-path provided",
                    "fingerprint": env!("CARGO_PKG_VERSION")
                });
                eprintln!("{}", serde_json::to_string(&error_obj).unwrap_or_default());
            }
        }
    }

    #[cfg(not(unix))]
    {
        // Windows doesn't support SIGHUP, wait indefinitely
        std::future::pending().await
    }
}

/// Perform reload from SIGHUP signal
async fn perform_sighup_reload(supervisor: &Arc<Supervisor>, config_path: &str) -> Result<()> {
    // Read and parse config file
    let raw = fs::read(config_path)?;
    let val: serde_json::Value = serde_json::from_slice(&raw)?;
    let ir = to_ir_v1(&val);

    // Trigger reload
    supervisor.reload(ir).await?;

    Ok(())
}
