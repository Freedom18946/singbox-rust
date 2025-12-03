use anyhow::Result;
use clap::{ArgAction, Parser};
use sb_config::validator::v2::to_ir_v1;
// Removed unused bridge import
use sb_core::admin::http::spawn_admin;
use sb_core::runtime::{supervisor::Supervisor, Runtime};
use serde_json::json;
use std::{fs, sync::Arc, thread, time::Duration};
use tokio::signal;

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
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    help_json: bool,
    /// Print transport plan (derived chain) for outbounds at startup
    #[arg(long = "print-transport", default_value_t = false)]
    print_transport: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Ensure rustls has a crypto provider installed (reqwest may use no-provider feature)
    #[allow(unused_must_use)]
    {
        use rustls::crypto::{ring, CryptoProvider};
        let _ = CryptoProvider::install_default(ring::default_provider());
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    
    // Register adapters early (must be called before Bridge::build or any adapter usage)
    #[cfg(feature = "adapters")]
    sb_adapters::register_all();
    
    if std::env::args().skip(1).any(|arg| arg == "--help-json") {
        app::cli::help::print_help_json::<Args>();
    }
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

    // 2) 读取配置（用于 DNS 接线 + IR 转换）
    let raw = fs::read(&args.config).unwrap_or_else(|_| b"{}".to_vec());
    let val: serde_json::Value = serde_json::from_slice(&raw).unwrap_or(serde_json::json!({}));

    // 2.1) 基于配置的 DNS 环境接线（保留用户已设置的 ENV 覆盖能力）
    let dns_applied = apply_dns_env_from_config(&val);

    // 2.2) 如果未使用配置驱动 DNS，且用户要求 stub，则初始化轻量 stub
    if !dns_applied && (args.dns_from_env || std::env::var("DNS_STUB").ok().as_deref() == Some("1"))
    {
        let ttl_secs: u64 = std::env::var("DNS_CACHE_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        sb_core::dns::stub::init_global(ttl_secs);
    }

    // 3) 配置→IR→Supervisor 启动
    let ir = to_ir_v1(&val);

    // 3.0) Debug: 打印每个 outbound 的推导传输链（便于诊断）。
    // 使用 tracing debug 级别输出；可用 RUST_LOG=sb_core::transport=debug 查看。
    let want_info = args.print_transport
        || std::env::var("SB_TRANSPORT_PLAN")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    for ob in &ir.outbounds {
        let name = ob.name.clone().unwrap_or_else(|| ob.ty_str().to_string());
        let kind = ob.ty_str();
        let chain = sb_core::runtime::transport::map::chain_from_ir(ob);
        let sni = ob.tls_sni.clone().unwrap_or_default();
        let alpn = ob
            .tls_alpn
            .as_ref()
            .map(|v| v.join(","))
            .unwrap_or_default();
        if want_info {
            tracing::info!(
                target: "sb_core::transport",
                outbound = %name,
                kind = %kind,
                chain = %chain.join(","),
                sni = %sni,
                alpn = %alpn,
                "transport plan"
            );
        } else {
            tracing::debug!(
                target: "sb_core::transport",
                outbound = %name,
                kind = %kind,
                chain = %chain.join(","),
                sni = %sni,
                alpn = %alpn,
                "derived transport chain"
            );
        }
    }

    // Start supervisor with initial configuration
    tracing::info!("Calling Supervisor::start");
    let supervisor = Arc::new(Supervisor::start(ir).await?);
    tracing::info!("Supervisor::start returned");

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
                    let socket_addr: std::net::SocketAddr = addr
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Invalid admin listen address: {}", e))?;

                    let tls_conf = app::admin_debug::http_server::TlsConf::from_env();
                    let auth_conf = app::admin_debug::http_server::AuthConf::from_env();

                    let tls_opt = if tls_conf.enabled {
                        Some(tls_conf)
                    } else {
                        None
                    };

                    app::admin_debug::http_server::spawn(socket_addr, tls_opt, auth_conf).map_err(
                        |e| anyhow::anyhow!("Failed to start admin debug server: {}", e),
                    )?;
                    tracing::info!(addr = %socket_addr, impl = "debug", "Started admin debug server");
                }
                #[cfg(not(feature = "admin_debug"))]
                {
                    return Err(anyhow::anyhow!(
                        "admin_debug feature not enabled, cannot use --admin-impl=debug"
                    ));
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
                return Err(anyhow::anyhow!(
                    "Invalid --admin-impl value: '{}'. Must be 'core' or 'debug'",
                    admin_impl
                ));
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

/// Apply DNS environment configuration from config file (top-level `dns` block).
/// Returns true if any DNS setting was derived from config.
fn apply_dns_env_from_config(doc: &serde_json::Value) -> bool {
    fn set_if_unset(k: &str, v: &str) {
        if std::env::var(k).is_err() {
            std::env::set_var(k, v);
        }
    }
    let mut applied = false;
    let dns = match doc.get("dns") {
        Some(v) => v,
        None => return false,
    };
    // servers: [{ address: "udp://1.1.1.1" | "https://1.1.1.1/dns-query" | "dot://host:853" | "doq://host:853@name" | "system" | "rcode://..." }]
    if let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) {
        // Build pool tokens (best-effort) and also map first usable server to SB_DNS_MODE* envs
        let mut pool_tokens: Vec<String> = Vec::new();
        let mut first_mode_set = false;
        for s in servers {
            let Some(addr_raw) = s.get("address").and_then(|v| v.as_str()) else {
                continue;
            };
            if addr_raw.starts_with("rcode://") {
                // Skip block/rcode entries for upstream pool
                continue;
            }
            // Normalize and push to pool tokens (for advanced pool resolver)
            if let Some(rest) = addr_raw.strip_prefix("udp://") {
                // ensure port (default 53)
                let token = if rest.contains(':') {
                    format!("udp:{rest}")
                } else {
                    format!("udp:{rest}:53")
                };
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "udp");
                    // For simple resolver
                    let svr = token.trim_start_matches("udp:");
                    set_if_unset("SB_DNS_UDP_SERVER", svr);
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if addr_raw.starts_with("https://") || addr_raw.starts_with("http://") {
                let token = format!("doh:{addr_raw}");
                pool_tokens.push(token);
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "doh");
                    set_if_unset("SB_DNS_DOH_URL", addr_raw);
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if let Some(rest) = addr_raw
                .strip_prefix("dot://")
                .or_else(|| addr_raw.strip_prefix("tls://"))
            {
                // ensure port (default 853)
                let token = if rest.contains(':') {
                    format!("dot:{rest}")
                } else {
                    format!("dot:{rest}:853")
                };
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "dot");
                    let dot = token.trim_start_matches("dot:");
                    set_if_unset("SB_DNS_DOT_ADDR", dot);
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if let Some(rest) = addr_raw
                .strip_prefix("doq://")
                .or_else(|| addr_raw.strip_prefix("quic://"))
            {
                // Syntax: doq://host:port[@sni]
                let token = format!("doq:{rest}");
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "doq");
                    // Optional (effective under dev-cli/tests): split to addr@sni
                    if let Some((addr, sni)) = rest.split_once('@') {
                        set_if_unset("SB_DNS_DOQ_ADDR", addr);
                        set_if_unset("SB_DNS_DOQ_SERVER_NAME", sni);
                    } else {
                        set_if_unset("SB_DNS_DOQ_ADDR", rest);
                    }
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if addr_raw.eq_ignore_ascii_case("system") {
                pool_tokens.push("system".to_string());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "system");
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            // Unknown scheme: ignore but keep for pool as unsupported
        }
        if !pool_tokens.is_empty() {
            set_if_unset("SB_DNS_POOL", &pool_tokens.join(","));
        }
    }
    // Strategy -> qtype/HE order (best-effort). E.g. "ipv4_only" → A first, "ipv6_only" → AAAA first.
    if let Some(strategy) = dns.get("strategy").and_then(|v| v.as_str()) {
        match strategy.to_ascii_lowercase().as_str() {
            "ipv4_only" | "prefer_ipv4" => {
                set_if_unset("SB_DNS_QTYPE", "a");
                set_if_unset("SB_DNS_HE_ORDER", "A_FIRST");
                applied = true;
            }
            "ipv6_only" | "prefer_ipv6" => {
                set_if_unset("SB_DNS_QTYPE", "aaaa");
                set_if_unset("SB_DNS_HE_ORDER", "AAAA_FIRST");
                applied = true;
            }
            _ => {}
        }
    }

    // TTL tuning (best-effort): dns.ttl.{default,min,max,neg} in seconds or string number
    if let Some(ttl) = dns.get("ttl").and_then(|v| v.as_object()) {
        if let Some(secs) = ttl.get("default").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_DEFAULT_TTL_S", &secs.to_string());
            applied = true;
        }
        if let Some(secs) = ttl.get("min").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_MIN_TTL_S", &secs.to_string());
            applied = true;
        }
        if let Some(secs) = ttl.get("max").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_MAX_TTL_S", &secs.to_string());
            applied = true;
        }
        if let Some(secs) = ttl.get("neg").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_NEG_TTL_S", &secs.to_string());
            applied = true;
        }
    }

    // hosts: { "example.com": ["1.2.3.4","::1"], ... }
    if let Some(hosts) = dns.get("hosts").and_then(|v| v.as_object()) {
        let mut parts: Vec<String> = Vec::new();
        for (host, val) in hosts {
            let host = host.trim().to_ascii_lowercase();
            if host.is_empty() {
                continue;
            }
            let mut ips: Vec<String> = Vec::new();
            match val {
                serde_json::Value::String(s) => {
                    if !s.trim().is_empty() {
                        ips.push(s.trim().to_string());
                    }
                }
                serde_json::Value::Array(arr) => {
                    for it in arr {
                        if let Some(s) = it.as_str() {
                            if !s.trim().is_empty() {
                                ips.push(s.trim().to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
            if !ips.is_empty() {
                parts.push(format!("{}={}", host, ips.join(";")));
            }
        }
        if !parts.is_empty() {
            set_if_unset("SB_DNS_STATIC", &parts.join(","));
            if let Some(ttl_s) = dns
                .get("hosts_ttl")
                .or_else(|| dns.get("static_ttl"))
                .and_then(num_or_string_secs)
            {
                set_if_unset("SB_DNS_STATIC_TTL_S", &ttl_s.to_string());
            }
            applied = true;
        }
    }

    // fakeip: { enabled: bool, inet4_range: "198.18.0.0/15", inet6_range: "fd00::/8" }
    if let Some(fakeip) = dns.get("fakeip").and_then(|v| v.as_object()) {
        let enabled = fakeip
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if enabled {
            set_if_unset("SB_DNS_FAKEIP_ENABLE", "1");
            applied = true;
            // V4 range
            if let Some(r) = fakeip.get("inet4_range").and_then(|v| v.as_str()) {
                if let Some((base, mask)) = split_cidr(r) {
                    set_if_unset("SB_FAKEIP_V4_BASE", base);
                    set_if_unset("SB_FAKEIP_V4_MASK", &mask.to_string());
                }
            }
            // V6 range
            if let Some(r) = fakeip.get("inet6_range").and_then(|v| v.as_str()) {
                if let Some((base, mask)) = split_cidr(r) {
                    set_if_unset("SB_FAKEIP_V6_BASE", base);
                    set_if_unset("SB_FAKEIP_V6_MASK", &mask.to_string());
                }
            }
        }
    }

    // pool selection strategy and concurrency knobs
    if let Some(s) = dns.get("pool_strategy").and_then(|v| v.as_str()) {
        let s_lc = s.to_ascii_lowercase();
        let v_norm = match s_lc.as_str() {
            "race" | "racing" => "race",
            "fanout" | "parallel" => "fanout",
            "sequential" | "seq" => "sequential",
            other => other,
        };
        set_if_unset("SB_DNS_POOL_STRATEGY", v_norm);
        applied = true;
    }
    if let Some(pool) = dns.get("pool").and_then(|v| v.as_object()) {
        if let Some(v) = pool.get("race_window_ms").and_then(|x| x.as_u64()) {
            set_if_unset("SB_DNS_RACE_WINDOW_MS", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool.get("he_race_ms").and_then(|x| x.as_u64()) {
            set_if_unset("SB_DNS_HE_RACE_MS", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool.get("he_order").and_then(|x| x.as_str()) {
            let norm = if v.eq_ignore_ascii_case("AAAA_FIRST") {
                "AAAA_FIRST"
            } else {
                "A_FIRST"
            };
            set_if_unset("SB_DNS_HE_ORDER", norm);
            applied = true;
        }
        if let Some(v) = pool.get("max_inflight").and_then(|x| x.as_u64()) {
            set_if_unset("SB_DNS_POOL_MAX_INFLIGHT", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool.get("per_host_inflight").and_then(|x| x.as_u64()) {
            set_if_unset("SB_DNS_PER_HOST_INFLIGHT", &v.to_string());
            applied = true;
        }
    }

    // timeouts
    if let Some(v) = dns.get("timeout_ms").and_then(|x| x.as_u64()) {
        let s = v.to_string();
        set_if_unset("SB_DNS_UDP_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_DOT_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_DOH_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_DOQ_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_QUERY_TIMEOUT_MS", &s);
        applied = true;
    }

    // cache controls
    if let Some(cache) = dns.get("cache").and_then(|v| v.as_object()) {
        if cache
            .get("enable")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
        {
            set_if_unset("SB_DNS_CACHE_ENABLE", "1");
            applied = true;
        }
        if let Some(cap) = cache.get("cap").and_then(|x| x.as_u64()) {
            set_if_unset("SB_DNS_CACHE_CAP", &cap.to_string());
            applied = true;
        }
        if let Some(neg_ms) = cache.get("neg_ttl_ms").and_then(|x| x.as_u64()) {
            set_if_unset("SB_DNS_CACHE_NEG_TTL_MS", &neg_ms.to_string());
            applied = true;
        }
    }
    applied
}

/// Parse integer seconds from number or from simple string (supports suffix s/m/h)
fn num_or_string_secs(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        // Try pure number-as-seconds
        if let Ok(n) = s.parse::<u64>() {
            return Some(n);
        }
        // Simple suffix parsing
        let (num, suf) = s.split_at(s.len().saturating_sub(1));
        if let Ok(n) = num.parse::<u64>() {
            return Some(match suf {
                "s" | "S" => n,
                "m" | "M" => n.saturating_mul(60),
                "h" | "H" => n.saturating_mul(3600),
                _ => return None,
            });
        }
    }
    None
}

fn split_cidr(s: &str) -> Option<(&str, u8)> {
    let s = s.trim();
    let (base, mask) = s.split_once('/')?;
    let m = mask.parse::<u8>().ok()?;
    Some((base, m))
}
