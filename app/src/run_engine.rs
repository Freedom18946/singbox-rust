//! Shared run engine helpers for CLI and bin run commands.
//!
//! This module consolidates common startup, configuration loading, and reload
//! logic to avoid duplication between cli/run.rs and bin/run.rs.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

use app::config_loader::{self, ConfigEntry};
use sb_config::ir::ConfigIR;

/// Apply debug/pprof options from config's experimental.debug section.
/// Sets environment variables for `SB_DEBUG_ADDR`, `SB_PPROF`, `SB_PPROF_FREQ`, `SB_PPROF_MAX_SEC`.
pub fn apply_debug_options(ir: &ConfigIR) {
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

/// Load config with optional subscription import.
///
/// - Uses `config_loader::load_config` to load and merge config entries
/// - Optionally imports a subscription file and merges it
/// - Validates the merged config
/// - Converts to `ConfigIR`
///
/// Returns (Config, `ConfigIR`) tuple.
///
/// # Errors
/// Returns an error if loading, importing, validation, or IR conversion fails.
pub fn load_config_with_import(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> Result<(sb_config::Config, ConfigIR)> {
    let mut cfg = config_loader::load_config(entries)?;
    if let Some(subfile) = import_path {
        info!(path=%subfile.display(), "importing subscription");
        let text = fs::read_to_string(subfile)
            .with_context(|| format!("read subscription file {}", subfile.display()))?;
        let subcfg = sb_config::subscribe::from_subscription(&text)
            .with_context(|| "parse subscription failed")?;
        cfg.merge_in_place(subcfg);
        cfg.validate()
            .with_context(|| "config after import invalid")?;
    }
    // Convert to IR once here, avoiding repeated to_ir calls at call sites
    let ir = sb_config::present::to_ir(&cfg).context("to_ir failed")?;
    Ok((cfg, ir))
}

/// Load config with optional subscription import, returning raw Value for DNS env bridge.
///
/// - Uses `config_loader::load_merged_value` to get raw Value (JSON/YAML)
/// - Uses `sb_config::config_from_raw_value` for migration + validation
/// - Optionally imports a subscription file and merges it
/// - Returns merged raw Value (`cfg.raw()`) for DNS env bridge compatibility
///
/// Returns (Config, `ConfigIR`, `serde_json::Value`) tuple.
///
/// # Errors
/// Returns an error if loading, importing, validation, or IR conversion fails.
pub fn load_config_with_import_raw(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> Result<(sb_config::Config, ConfigIR, serde_json::Value)> {
    let raw = config_loader::load_merged_value(entries)?;
    let (mut cfg, mut ir) = sb_config::config_from_raw_value(raw)?;

    if let Some(subfile) = import_path {
        info!(path=%subfile.display(), "importing subscription");
        let text = fs::read_to_string(subfile)
            .with_context(|| format!("read subscription file {}", subfile.display()))?;
        let subcfg = sb_config::subscribe::from_subscription(&text)
            .with_context(|| "parse subscription failed")?;
        cfg.merge_in_place(subcfg);
        cfg.validate()
            .with_context(|| "config after import invalid")?;
        // Regenerate IR after subscription merge
        ir = sb_config::present::to_ir(&cfg).context("to_ir after merge failed")?;
    }

    // Return merged raw from cfg for DNS env bridge (reflects merged state)
    let merged_raw = cfg.raw().clone();
    Ok((cfg, ir, merged_raw))
}

/// Unified reload helper for watch mode and SIGHUP.
///
/// - Loads config with optional subscription import
/// - Applies debug options from the new config
/// - Reloads the Supervisor with the new IR
#[cfg(feature = "router")]
pub async fn reload_with_supervisor(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
    supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
) -> Result<()> {
    let (_cfg, ir) = load_config_with_import(entries, import_path)?;
    apply_debug_options(&ir);
    supervisor
        .reload(ir)
        .await
        .context("Supervisor reload failed")?;
    Ok(())
}

// ============================================================================
// Unified Supervisor Run Loop
// ============================================================================

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::error;

/// Compute a stable fingerprint of the merged config for change detection.
/// Uses sb_config::json_norm::fingerprint_hex8 for canonical SHA256-8 fingerprint.
/// Returns (numeric for fast comparison, hex-8 for display).
#[cfg(feature = "router")]
fn config_fingerprint(raw: &serde_json::Value) -> (u64, String) {
    let hex = sb_config::json_norm::fingerprint_hex8(raw);
    // Derive numeric from hex for fast comparison
    let numeric = u64::from_str_radix(&hex, 16).unwrap_or(0);
    (numeric, hex)
}

/// Source of a reload request.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadSource {
    Watch,
    Sighup,
}

/// Outcome of a reload attempt.
#[cfg(feature = "router")]
pub enum ReloadOutcome {
    /// Reload applied successfully; contains config fingerprint hex
    Applied(String),
    /// Reload skipped because config fingerprint unchanged; contains hex
    SkippedNoChange(String),
    /// Reload failed with error
    Failed(anyhow::Error),
}

/// Shared reload state for fingerprint tracking across all reload sources.
/// Used with Arc<Mutex> to serialize reloads and prevent concurrent races.
#[cfg(feature = "router")]
struct ReloadState {
    /// Numeric fingerprint for fast comparison
    fingerprint: u64,
    /// Hex string for output display
    fingerprint_hex: String,
}

/// Alias for tokio's async Mutex (distinguished from std::sync::Mutex).
#[cfg(feature = "router")]
type TokioMutex<T> = tokio::sync::Mutex<T>;

/// Configuration input sources for dynamic entry resolution.
/// Used instead of pre-built entries to support dynamic config directory scanning.
#[cfg(feature = "router")]
#[derive(Clone, Debug, Default)]
pub struct ConfigInputs {
    /// Config file paths (-c flags)
    pub config_paths: Vec<PathBuf>,
    /// Config directories (-C flags)
    pub config_dirs: Vec<PathBuf>,
}

/// Options for the unified supervisor run loop.
#[cfg(feature = "router")]
#[derive(Clone)]
pub struct RunOptions {
    /// Config input sources for dynamic entry resolution.
    /// Entries are collected dynamically at startup, watch, and reload.
    pub config_inputs: ConfigInputs,
    /// Optional subscription import path (-i flag)
    pub import_path: Option<PathBuf>,
    /// Enable watch mode (poll for config changes every 2s)
    pub watch: bool,
    /// Optional reload path override for SIGHUP (uses this instead of config_inputs)
    pub reload_path: Option<PathBuf>,
    /// Optional admin HTTP listen address
    pub admin_listen: Option<String>,
    /// Optional admin HTTP token
    pub admin_token: Option<String>,
    /// Admin server implementation (core or debug)
    pub admin_impl: AdminImpl,
    /// Print startup message (controlled by startup_output)
    pub print_startup: bool,
    /// Startup output mode
    pub startup_output: StartupOutputMode,
    /// Reload output mode
    pub reload_output: ReloadOutputMode,
    /// Grace period for shutdown (in milliseconds)
    pub grace_ms: u64,
    /// Optional prometheus exporter listen address
    pub prom_listen: Option<String>,
    /// Enable DNS stub init from env (--dns-from-env / `DNS_STUB=1`)
    pub dns_from_env: bool,
    /// Print transport plan for outbounds at startup (info level).
    /// When false, still outputs debug-level "derived transport chain".
    pub print_transport: bool,
    /// Enable health task (sets `SB_HEALTH_ENABLE=1` for Supervisor).
    /// bin/run: true when --health flag or `HEALTH=1` env.
    /// CLI run: false by default.
    pub health_enable: bool,
    /// Enable DNS environment bridge from config.
    /// When true, calls apply_dns_env_from_config() to derive DNS env vars.
    /// bin/run: true (full featured); CLI run: false (avoid side effects).
    pub dns_env_bridge: bool,
}

/// Mode for startup output.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StartupOutputMode {
    /// Log via tracing::info (CLI run default)
    #[default]
    LogOnly,
    /// Print to stdout in text format: "started pid=... fingerprint=..."
    TextStdout,
    /// Print to stdout in JSON format: {"event":"started",...}
    JsonStdout,
}

/// Admin server implementation.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AdminImpl {
    /// Core admin server (sb_core::admin::http)
    #[default]
    Core,
    /// Debug admin server (app::admin_debug)
    Debug,
}

/// Mode for reload success/failure output.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ReloadOutputMode {
    /// Log only (info/error level tracing)
    #[default]
    LogOnly,
    /// JSON output to stderr (for bin/run compatibility)
    JsonStderr,
}

#[cfg(feature = "router")]
const FATAL_STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(feature = "router")]
struct WatchHandle {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

#[cfg(feature = "router")]
impl WatchHandle {
    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.join.await;
    }
}

#[cfg(feature = "router")]
struct CloseMonitor {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

#[cfg(feature = "router")]
impl CloseMonitor {
    fn start() -> Self {
        let (stop, mut stop_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(FATAL_STOP_TIMEOUT) => {
                    error!("Supervisor did not close in time!");
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

#[cfg(feature = "router")]
fn file_mtime(path: &std::path::Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

#[cfg(feature = "router")]
fn snapshot_mtimes(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> HashMap<PathBuf, SystemTime> {
    let mut snapshot = HashMap::new();
    for path in config_loader::entry_files(entries) {
        snapshot.insert(path.clone(), file_mtime(&path));
    }
    // Include import file in watch set
    if let Some(import) = import_path {
        if import.exists() {
            snapshot.insert(import.to_path_buf(), file_mtime(import));
        }
    }
    snapshot
}

#[cfg(feature = "router")]
fn snapshot_changed(
    prev: &HashMap<PathBuf, SystemTime>,
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> (bool, HashMap<PathBuf, SystemTime>) {
    let mut changed = false;
    let mut current = HashMap::new();

    // Check config entry files
    for path in config_loader::entry_files(entries) {
        let now = file_mtime(&path);
        match prev.get(&path) {
            Some(old) => {
                if now > *old {
                    changed = true;
                }
            }
            None => changed = true, // New file detected
        }
        current.insert(path, now);
    }

    // Check import file
    if let Some(import) = import_path {
        if import.exists() {
            let now = file_mtime(import);
            match prev.get(&import.to_path_buf()) {
                Some(old) => {
                    if now > *old {
                        changed = true;
                    }
                }
                None => changed = true,
            }
            current.insert(import.to_path_buf(), now);
        }
    }

    // Entry list changed (files added/removed from config dirs)
    if prev.len() != current.len() {
        changed = true;
    }
    // Also check if any file was removed
    for path in prev.keys() {
        if !current.contains_key(path) {
            changed = true;
            break;
        }
    }

    (changed, current)
}

#[cfg(feature = "router")]
enum RunSignal {
    Reload,
    Terminate,
}

#[cfg(feature = "router")]
async fn wait_for_signal() -> RunSignal {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => RunSignal::Terminate,
        () = term_signal() => RunSignal::Terminate,
        () = hup_signal() => RunSignal::Reload,
    }
}

#[cfg(all(feature = "router", unix))]
async fn term_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM");
    term.recv().await;
}

#[cfg(all(feature = "router", not(unix)))]
async fn term_signal() {
    std::future::pending::<()>().await;
}

#[cfg(all(feature = "router", unix))]
async fn hup_signal() {
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("failed to register SIGHUP");
    hup.recv().await;
}

#[cfg(all(feature = "router", not(unix)))]
async fn hup_signal() {
    std::future::pending::<()>().await;
}

#[cfg(feature = "router")]
fn report_reload_result(outcome: &ReloadOutcome, source: ReloadSource, mode: ReloadOutputMode) {
    let source_str = match source {
        ReloadSource::Watch => "watch",
        ReloadSource::Sighup => "SIGHUP",
    };

    match (outcome, mode) {
        (ReloadOutcome::Applied(cfg_fp), ReloadOutputMode::LogOnly) => {
            info!(source=%source_str, config_fingerprint=%cfg_fp, "hot-reload applied");
        }
        (ReloadOutcome::SkippedNoChange(cfg_fp), ReloadOutputMode::LogOnly) => {
            info!(source=%source_str, config_fingerprint=%cfg_fp, "reload skipped (config unchanged)");
        }
        (ReloadOutcome::Failed(e), ReloadOutputMode::LogOnly) => {
            error!(source=%source_str, error=%e, "reload failed");
        }
        (ReloadOutcome::Applied(cfg_fp), ReloadOutputMode::JsonStderr) => {
            let obj = serde_json::json!({
                "event": "reload",
                "ok": true,
                "source": source_str,
                "applied": true,
                "config_fingerprint": cfg_fp,
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
        (ReloadOutcome::SkippedNoChange(cfg_fp), ReloadOutputMode::JsonStderr) => {
            let obj = serde_json::json!({
                "event": "reload",
                "ok": true,
                "source": source_str,
                "applied": false,
                "reason": "no_change",
                "config_fingerprint": cfg_fp,
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
        (ReloadOutcome::Failed(e), ReloadOutputMode::JsonStderr) => {
            let obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "source": source_str,
                "applied": false,
                "error": format!("{}", e),
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
    }
}

/// Reload with shared state for serialization and fingerprint-based change detection.
/// Acquires lock to prevent concurrent reloads from racing.
#[cfg(feature = "router")]
async fn reload_with_state(
    state: Arc<TokioMutex<ReloadState>>,
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
    supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
) -> ReloadOutcome {
    // Acquire lock to serialize reloads (prevents concurrent watch + SIGHUP races)
    let mut guard = state.lock().await;

    // Load config with raw value for fingerprinting
    let (_, ir, raw) = match load_config_with_import_raw(entries, import_path) {
        Ok(v) => v,
        Err(e) => return ReloadOutcome::Failed(e),
    };

    let (new_fp_numeric, new_fp_hex) = config_fingerprint(&raw);

    // Skip reload if config unchanged (compare numeric fingerprint for speed)
    if new_fp_numeric == guard.fingerprint {
        return ReloadOutcome::SkippedNoChange(guard.fingerprint_hex.clone());
    }

    // Apply debug options and reload
    apply_debug_options(&ir);
    match supervisor.reload(ir).await {
        Ok(_) => {
            guard.fingerprint = new_fp_numeric;
            guard.fingerprint_hex = new_fp_hex.clone();
            ReloadOutcome::Applied(new_fp_hex)
        }
        Err(e) => ReloadOutcome::Failed(e),
    }
}

/// Unified supervisor run loop.
///
/// Handles:
/// - Optional prometheus exporter startup
/// - Config loading with optional subscription import (raw for DNS env bridge)
/// - DNS environment bridge from config
/// - DNS stub initialization
/// - Print transport plan for outbounds
/// - Debug options application
/// - Supervisor startup
/// - Admin server (core or debug implementation)
/// - Startup output (log/text/json)
/// - Optional watch mode (polls for config changes every 2s)
/// - Signal handling (SIGHUP for reload, SIGTERM/CTRL+C for shutdown)
/// - Graceful shutdown
#[cfg(feature = "router")]
pub async fn run_supervisor(opts: RunOptions) -> Result<()> {
    // 0) Health enable env var (Supervisor uses SB_HEALTH_ENABLE to spawn health task)
    if opts.health_enable {
        std::env::set_var("SB_HEALTH_ENABLE", "1");
    }

    // 1) Optional Prom exporter
    if let Some(ref addr) = opts.prom_listen {
        let addr_clone = addr.clone();
        std::thread::spawn(move || {
            let _ = sb_core::metrics::http_exporter::run_exporter(&addr_clone);
        });
    }

    // 1.5) Dynamically collect config entries from inputs
    let entries = config_loader::collect_config_entries(
        &opts.config_inputs.config_paths,
        &opts.config_inputs.config_dirs,
    )?;

    // 1.6) Detect stdin config and disable watch/reload if present
    let has_stdin = config_loader::entries_have_stdin(&entries);
    if has_stdin && opts.watch {
        // Stdin config is not reloadable - warn/error based on output mode
        match opts.reload_output {
            ReloadOutputMode::LogOnly => {
                tracing::warn!("stdin config detected; watch mode disabled (stdin not reloadable)");
            }
            ReloadOutputMode::JsonStderr => {
                let obj = serde_json::json!({
                    "event": "watch_disabled",
                    "reason": "stdin config not reloadable",
                    "fingerprint": env!("CARGO_PKG_VERSION")
                });
                eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
            }
        }
    }

    // 2) Load config with raw Value for DNS env bridge
    let (_cfg, ir, raw) = load_config_with_import_raw(&entries, opts.import_path.as_deref())?;

    // 2.0.1) Create shared reload state with initial fingerprint (shared across watch + SIGHUP)
    let (initial_fp_numeric, initial_fp_hex) = config_fingerprint(&raw);
    let startup_config_fingerprint = initial_fp_hex.clone(); // Keep copy for startup output
    let reload_state = Arc::new(TokioMutex::new(ReloadState {
        fingerprint: initial_fp_numeric,
        fingerprint_hex: initial_fp_hex,
    }));

    // 2.1) DNS environment bridge from config (only if enabled)
    let dns_applied = if opts.dns_env_bridge {
        apply_dns_env_from_config(&raw)
    } else {
        false
    };

    // 2.2) DNS stub init if needed
    if !dns_applied && (opts.dns_from_env || std::env::var("DNS_STUB").ok().as_deref() == Some("1"))
    {
        let ttl_secs: u64 = std::env::var("DNS_CACHE_TTL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        sb_core::dns::stub::init_global(ttl_secs);
    }

    // 3) Print transport plan for outbounds
    // - print_transport=true or SB_TRANSPORT_PLAN=1: info level "transport plan"
    // - otherwise: debug level "derived transport chain" (restore old bin/run behavior)
    let want_transport_info = opts.print_transport
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
        if want_transport_info {
            info!(
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

    // 4) Apply debug options
    apply_debug_options(&ir);

    // 4.5) Install global HTTP client for sb-core (geo downloads, remote rulesets)
    app::reqwest_http::install_global_http_client();

    // 5) Start Supervisor
    info!("Calling Supervisor::start");
    let supervisor = Arc::new(
        sb_core::runtime::supervisor::Supervisor::start(ir)
            .await
            .context("Supervisor::start failed")?,
    );
    info!("Supervisor::start returned");

    // 6) Admin server (core or debug)
    if let Some(ref addr) = opts.admin_listen {
        match opts.admin_impl {
            AdminImpl::Debug => {
                #[cfg(feature = "admin_debug")]
                {
                    let socket_addr: std::net::SocketAddr = addr
                        .parse()
                        .map_err(|e| anyhow::anyhow!("Invalid admin listen address: {e}"))?;

                    let tls_conf = app::admin_debug::http_server::TlsConf::from_env();
                    let auth_conf = app::admin_debug::http_server::AuthConf::from_env();

                    let tls_opt = if tls_conf.enabled {
                        Some(tls_conf)
                    } else {
                        None
                    };

                    app::admin_debug::http_server::spawn(socket_addr, tls_opt, auth_conf)
                        .map_err(|e| anyhow::anyhow!("Failed to start admin debug server: {e}"))?;
                    info!(addr = %socket_addr, r#impl = "debug", "Started admin debug server");
                }
                #[cfg(not(feature = "admin_debug"))]
                {
                    return Err(anyhow::anyhow!(
                        "admin_debug feature not enabled, cannot use admin_impl=debug"
                    ));
                }
            }
            AdminImpl::Core => {
                if let Err(e) = app::util::spawn_core_admin_from_supervisor(
                    addr,
                    opts.admin_token.clone(),
                    supervisor.clone(),
                )
                .await
                {
                    error!(error=%e, "failed to start core admin server");
                }
            }
        }
    }

    // 7) Startup output
    match opts.startup_output {
        StartupOutputMode::LogOnly => {
            if opts.print_startup {
                info!("singbox-rust booted; press Ctrl+C to quit");
            }
        }
        StartupOutputMode::TextStdout => {
            println!(
                "started pid={} fingerprint={}",
                std::process::id(),
                env!("CARGO_PKG_VERSION")
            );
        }
        StartupOutputMode::JsonStdout => {
            let obj = serde_json::json!({
                "event": "started",
                "pid": std::process::id(),
                "config_fingerprint": startup_config_fingerprint,
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        }
    }

    // 8) Optional watch mode (disabled if stdin config detected)
    let watch_handle = if opts.watch && !has_stdin {
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let sup_for_watch = supervisor.clone();
        let config_inputs_clone = opts.config_inputs.clone();
        let import_clone = opts.import_path.clone();
        let reload_output = opts.reload_output;
        let state_for_watch = reload_state.clone();

        // Initial snapshot with current entries and import
        let mut snapshot = snapshot_mtimes(&entries, opts.import_path.as_deref());

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    () = tokio::time::sleep(Duration::from_secs(2)) => {
                        // Dynamically re-collect entries each tick (detects dir changes)
                        let current_entries = match config_loader::collect_config_entries(
                            &config_inputs_clone.config_paths,
                            &config_inputs_clone.config_dirs,
                        ) {
                            Ok(e) => e,
                            Err(e) => {
                                tracing::warn!(error=%e, "failed to collect config entries");
                                continue;
                            }
                        };

                        let (changed, next_snapshot) = snapshot_changed(
                            &snapshot,
                            &current_entries,
                            import_clone.as_deref(),
                        );
                        snapshot = next_snapshot;
                        if !changed {
                            continue;
                        }
                        info!("config change detected; checking for reload…");
                        let outcome = reload_with_state(
                            state_for_watch.clone(),
                            &current_entries,
                            import_clone.as_deref(),
                            &sup_for_watch,
                        ).await;
                        report_reload_result(&outcome, ReloadSource::Watch, reload_output);
                    }
                }
            }
        });
        Some(WatchHandle {
            stop: stop_tx,
            join,
        })
    } else {
        None
    };

    // 9) Signal handling loop
    while let RunSignal::Reload = wait_for_signal().await {
        info!("SIGHUP received; reloading configuration…");

        // Determine entries for reload
        let reload_entries = if let Some(ref path) = opts.reload_path {
            vec![ConfigEntry {
                path: path.display().to_string(),
                source: config_loader::ConfigSource::File(path.clone()),
            }]
        } else {
            // Dynamically re-collect entries
            match config_loader::collect_config_entries(
                &opts.config_inputs.config_paths,
                &opts.config_inputs.config_dirs,
            ) {
                Ok(e) => e,
                Err(e) => {
                    let outcome = ReloadOutcome::Failed(e);
                    report_reload_result(&outcome, ReloadSource::Sighup, opts.reload_output);
                    continue;
                }
            }
        };

        // Check for stdin in reload entries
        if config_loader::entries_have_stdin(&reload_entries) {
            let outcome = ReloadOutcome::Failed(anyhow::anyhow!("stdin config not reloadable"));
            report_reload_result(&outcome, ReloadSource::Sighup, opts.reload_output);
            continue;
        }

        let import_for_reload = if opts.reload_path.is_some() {
            None
        } else {
            opts.import_path.as_deref()
        };

        let outcome = reload_with_state(
            reload_state.clone(),
            &reload_entries,
            import_for_reload,
            &supervisor,
        )
        .await;
        report_reload_result(&outcome, ReloadSource::Sighup, opts.reload_output);
    }

    // 10) Graceful shutdown
    let close_monitor = CloseMonitor::start();
    if let Some(watch) = watch_handle {
        watch.shutdown().await;
    }

    let grace_duration = Duration::from_millis(opts.grace_ms);
    let shutdown_result = supervisor.handle().shutdown_graceful(grace_duration).await;
    close_monitor.shutdown().await;

    if let Err(e) = shutdown_result {
        error!(error=%e, "Supervisor did not close properly");
        std::process::exit(1);
    }

    Ok(())
}

// ============================================================================
// DNS Environment Bridge
// ============================================================================

/// Apply DNS environment configuration from config file (top-level `dns` block).
/// Returns true if any DNS setting was derived from config.
#[cfg(feature = "router")]
#[allow(clippy::too_many_lines)]
fn apply_dns_env_from_config(doc: &serde_json::Value) -> bool {
    fn set_if_unset(k: &str, v: &str) {
        if std::env::var(k).is_err() {
            std::env::set_var(k, v);
        }
    }
    let mut applied = false;
    let Some(dns) = doc.get("dns") else {
        return false;
    };
    // servers: [{ address: "udp://1.1.1.1" | "https://..." | "dot://..." | "doq://..." | "system" | "rcode://..." }]
    if let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) {
        let mut pool_tokens: Vec<String> = Vec::new();
        let mut first_mode_set = false;
        for s in servers {
            let Some(addr_raw) = s.get("address").and_then(|v| v.as_str()) else {
                continue;
            };
            if addr_raw.starts_with("rcode://") {
                continue;
            }
            if let Some(rest) = addr_raw.strip_prefix("udp://") {
                let token = if rest.contains(':') {
                    format!("udp:{rest}")
                } else {
                    format!("udp:{rest}:53")
                };
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "udp");
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
                let token = format!("doq:{rest}");
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "doq");
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
            }
        }
        if !pool_tokens.is_empty() {
            set_if_unset("SB_DNS_POOL", &pool_tokens.join(","));
        }
    }
    // Strategy
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
    // TTL tuning
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
    // hosts
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
    // fakeip
    if let Some(fakeip) = dns.get("fakeip").and_then(|v| v.as_object()) {
        let enabled = fakeip
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if enabled {
            set_if_unset("SB_DNS_FAKEIP_ENABLE", "1");
            applied = true;
            if let Some(r) = fakeip.get("inet4_range").and_then(|v| v.as_str()) {
                if let Some((base, mask)) = split_cidr(r) {
                    set_if_unset("SB_FAKEIP_V4_BASE", base);
                    set_if_unset("SB_FAKEIP_V4_MASK", &mask.to_string());
                }
            }
            if let Some(r) = fakeip.get("inet6_range").and_then(|v| v.as_str()) {
                if let Some((base, mask)) = split_cidr(r) {
                    set_if_unset("SB_FAKEIP_V6_BASE", base);
                    set_if_unset("SB_FAKEIP_V6_MASK", &mask.to_string());
                }
            }
        }
    }
    // pool selection strategy
    if let Some(s) = dns.get("pool_strategy").and_then(|v| v.as_str()) {
        let s_lc = s.to_ascii_lowercase();
        let v_norm = match s_lc.as_str() {
            "race" | "racing" => "race",
            "fanout" | "parallel" => "fanout",
            "sequential" | "seq" => "sequential",
            _ => s_lc.as_str(),
        };
        set_if_unset("SB_DNS_POOL_STRATEGY", v_norm);
        applied = true;
    }
    if let Some(pool) = dns.get("pool").and_then(|v| v.as_object()) {
        if let Some(v) = pool
            .get("race_window_ms")
            .and_then(serde_json::Value::as_u64)
        {
            set_if_unset("SB_DNS_RACE_WINDOW_MS", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool.get("he_race_ms").and_then(serde_json::Value::as_u64) {
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
        if let Some(v) = pool.get("max_inflight").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_POOL_MAX_INFLIGHT", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool
            .get("per_host_inflight")
            .and_then(serde_json::Value::as_u64)
        {
            set_if_unset("SB_DNS_PER_HOST_INFLIGHT", &v.to_string());
            applied = true;
        }
    }
    // timeouts
    if let Some(v) = dns.get("timeout_ms").and_then(serde_json::Value::as_u64) {
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
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            set_if_unset("SB_DNS_CACHE_ENABLE", "1");
            applied = true;
        }
        if let Some(cap) = cache.get("cap").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_CACHE_CAP", &cap.to_string());
            applied = true;
        }
        if let Some(neg_ms) = cache.get("neg_ttl_ms").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_CACHE_NEG_TTL_MS", &neg_ms.to_string());
            applied = true;
        }
    }
    applied
}

#[cfg(feature = "router")]
fn num_or_string_secs(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(n) = s.parse::<u64>() {
            return Some(n);
        }
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

#[cfg(feature = "router")]
fn split_cidr(s: &str) -> Option<(&str, u8)> {
    let s = s.trim();
    let (base, mask) = s.split_once('/')?;
    let m = mask.parse::<u8>().ok()?;
    Some((base, m))
}
