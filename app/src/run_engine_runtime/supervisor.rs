use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::config_loader::{self, ConfigEntry};

const FATAL_STOP_TIMEOUT: Duration = Duration::from_secs(10);

struct CloseMonitor {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

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
        if self.stop.send(()).is_err() {
            tracing::debug!("close monitor stop signal dropped before shutdown");
        }
        if let Err(error) = self.join.await {
            tracing::warn!(%error, "close monitor join failed during shutdown");
        }
    }
}

fn maybe_start_prom_exporter(
    prom_listen: Option<&str>,
    runtime_deps: &crate::runtime_deps::AppRuntimeDeps,
) {
    let Some(addr) = prom_listen else {
        return;
    };

    #[cfg(feature = "sb-metrics")]
    match addr.parse() {
        Ok(socket_addr) => {
            let _join_handle =
                sb_metrics::spawn_http_exporter(runtime_deps.metrics_registry(), socket_addr);
        }
        Err(error) => {
            tracing::warn!(addr = %addr, error = %error, "invalid prom exporter listen addr");
        }
    }

    #[cfg(not(feature = "sb-metrics"))]
    {
        let addr = addr.to_string();
        std::thread::spawn(move || {
            #[allow(deprecated)]
            let _ = sb_core::metrics::http_exporter::run_exporter(&addr);
        });
    }
}

fn maybe_init_dns_stub(dns_applied: bool, opts: &crate::run_engine::RunOptions) {
    if dns_applied || !(opts.dns_from_env || std::env::var("DNS_STUB").ok().as_deref() == Some("1"))
    {
        return;
    }

    let ttl_secs: u64 = std::env::var("DNS_CACHE_TTL").map_or(30, |raw| {
        let trimmed = raw.trim();
        match trimmed.parse::<u64>() {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("env 'DNS_CACHE_TTL' value '{trimmed}' is not a valid u64; silent parse fallback is disabled; using default 30: {error}");
                30
            }
        }
    });
    sb_core::dns::stub::init_global(ttl_secs);
}

async fn start_supervisor(
    ir: sb_config::ir::ConfigIR,
) -> Result<Arc<sb_core::runtime::supervisor::Supervisor>> {
    #[cfg(feature = "adapters")]
    info!("Calling Supervisor::start_with_registry");
    #[cfg(not(feature = "adapters"))]
    info!("Calling Supervisor::start");

    #[cfg(feature = "adapters")]
    let supervisor = Arc::new(
        sb_core::runtime::supervisor::Supervisor::start_with_registry(
            ir,
            Some(sb_adapters::build_default_registry()),
        )
        .await
        .context("Supervisor::start_with_registry failed")?,
    );

    #[cfg(not(feature = "adapters"))]
    let supervisor = Arc::new(
        sb_core::runtime::supervisor::Supervisor::start(ir)
            .await
            .context("Supervisor::start failed")?,
    );

    info!("Supervisor startup returned");
    Ok(supervisor)
}

fn reload_entries_from_opts(opts: &crate::run_engine::RunOptions) -> Result<Vec<ConfigEntry>> {
    if let Some(path) = opts.reload_path.as_ref() {
        return Ok(vec![ConfigEntry {
            path: path.display().to_string(),
            source: config_loader::ConfigSource::File(path.clone()),
        }]);
    }

    config_loader::collect_config_entries(
        &opts.config_inputs.config_paths,
        &opts.config_inputs.config_dirs,
    )
}

fn import_path_for_reload(opts: &crate::run_engine::RunOptions) -> Option<&std::path::Path> {
    if opts.reload_path.is_some() {
        None
    } else {
        opts.import_path.as_deref()
    }
}

fn apply_tls_provider_and_probe(
    raw: &serde_json::Value,
    ir: &sb_config::ir::ConfigIR,
) -> Result<()> {
    let tls_provider = crate::tls_provider::ensure_default_provider()
        .context("failed to select/install rustls crypto provider")?;

    let mut capability_probe = crate::capability_probe::collect_report(raw, ir);
    for id in ["tls.ech.tcp", "tls.ech.quic"] {
        if let Some(probe) = capability_probe
            .probes
            .iter_mut()
            .find(|probe| probe.capability_id == id)
        {
            probe.details.insert(
                "tls_provider".to_string(),
                tls_provider.provider.as_str().to_string(),
            );
            probe.details.insert(
                "tls_provider_source".to_string(),
                tls_provider.source.to_string(),
            );
            probe.details.insert(
                "tls_provider_install".to_string(),
                tls_provider.install_result.to_string(),
            );
            probe.details.insert(
                "tls_provider_requested".to_string(),
                tls_provider.requested.clone(),
            );
            probe.details.insert(
                "tls_provider_fallback_reason".to_string(),
                tls_provider
                    .fallback_reason
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
    }
    crate::capability_probe::log_report(&capability_probe);

    let find_probe = |id: &str| {
        capability_probe
            .probes
            .iter()
            .find(|probe| probe.capability_id == id)
    };
    let ech_tcp_requested = find_probe("tls.ech.tcp").is_some_and(|probe| probe.requested);
    let ech_tcp_runtime =
        find_probe("tls.ech.tcp").map_or("unsupported", |probe| probe.runtime_state.as_str());
    let ech_tcp_compile =
        find_probe("tls.ech.tcp").map_or("absent", |probe| probe.compile_state.as_str());
    let ech_quic_requested = find_probe("tls.ech.quic").is_some_and(|probe| probe.requested);
    let ech_quic_runtime =
        find_probe("tls.ech.quic").map_or("unsupported", |probe| probe.runtime_state.as_str());
    tracing::info!(
        target: "app::tls_provider",
        provider = tls_provider.provider.as_str(),
        requested = %tls_provider.requested,
        source = tls_provider.source,
        install = tls_provider.install_result,
        fallback = tls_provider.fallback_reason.as_deref().unwrap_or("-"),
        ech_feature_enabled = cfg!(feature = "tls_ech"),
        ech_tcp_requested,
        ech_tcp_compile,
        ech_tcp_runtime,
        ech_quic_requested,
        ech_quic_runtime,
        aws_lc_compiled = crate::tls_provider::aws_lc_compiled(),
        "tls provider decision"
    );

    if let Some(path) = crate::capability_probe::probe_output_path_from_env() {
        let out_path = PathBuf::from(&path);
        match crate::capability_probe::write_report(&capability_probe, &out_path) {
            Ok(()) => tracing::info!(
                path = %out_path.display(),
                probe_count = capability_probe.probes.len(),
                "capability probe report written"
            ),
            Err(error) => tracing::warn!(
                path = %out_path.display(),
                error = %error,
                "failed to write capability probe report"
            ),
        }
    }

    if crate::capability_probe::probe_only_enabled() {
        tracing::info!("capability probe only mode enabled; skipping supervisor startup");
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
pub async fn run_supervisor(opts: crate::run_engine::RunOptions) -> Result<()> {
    if opts.health_enable {
        std::env::set_var("SB_HEALTH_ENABLE", "1");
    }

    let runtime_deps =
        crate::runtime_deps::AppRuntimeDeps::new().context("failed to build runtime deps")?;

    maybe_start_prom_exporter(opts.prom_listen.as_deref(), &runtime_deps);

    let entries = config_loader::collect_config_entries(
        &opts.config_inputs.config_paths,
        &opts.config_inputs.config_dirs,
    )?;

    let has_stdin = config_loader::entries_have_stdin(&entries);
    if has_stdin && opts.watch {
        crate::run_engine_runtime::output::report_watch_disabled(opts.reload_output);
    }

    let (_cfg, ir, raw) = crate::run_engine_runtime::config_load::load_config_with_import_raw(
        &entries,
        opts.import_path.as_deref(),
    )?;

    apply_tls_provider_and_probe(&raw, &ir)?;
    if crate::capability_probe::probe_only_enabled() {
        return Ok(());
    }

    let reload_state = Arc::new(crate::run_engine_runtime::config_load::TokioMutex::new(
        crate::run_engine_runtime::config_load::ReloadState::from_raw(&raw),
    ));
    let startup_config_fingerprint = {
        let guard = reload_state.lock().await;
        guard.fingerprint_hex.clone()
    };

    let dns_applied = if opts.dns_env_bridge {
        crate::dns_env::apply_dns_env_from_config(&raw)
    } else {
        false
    };
    maybe_init_dns_stub(dns_applied, &opts);

    crate::run_engine_runtime::output::log_transport_plan(&ir, opts.print_transport);
    crate::run_engine_runtime::debug_env::apply_debug_options(&ir);

    let supervisor = start_supervisor(ir).await?;
    let admin_services = crate::run_engine_runtime::admin_start::start_admin_services(
        &opts,
        &supervisor,
        &runtime_deps,
    )
    .await?;

    crate::run_engine_runtime::output::emit_startup_output(&opts, &startup_config_fingerprint);

    let watch_handle = if opts.watch && !has_stdin {
        Some(crate::run_engine_runtime::watch::spawn_watch_task(
            &entries,
            opts.config_inputs.clone(),
            opts.import_path.clone(),
            opts.reload_output,
            reload_state.clone(),
            supervisor.clone(),
        ))
    } else {
        None
    };

    loop {
        match crate::run_engine_runtime::watch::wait_for_signal().await {
            crate::run_engine_runtime::watch::RunSignal::Reload => {}
            crate::run_engine_runtime::watch::RunSignal::Terminate => break,
        }
        info!("SIGHUP received; reloading configuration…");

        let reload_entries = match reload_entries_from_opts(&opts) {
            Ok(entries) => entries,
            Err(error) => {
                let outcome = crate::run_engine::ReloadOutcome::Failed(error);
                crate::run_engine_runtime::output::report_reload_result(
                    &outcome,
                    crate::run_engine::ReloadSource::Sighup,
                    opts.reload_output,
                );
                continue;
            }
        };

        if config_loader::entries_have_stdin(&reload_entries) {
            let outcome = crate::run_engine::ReloadOutcome::Failed(anyhow::anyhow!(
                "stdin config not reloadable"
            ));
            crate::run_engine_runtime::output::report_reload_result(
                &outcome,
                crate::run_engine::ReloadSource::Sighup,
                opts.reload_output,
            );
            continue;
        }

        let outcome = crate::run_engine_runtime::config_load::reload_with_state(
            reload_state.clone(),
            &reload_entries,
            import_path_for_reload(&opts),
            &supervisor,
        )
        .await;
        crate::run_engine_runtime::output::report_reload_result(
            &outcome,
            crate::run_engine::ReloadSource::Sighup,
            opts.reload_output,
        );
    }

    let close_monitor = CloseMonitor::start();
    if let Some(watch) = watch_handle {
        watch.shutdown().await;
    }
    admin_services.shutdown().await;

    let grace_duration = Duration::from_millis(opts.grace_ms);
    let shutdown_result = supervisor.handle().shutdown_graceful(grace_duration).await;
    close_monitor.shutdown().await;

    if let Err(error) = shutdown_result {
        error!(error=%error, "Supervisor did not close properly");
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn wp30ao_pin_run_engine_is_thin_supervisor_facade() {
        let source = include_str!("supervisor.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("async fn run_supervisor("));
        assert!(run_engine.contains("run_engine_runtime::supervisor::run_supervisor(opts).await"));
        assert!(!run_engine.contains("struct CloseMonitor"));
        assert!(!run_engine.contains("Supervisor startup returned"));
    }
}
