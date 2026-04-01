use sb_config::ir::ConfigIR;
use tracing::{error, info};

pub fn report_watch_disabled(mode: crate::run_engine::ReloadOutputMode) {
    match mode {
        crate::run_engine::ReloadOutputMode::LogOnly => {
            tracing::warn!("stdin config detected; watch mode disabled (stdin not reloadable)");
        }
        crate::run_engine::ReloadOutputMode::JsonStderr => {
            let obj = serde_json::json!({
                "event": "watch_disabled",
                "reason": "stdin config not reloadable",
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
    }
}

pub fn report_reload_result(
    outcome: &crate::run_engine::ReloadOutcome,
    source: crate::run_engine::ReloadSource,
    mode: crate::run_engine::ReloadOutputMode,
) {
    let source_str = match source {
        crate::run_engine::ReloadSource::Watch => "watch",
        crate::run_engine::ReloadSource::Sighup => "SIGHUP",
    };

    match (outcome, mode) {
        (
            crate::run_engine::ReloadOutcome::Applied(config_fingerprint),
            crate::run_engine::ReloadOutputMode::LogOnly,
        ) => {
            info!(source=%source_str, config_fingerprint=%config_fingerprint, "hot-reload applied");
        }
        (
            crate::run_engine::ReloadOutcome::SkippedNoChange(config_fingerprint),
            crate::run_engine::ReloadOutputMode::LogOnly,
        ) => {
            info!(source=%source_str, config_fingerprint=%config_fingerprint, "reload skipped (config unchanged)");
        }
        (
            crate::run_engine::ReloadOutcome::Failed(error),
            crate::run_engine::ReloadOutputMode::LogOnly,
        ) => {
            error!(source=%source_str, error=%error, "reload failed");
        }
        (
            crate::run_engine::ReloadOutcome::Applied(config_fingerprint),
            crate::run_engine::ReloadOutputMode::JsonStderr,
        ) => {
            let obj = serde_json::json!({
                "event": "reload",
                "ok": true,
                "source": source_str,
                "applied": true,
                "config_fingerprint": config_fingerprint,
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
        (
            crate::run_engine::ReloadOutcome::SkippedNoChange(config_fingerprint),
            crate::run_engine::ReloadOutputMode::JsonStderr,
        ) => {
            let obj = serde_json::json!({
                "event": "reload",
                "ok": true,
                "source": source_str,
                "applied": false,
                "reason": "no_change",
                "config_fingerprint": config_fingerprint,
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
        (
            crate::run_engine::ReloadOutcome::Failed(error),
            crate::run_engine::ReloadOutputMode::JsonStderr,
        ) => {
            let obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "source": source_str,
                "applied": false,
                "error": error.to_string(),
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            eprintln!("{}", serde_json::to_string(&obj).unwrap_or_default());
        }
    }
}

pub fn emit_startup_output(opts: &crate::run_engine::RunOptions, startup_config_fingerprint: &str) {
    match opts.startup_output {
        crate::run_engine::StartupOutputMode::LogOnly => {
            if opts.print_startup {
                info!("singbox-rust booted; press Ctrl+C to quit");
            }
        }
        crate::run_engine::StartupOutputMode::TextStdout => {
            println!(
                "started pid={} fingerprint={}",
                std::process::id(),
                env!("CARGO_PKG_VERSION")
            );
        }
        crate::run_engine::StartupOutputMode::JsonStdout => {
            let obj = serde_json::json!({
                "event": "started",
                "pid": std::process::id(),
                "config_fingerprint": startup_config_fingerprint,
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            println!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        }
    }
}

pub fn log_transport_plan(ir: &ConfigIR, print_transport: bool) {
    let want_transport_info = print_transport
        || std::env::var("SB_TRANSPORT_PLAN")
            .ok()
            .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));

    for outbound in &ir.outbounds {
        let name = outbound
            .name
            .clone()
            .unwrap_or_else(|| outbound.ty_str().to_string());
        let kind = outbound.ty_str();
        let chain = sb_core::runtime::transport::map::chain_from_ir(outbound);
        let sni = outbound.tls_sni.clone().unwrap_or_default();
        let alpn = outbound
            .tls_alpn
            .as_ref()
            .map(|items| items.join(","))
            .unwrap_or_default();

        if want_transport_info {
            info!(
                target: "sb_transport",
                outbound = %name,
                kind = %kind,
                chain = %chain.join(","),
                sni = %sni,
                alpn = %alpn,
                "transport plan"
            );
        } else {
            tracing::debug!(
                target: "sb_transport",
                outbound = %name,
                kind = %kind,
                chain = %chain.join(","),
                sni = %sni,
                alpn = %alpn,
                "derived transport chain"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn wp30ao_pin_output_owner_moved_out_of_run_engine_rs() {
        let source = include_str!("output.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("fn report_reload_result("));
        assert!(source.contains("fn emit_startup_output("));
        assert!(source.contains("fn log_transport_plan("));
        assert!(!run_engine.contains("fn report_reload_result("));
        assert!(!run_engine.contains("transport plan"));
    }
}
