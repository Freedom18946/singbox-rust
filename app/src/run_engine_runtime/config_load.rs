use anyhow::{Context, Result};
use sb_config::ir::ConfigIR;
use std::fs;
use std::path::Path;
#[cfg(feature = "router")]
use std::sync::Arc;
use tracing::info;

use crate::config_loader::{self, ConfigEntry};

/// Load config with optional subscription import.
///
/// Returns `(Config, ConfigIR)`.
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
    let ir = sb_config::present::to_ir(&cfg).context("to_ir failed")?;
    Ok((cfg, ir))
}

/// Load config with optional subscription import, returning merged raw `Value`.
///
/// Returns `(Config, ConfigIR, raw_value)`.
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
        ir = sb_config::present::to_ir(&cfg).context("to_ir after merge failed")?;
    }

    let merged_raw = cfg.raw().clone();
    Ok((cfg, ir, merged_raw))
}

#[cfg(feature = "router")]
pub fn config_fingerprint(raw: &serde_json::Value) -> (u64, String) {
    let hex = sb_config::json_norm::fingerprint_hex8(raw);
    let numeric = u64::from_str_radix(&hex, 16).unwrap_or(0);
    (numeric, hex)
}

#[cfg(feature = "router")]
pub struct ReloadState {
    pub fingerprint: u64,
    pub fingerprint_hex: String,
}

#[cfg(feature = "router")]
impl ReloadState {
    pub fn from_raw(raw: &serde_json::Value) -> Self {
        let (fingerprint, fingerprint_hex) = config_fingerprint(raw);
        Self {
            fingerprint,
            fingerprint_hex,
        }
    }
}

#[cfg(feature = "router")]
pub type TokioMutex<T> = tokio::sync::Mutex<T>;

#[cfg(feature = "router")]
pub async fn reload_with_supervisor(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
    supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
) -> Result<()> {
    let (_cfg, ir) = load_config_with_import(entries, import_path)?;
    crate::run_engine_runtime::debug_env::apply_debug_options(&ir);
    supervisor
        .reload(ir)
        .await
        .context("Supervisor reload failed")?;
    Ok(())
}

/// Reload with shared state for serialization and fingerprint-based change detection.
#[cfg(feature = "router")]
pub async fn reload_with_state(
    state: Arc<TokioMutex<ReloadState>>,
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
    supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
) -> crate::run_engine::ReloadOutcome {
    let mut guard = state.lock().await;

    let (_, ir, raw) = match load_config_with_import_raw(entries, import_path) {
        Ok(v) => v,
        Err(error) => return crate::run_engine::ReloadOutcome::Failed(error),
    };

    let (new_fp_numeric, new_fp_hex) = config_fingerprint(&raw);
    if new_fp_numeric == guard.fingerprint {
        return crate::run_engine::ReloadOutcome::SkippedNoChange(guard.fingerprint_hex.clone());
    }

    crate::run_engine_runtime::debug_env::apply_debug_options(&ir);
    match supervisor.reload(ir).await {
        Ok(_) => {
            guard.fingerprint = new_fp_numeric;
            guard.fingerprint_hex.clone_from(&new_fp_hex);
            drop(guard);
            crate::run_engine::ReloadOutcome::Applied(new_fp_hex)
        }
        Err(error) => crate::run_engine::ReloadOutcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{load_config_with_import, load_config_with_import_raw};
    use crate::config_loader::{ConfigEntry, ConfigSource};
    use std::fs;
    use tempfile::tempdir;

    fn file_entry(path: &std::path::Path) -> ConfigEntry {
        ConfigEntry {
            path: path.display().to_string(),
            source: ConfigSource::File(path.to_path_buf()),
        }
    }

    #[test]
    fn load_config_with_import_builds_ir_from_base_config() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let config_path = dir.path().join("base.json");
        fs::write(
            &config_path,
            r#"{
                "log": { "level": "info" },
                "outbounds": [{ "type": "direct", "tag": "base-direct" }]
            }"#,
        )?;

        let (_cfg, ir) = load_config_with_import(&[file_entry(&config_path)], None)?;

        assert_eq!(ir.outbounds.len(), 1);
        assert_eq!(ir.outbounds[0].name.as_deref(), Some("base-direct"));
        Ok(())
    }

    #[test]
    fn load_config_with_import_raw_merges_subscription_and_returns_merged_raw() -> anyhow::Result<()>
    {
        let dir = tempdir()?;
        let base_path = dir.path().join("base.json");
        let import_path = dir.path().join("subscription.json");

        fs::write(
            &base_path,
            r#"{
                "outbounds": [{ "type": "direct", "tag": "base-direct" }]
            }"#,
        )?;
        fs::write(
            &import_path,
            r#"{
                "outbounds": [
                    {
                        "type": "http",
                        "tag": "import-http",
                        "server": "1.1.1.1",
                        "server_port": 8080
                    }
                ]
            }"#,
        )?;

        let (_cfg, ir, raw) =
            load_config_with_import_raw(&[file_entry(&base_path)], Some(import_path.as_path()))?;

        let outbounds = raw
            .get("outbounds")
            .and_then(serde_json::Value::as_array)
            .expect("merged raw contains outbounds");

        assert_eq!(ir.outbounds.len(), 2);
        assert_eq!(outbounds.len(), 2);
        assert!(outbounds.iter().any(|item| {
            item.get("tag")
                .or_else(|| item.get("name"))
                .and_then(serde_json::Value::as_str)
                == Some("import-http")
        }));
        Ok(())
    }

    #[test]
    fn wp30ao_pin_run_engine_facade_delegates_config_loading() {
        let source = include_str!("config_load.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("fn load_config_with_import("));
        assert!(source.contains("fn load_config_with_import_raw("));
        assert!(run_engine.contains("run_engine_runtime::config_load::load_config_with_import("));
        assert!(
            run_engine.contains("run_engine_runtime::config_load::load_config_with_import_raw(")
        );
        assert!(!run_engine.contains("config after import invalid"));
    }

    #[cfg(feature = "router")]
    #[test]
    fn wp30ao_pin_run_engine_facade_delegates_reload_helper() {
        let source = include_str!("config_load.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("async fn reload_with_supervisor("));
        assert!(run_engine.contains("run_engine_runtime::config_load::reload_with_supervisor("));
        assert!(!run_engine.contains("Supervisor reload failed"));
    }
}
