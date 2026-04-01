//! Shared run engine facade for CLI and bin run commands.
//!
//! This module now keeps the public entry points and option types thin while
//! delegating runtime orchestration owners to `run_engine_runtime/*`.

use anyhow::Result;
use std::path::{Path, PathBuf};
#[cfg(feature = "router")]
use std::sync::Arc;

use crate::config_loader::ConfigEntry;
use sb_config::ir::ConfigIR;

/// Apply debug/pprof options from config's experimental.debug section.
pub fn apply_debug_options(ir: &ConfigIR) {
    crate::run_engine_runtime::debug_env::apply_debug_options(ir);
}

/// Load config with optional subscription import.
///
/// Returns `(Config, ConfigIR)`.
///
/// # Errors
///
/// Returns an error if config loading, optional subscription import, validation,
/// or IR conversion fails.
pub fn load_config_with_import(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> Result<(sb_config::Config, ConfigIR)> {
    crate::run_engine_runtime::config_load::load_config_with_import(entries, import_path)
}

/// Load config with optional subscription import, returning merged raw `Value`.
///
/// Returns `(Config, ConfigIR, raw_value)`.
///
/// # Errors
///
/// Returns an error if raw loading, optional subscription import, validation,
/// or IR conversion fails.
pub fn load_config_with_import_raw(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> Result<(sb_config::Config, ConfigIR, serde_json::Value)> {
    crate::run_engine_runtime::config_load::load_config_with_import_raw(entries, import_path)
}

/// Unified reload helper for watch mode and SIGHUP.
///
/// # Errors
///
/// Returns an error if config reloading or `Supervisor::reload` fails.
#[cfg(feature = "router")]
pub async fn reload_with_supervisor(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
    supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
) -> Result<()> {
    crate::run_engine_runtime::config_load::reload_with_supervisor(entries, import_path, supervisor)
        .await
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
    Applied(String),
    SkippedNoChange(String),
    Failed(anyhow::Error),
}

/// Configuration input sources for dynamic entry resolution.
#[cfg(feature = "router")]
#[derive(Clone, Debug, Default)]
pub struct ConfigInputs {
    pub config_paths: Vec<PathBuf>,
    pub config_dirs: Vec<PathBuf>,
}

/// Options for the unified supervisor run loop.
#[cfg(feature = "router")]
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct RunOptions {
    pub config_inputs: ConfigInputs,
    pub import_path: Option<PathBuf>,
    pub watch: bool,
    pub reload_path: Option<PathBuf>,
    pub admin_listen: Option<String>,
    pub admin_token: Option<String>,
    pub admin_impl: AdminImpl,
    pub print_startup: bool,
    pub startup_output: StartupOutputMode,
    pub reload_output: ReloadOutputMode,
    pub grace_ms: u64,
    pub prom_listen: Option<String>,
    pub dns_from_env: bool,
    pub print_transport: bool,
    pub health_enable: bool,
    pub dns_env_bridge: bool,
}

/// Mode for startup output.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum StartupOutputMode {
    #[default]
    LogOnly,
    TextStdout,
    JsonStdout,
}

/// Admin server implementation.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AdminImpl {
    #[default]
    Core,
    Debug,
}

/// Mode for reload success/failure output.
#[cfg(feature = "router")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ReloadOutputMode {
    #[default]
    LogOnly,
    JsonStderr,
}

/// Unified supervisor run loop facade.
///
/// # Errors
///
/// Returns an error if startup configuration, runtime dependency setup, or
/// runtime orchestration initialization fails.
#[cfg(feature = "router")]
pub async fn run_supervisor(opts: RunOptions) -> Result<()> {
    crate::run_engine_runtime::supervisor::run_supervisor(opts).await
}
