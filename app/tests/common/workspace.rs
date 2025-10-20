//! Workspace binary location utilities for tests

use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;
use std::fs;

/// Locate a workspace binary by name.
///
/// Tries environment variable first (e.g., CARGO_BIN_EXE_check),
/// then falls back to target/profile/binary_name path.
///
/// # Example
///
/// ```no_run
/// let check_bin = workspace_bin("check");
/// assert!(check_bin.exists());
/// ```
pub fn workspace_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // Go to workspace root
    path.push("target");

    let profile = std::env::var("CARGO_PROFILE")
        .ok()
        .or_else(|| std::env::var("PROFILE").ok())
        .unwrap_or_else(|| "debug".into());

    path.push(profile);
    path.push(name);

    if cfg!(windows) {
        path.set_extension("exe");
    }

    path
}

/// Write configuration content to a temporary file.
///
/// # Example
///
/// ```no_run
/// let cfg = r#"{"schema_version": 2}"#;
/// let temp = write_temp_config(cfg);
/// // Use temp.path() for the file path
/// ```
pub fn write_temp_config(content: &str) -> NamedTempFile {
    let f = NamedTempFile::new().expect("Failed to create temp file");
    fs::write(f.path(), content.as_bytes()).expect("Failed to write config");
    f
}

/// Run a binary check command with the given config path.
///
/// Returns (success, stdout) tuple if the command runs successfully.
///
/// # Example
///
/// ```no_run
/// if let Some((success, output)) = run_check("config.json") {
///     assert!(success, "Check failed: {}", output);
/// }
/// ```
pub fn run_check(cfg_path: &str) -> Option<(bool, String)> {
    let bin = workspace_bin("check").to_string_lossy().to_string();
    let out = Command::new(bin)
        .args(&["--config", cfg_path])
        .output()
        .ok()?;
    let success = out.status.success();
    let stdout = String::from_utf8(out.stdout).ok()?;
    Some((success, stdout))
}
