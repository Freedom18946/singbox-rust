use anyhow::Result;
use std::fs;
use std::path::Path;

/// Simple atomic file write implementation for CLI tools
///
/// # Errors
/// Returns an error if:
/// - Writing to the temporary file fails
/// - Renaming the temporary file to the target path fails
pub fn write_atomic<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<()> {
    let path = path.as_ref();
    let temp_path = path.with_extension("tmp");

    // Write to temporary file first
    fs::write(&temp_path, contents)?;

    // Atomically rename to final destination
    fs::rename(temp_path, path)?;

    Ok(())
}

/// Register adapters (idempotent).
/// When `adapters` feature is enabled, calls `sb_adapters::register_all()`.
/// Otherwise, this is a no-op.
#[inline]
pub fn register_adapters_once() {
    #[cfg(feature = "adapters")]
    sb_adapters::register_all();
}

/// Spawn core admin HTTP server using real engine/bridge from Supervisor state.
///
/// This helper consolidates the logic to:
/// 1. Get engine/bridge from Supervisor state
/// 2. Call sb_core::admin::http::spawn_admin with proper arguments
/// 3. Log the startup message
///
/// # Arguments
/// * `listen` - The address to listen on (e.g. "127.0.0.1:19090")
/// * `token` - Optional authentication token
/// * `supervisor` - Arc reference to the Supervisor
///
/// # Errors
/// Returns an error if spawn_admin fails to bind to the address.
#[cfg(feature = "router")]
pub async fn spawn_core_admin_from_supervisor(
    listen: &str,
    token: Option<String>,
    supervisor: std::sync::Arc<sb_core::runtime::supervisor::Supervisor>,
) -> anyhow::Result<()> {
    use sb_core::admin::http::spawn_admin;

    let supervisor_for_admin = Some(supervisor.clone());
    let handle = tokio::runtime::Handle::current();

    // Get real engine/bridge from Supervisor state
    let state_lock = supervisor.handle().state().await;
    let state_guard = state_lock.read().await;
    let engine = state_guard.engine.clone();
    let bridge = state_guard.bridge.clone();
    drop(state_guard);

    spawn_admin(
        listen,
        engine,
        bridge,
        token,
        supervisor_for_admin,
        Some(handle),
    )?;

    tracing::info!(addr = %listen, "Started core admin server");
    Ok(())
}
