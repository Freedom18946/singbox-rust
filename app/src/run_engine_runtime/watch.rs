use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::config_loader::{self, ConfigEntry};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct WatchHandle {
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl WatchHandle {
    pub async fn shutdown(self) {
        if self.stop.send(()).is_err() {
            tracing::debug!("watch stop signal dropped before shutdown");
        }
        if let Err(error) = self.join.await {
            tracing::warn!(%error, "watch task join failed during shutdown");
        }
    }
}

fn file_mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

pub fn snapshot_mtimes(
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> HashMap<PathBuf, SystemTime> {
    let mut snapshot = HashMap::new();
    for path in config_loader::entry_files(entries) {
        snapshot.insert(path.clone(), file_mtime(&path));
    }
    if let Some(import) = import_path {
        if import.exists() {
            snapshot.insert(import.to_path_buf(), file_mtime(import));
        }
    }
    snapshot
}

pub fn snapshot_changed(
    prev: &HashMap<PathBuf, SystemTime>,
    entries: &[ConfigEntry],
    import_path: Option<&Path>,
) -> (bool, HashMap<PathBuf, SystemTime>) {
    let mut changed = false;
    let mut current = HashMap::new();

    for path in config_loader::entry_files(entries) {
        let now = file_mtime(&path);
        match prev.get(&path) {
            Some(old) => {
                if now > *old {
                    changed = true;
                }
            }
            None => changed = true,
        }
        current.insert(path, now);
    }

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

    if prev.len() != current.len() {
        changed = true;
    }
    for path in prev.keys() {
        if !current.contains_key(path) {
            changed = true;
            break;
        }
    }

    (changed, current)
}

pub fn spawn_watch_task(
    entries: &[ConfigEntry],
    config_inputs: crate::run_engine::ConfigInputs,
    import_path: Option<PathBuf>,
    reload_output: crate::run_engine::ReloadOutputMode,
    state: Arc<
        crate::run_engine_runtime::config_load::TokioMutex<
            crate::run_engine_runtime::config_load::ReloadState,
        >,
    >,
    supervisor: Arc<sb_core::runtime::supervisor::Supervisor>,
) -> WatchHandle {
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let mut snapshot = snapshot_mtimes(entries, import_path.as_deref());

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                () = tokio::time::sleep(Duration::from_secs(2)) => {
                    let current_entries = match config_loader::collect_config_entries(
                        &config_inputs.config_paths,
                        &config_inputs.config_dirs,
                    ) {
                        Ok(entries) => entries,
                        Err(error) => {
                            tracing::warn!(error=%error, "failed to collect config entries");
                            continue;
                        }
                    };

                    let (changed, next_snapshot) = snapshot_changed(
                        &snapshot,
                        &current_entries,
                        import_path.as_deref(),
                    );
                    snapshot = next_snapshot;
                    if !changed {
                        continue;
                    }

                    tracing::info!("config change detected; checking for reload…");
                    let outcome = crate::run_engine_runtime::config_load::reload_with_state(
                        state.clone(),
                        &current_entries,
                        import_path.as_deref(),
                        &supervisor,
                    )
                    .await;
                    crate::run_engine_runtime::output::report_reload_result(
                        &outcome,
                        crate::run_engine::ReloadSource::Watch,
                        reload_output,
                    );
                }
            }
        }
    });

    WatchHandle {
        stop: stop_tx,
        join,
    }
}

pub enum RunSignal {
    Reload,
    Terminate,
}

pub async fn wait_for_signal() -> RunSignal {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => RunSignal::Terminate,
        () = term_signal() => RunSignal::Terminate,
        () = hup_signal() => RunSignal::Reload,
    }
}

#[cfg(unix)]
async fn term_signal() {
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        tracing::warn!("failed to register SIGTERM handler");
        return;
    };
    term.recv().await;
}

#[cfg(not(unix))]
async fn term_signal() {
    std::future::pending::<()>().await;
}

#[cfg(unix)]
async fn hup_signal() {
    let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else {
        tracing::warn!("failed to register SIGHUP handler");
        return;
    };
    hup.recv().await;
}

#[cfg(not(unix))]
async fn hup_signal() {
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod tests {
    use super::{snapshot_changed, snapshot_mtimes};
    use crate::config_loader::{ConfigEntry, ConfigSource};
    use std::collections::HashMap;
    use std::fs;
    use std::time::SystemTime;
    use tempfile::tempdir;

    fn file_entry(path: &std::path::Path) -> ConfigEntry {
        ConfigEntry {
            path: path.display().to_string(),
            source: ConfigSource::File(path.to_path_buf()),
        }
    }

    #[test]
    fn snapshot_changed_detects_added_file_from_dynamic_entry_collection() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let first = dir.path().join("a.json");
        let second = dir.path().join("b.json");
        fs::write(&first, "{}")?;
        fs::write(&second, "{}")?;

        let prev = snapshot_mtimes(&[file_entry(&first)], None);
        let (changed, current) =
            snapshot_changed(&prev, &[file_entry(&first), file_entry(&second)], None);

        assert!(changed);
        assert_eq!(current.len(), 2);
        assert!(current.contains_key(&second));
        Ok(())
    }

    #[test]
    fn snapshot_changed_detects_removed_import_file() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let config = dir.path().join("config.json");
        let import = dir.path().join("import.json");
        fs::write(&config, "{}")?;
        fs::write(&import, "{}")?;

        let mut prev = HashMap::new();
        prev.insert(config.clone(), SystemTime::UNIX_EPOCH);
        prev.insert(import.clone(), SystemTime::UNIX_EPOCH);
        fs::remove_file(&import)?;

        let (changed, current) =
            snapshot_changed(&prev, &[file_entry(&config)], Some(import.as_path()));

        assert!(changed);
        assert_eq!(current.len(), 1);
        assert!(!current.contains_key(&import));
        Ok(())
    }

    #[test]
    fn wp30ao_pin_watch_owner_moved_out_of_run_engine_rs() {
        let source = include_str!("watch.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("fn snapshot_changed("));
        assert!(source.contains("async fn wait_for_signal()"));
        assert!(!run_engine.contains("fn snapshot_changed("));
        assert!(!run_engine.contains("async fn wait_for_signal()"));
    }
}
