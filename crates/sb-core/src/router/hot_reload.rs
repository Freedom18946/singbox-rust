//! Rule set hot reloading functionality
//!
//! This module provides hot reloading capabilities for router rule sets,
//! allowing dynamic updates without service interruption.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

#[cfg(feature = "geoip_hot")]
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use super::{router_build_index_from_str, BuildError};
use crate::router::{RouterHandle, RouterIndex};

/// Hot reload configuration
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Enable hot reloading
    pub enabled: bool,
    /// Check interval for file changes (when notify is not available)
    pub check_interval: Duration,
    /// Validation timeout for new rule sets
    pub validation_timeout: Duration,
    /// Maximum number of rollback attempts
    pub max_rollback_attempts: usize,
    /// Rule set file paths to monitor
    pub rule_set_paths: Vec<PathBuf>,
    /// Maximum rules per rule set
    pub max_rules: usize,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            check_interval: Duration::from_secs(5),
            validation_timeout: Duration::from_secs(10),
            max_rollback_attempts: 3,
            rule_set_paths: Vec::new(),
            max_rules: 10000,
        }
    }
}

/// Hot reload event types
#[derive(Debug, Clone)]
pub enum HotReloadEvent {
    /// Rule set file changed
    FileChanged { path: PathBuf },
    /// Rule set validation succeeded
    ValidationSucceeded { path: PathBuf, checksum: [u8; 32] },
    /// Rule set validation failed
    ValidationFailed { path: PathBuf, error: String },
    /// Rule set applied successfully
    Applied { path: PathBuf, generation: u64 },
    /// Rollback performed
    RolledBack { path: PathBuf, reason: String },
}

/// File metadata for change detection
#[derive(Debug, Clone)]
struct FileMetadata {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
    checksum: Option<[u8; 32]>,
}

/// Hot reload manager
pub struct HotReloadManager {
    config: HotReloadConfig,
    router_handle: Arc<RouterHandle>,
    event_tx: mpsc::UnboundedSender<HotReloadEvent>,
    event_rx: Arc<RwLock<mpsc::UnboundedReceiver<HotReloadEvent>>>,
    file_metadata: Arc<RwLock<HashMap<PathBuf, FileMetadata>>>,
    #[cfg(feature = "geoip_hot")]
    _watcher: Option<RecommendedWatcher>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl HotReloadManager {
    /// Create a new hot reload manager
    pub fn new(config: HotReloadConfig, router_handle: Arc<RouterHandle>) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Self {
            config,
            router_handle,
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
            file_metadata: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "geoip_hot")]
            _watcher: None,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start hot reloading
    pub async fn start(&mut self) -> Result<(), HotReloadError> {
        if !self.config.enabled {
            debug!("Hot reload is disabled");
            return Ok(());
        }

        info!("Starting rule set hot reload manager");

        // Initialize file metadata
        self.initialize_file_metadata().await?;

        // Start file system watcher if available
        #[cfg(feature = "geoip_hot")]
        {
            if let Err(e) = self.start_file_watcher().await {
                warn!(
                    "Failed to start file watcher, falling back to polling: {}",
                    e
                );
            }
        }

        // Start polling monitor as fallback
        self.start_polling_monitor().await;

        // Start event processor
        self.start_event_processor().await;

        Ok(())
    }

    /// Stop hot reloading
    pub async fn stop(&self) {
        info!("Stopping rule set hot reload manager");
        let _ = self.shutdown_tx.send(true);
    }

    /// Initialize file metadata for all monitored files
    async fn initialize_file_metadata(&self) -> Result<(), HotReloadError> {
        let mut metadata = self.file_metadata.write().await;

        for path in &self.config.rule_set_paths {
            match self.get_file_metadata(path).await {
                Ok(meta) => {
                    metadata.insert(path.clone(), meta);
                    debug!("Initialized metadata for: {}", path.display());
                }
                Err(e) => {
                    warn!("Failed to get metadata for {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Get file metadata
    async fn get_file_metadata(&self, path: &Path) -> Result<FileMetadata, HotReloadError> {
        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            HotReloadError::FileAccess(format!(
                "Failed to read metadata for {}: {}",
                path.display(),
                e
            ))
        })?;

        let modified = metadata.modified().map_err(|e| {
            HotReloadError::FileAccess(format!(
                "Failed to get modified time for {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(FileMetadata {
            path: path.to_path_buf(),
            modified,
            size: metadata.len(),
            checksum: None,
        })
    }

    /// Start file system watcher
    #[cfg(feature = "geoip_hot")]
    async fn start_file_watcher(&mut self) -> Result<(), HotReloadError> {
        let event_tx = self.event_tx.clone();
        let rule_set_paths = self.config.rule_set_paths.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if let EventKind::Modify(_) = event.kind {
                        for path in event.paths {
                            if rule_set_paths.contains(&path) {
                                let _ = event_tx.send(HotReloadEvent::FileChanged { path });
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("File watcher error: {}", e);
                }
            },
            notify::Config::default(),
        )
        .map_err(|e| HotReloadError::WatcherSetup(format!("Failed to create watcher: {}", e)))?;

        // Watch directories containing rule set files
        let mut watched_dirs = std::collections::HashSet::new();
        for path in &self.config.rule_set_paths {
            if let Some(parent) = path.parent() {
                if watched_dirs.insert(parent.to_path_buf()) {
                    watcher
                        .watch(parent, RecursiveMode::NonRecursive)
                        .map_err(|e| {
                            HotReloadError::WatcherSetup(format!(
                                "Failed to watch {}: {}",
                                parent.display(),
                                e
                            ))
                        })?;
                    debug!("Watching directory: {}", parent.display());
                }
            }
        }

        self._watcher = Some(watcher);
        info!("File system watcher started");
        Ok(())
    }

    /// Start polling monitor as fallback
    async fn start_polling_monitor(&self) {
        let file_metadata = self.file_metadata.clone();
        let event_tx = self.event_tx.clone();
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.check_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let metadata = file_metadata.read().await;
                        for (path, old_meta) in metadata.iter() {
                            match tokio::fs::metadata(path).await {
                                Ok(new_metadata) => {
                                    if let Ok(modified) = new_metadata.modified() {
                                        if modified > old_meta.modified || new_metadata.len() != old_meta.size {
                                            let _ = event_tx.send(HotReloadEvent::FileChanged {
                                                path: path.clone()
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to check file {}: {}", path.display(), e);
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("Polling monitor shutting down");
                            break;
                        }
                    }
                }
            }
        });

        debug!("Polling monitor started");
    }

    /// Start event processor
    async fn start_event_processor(&self) {
        let event_rx = self.event_rx.clone();
        let router_handle = self.router_handle.clone();
        let file_metadata = self.file_metadata.clone();
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let mut rx = event_rx.write().await;

            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(HotReloadEvent::FileChanged { path }) => {
                                Self::handle_file_changed(&path, &router_handle, &file_metadata, &config).await;
                            }
                            Some(event) => {
                                debug!("Hot reload event: {:?}", event);
                            }
                            None => {
                                debug!("Event channel closed");
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("Event processor shutting down");
                            break;
                        }
                    }
                }
            }
        });

        debug!("Event processor started");
    }

    /// Handle file changed event
    async fn handle_file_changed(
        path: &Path,
        router_handle: &Arc<RouterHandle>,
        file_metadata: &Arc<RwLock<HashMap<PathBuf, FileMetadata>>>,
        config: &HotReloadConfig,
    ) {
        info!("Rule set file changed: {}", path.display());

        // Check if file actually changed by comparing metadata
        let new_meta = match Self::get_file_metadata_static(path).await {
            Ok(meta) => meta,
            Err(e) => {
                error!("Failed to get metadata for {}: {}", path.display(), e);
                return;
            }
        };

        // Check if file actually changed
        {
            let metadata = file_metadata.read().await;
            if let Some(old_meta) = metadata.get(path) {
                if old_meta.modified == new_meta.modified && old_meta.size == new_meta.size {
                    debug!(
                        "File {} metadata unchanged, skipping reload",
                        path.display()
                    );
                    return;
                }
            }
        }

        // Read and validate new rule set
        let content = match tokio::fs::read_to_string(path).await {
            Ok(content) => content,
            Err(e) => {
                error!("Failed to read rule set file {}: {}", path.display(), e);
                return;
            }
        };

        // Validate new rule set
        match Self::validate_rule_set(&content, config.max_rules).await {
            Ok(new_index) => {
                info!("Rule set validation succeeded for: {}", path.display());

                // Apply new rule set
                if let Err(e) = Self::apply_rule_set(router_handle, new_index).await {
                    error!("Failed to apply rule set from {}: {}", path.display(), e);
                    return;
                }

                // Update metadata
                let mut metadata = file_metadata.write().await;
                metadata.insert(path.to_path_buf(), new_meta);

                info!("Rule set hot reload completed for: {}", path.display());
            }
            Err(e) => {
                error!("Rule set validation failed for {}: {}", path.display(), e);
            }
        }
    }

    /// Get file metadata (static version)
    async fn get_file_metadata_static(path: &Path) -> Result<FileMetadata, HotReloadError> {
        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            HotReloadError::FileAccess(format!(
                "Failed to read metadata for {}: {}",
                path.display(),
                e
            ))
        })?;

        let modified = metadata.modified().map_err(|e| {
            HotReloadError::FileAccess(format!(
                "Failed to get modified time for {}: {}",
                path.display(),
                e
            ))
        })?;

        Ok(FileMetadata {
            path: path.to_path_buf(),
            modified,
            size: metadata.len(),
            checksum: None,
        })
    }

    /// Validate rule set content
    pub async fn validate_rule_set(
        content: &str,
        max_rules: usize,
    ) -> Result<Arc<RouterIndex>, HotReloadError> {
        // Use existing router build function to validate
        router_build_index_from_str(content, max_rules)
            .map_err(|e| HotReloadError::Validation(format!("Rule set validation failed: {}", e)))
    }

    /// Apply new rule set to router
    async fn apply_rule_set(
        router_handle: &Arc<RouterHandle>,
        new_index: Arc<RouterIndex>,
    ) -> Result<(), HotReloadError> {
        // Get current generation for rollback
        let current_gen = router_handle.current_generation().await;

        // Apply new index
        router_handle
            .replace_index(new_index)
            .await
            .map_err(|e| HotReloadError::Application(format!("Failed to apply rule set: {}", e)))?;

        // Verify the new index is working
        tokio::time::sleep(Duration::from_millis(100)).await;

        let new_gen = router_handle.current_generation().await;
        if new_gen <= current_gen {
            return Err(HotReloadError::Application(
                "Rule set generation did not increase".to_string(),
            ));
        }

        Ok(())
    }

    /// Get event receiver for monitoring
    pub fn event_receiver(&self) -> Arc<RwLock<mpsc::UnboundedReceiver<HotReloadEvent>>> {
        self.event_rx.clone()
    }
}

/// Hot reload error types
#[derive(Debug, thiserror::Error)]
pub enum HotReloadError {
    #[error("File access error: {0}")]
    FileAccess(String),

    #[error("Watcher setup error: {0}")]
    WatcherSetup(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Application error: {0}")]
    Application(String),

    #[error("Rollback error: {0}")]
    Rollback(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_hot_reload_config() {
        let config = HotReloadConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.check_interval, Duration::from_secs(5));
        assert_eq!(config.max_rules, 10000);
    }

    #[tokio::test]
    async fn test_file_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_rules.txt");

        fs::write(&file_path, "exact:example.com=direct\ndefault=proxy")
            .await
            .unwrap();

        let manager = create_test_manager(&file_path).await;
        let metadata = manager.get_file_metadata(&file_path).await.unwrap();

        assert_eq!(metadata.path, file_path);
        assert!(metadata.size > 0);
    }

    #[tokio::test]
    async fn test_rule_set_validation() {
        let valid_content = "exact:example.com=direct\nsuffix:google.com=proxy\ndefault=direct";
        let result = HotReloadManager::validate_rule_set(valid_content, 1000).await;
        assert!(result.is_ok());

        let invalid_content = "invalid_syntax_here";
        let result = HotReloadManager::validate_rule_set(invalid_content, 1000).await;
        assert!(result.is_err());
    }

    async fn create_test_manager(rule_path: &Path) -> HotReloadManager {
        let config = HotReloadConfig {
            enabled: true,
            rule_set_paths: vec![rule_path.to_path_buf()],
            ..Default::default()
        };

        // Create a mock router handle
        let router_handle = Arc::new(RouterHandle::new_mock());

        HotReloadManager::new(config, router_handle)
    }
}
