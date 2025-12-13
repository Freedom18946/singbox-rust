//! CLI commands for rule set hot reloading management

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
// Signal handling is platform-specific, use a simple approach
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::router::{HotReloadConfig, HotReloadManager, RouterHandle};

/// Hot reload CLI configuration
#[derive(Debug, Clone)]
pub struct HotReloadCliConfig {
    /// Rule set file paths to monitor
    pub rule_files: Vec<PathBuf>,
    /// Check interval in seconds
    pub check_interval_secs: u64,
    /// Maximum rules per rule set
    pub max_rules: usize,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for HotReloadCliConfig {
    fn default() -> Self {
        Self {
            rule_files: Vec::new(),
            check_interval_secs: 5,
            max_rules: 10000,
            verbose: false,
        }
    }
}

/// Start hot reload monitoring from CLI
pub async fn start_hot_reload_cli(
    config: HotReloadCliConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.rule_files.is_empty() {
        return Err("No rule files specified for monitoring".into());
    }

    info!("Starting rule set hot reload monitoring");
    info!("Monitoring {} rule files", config.rule_files.len());

    if config.verbose {
        for file in &config.rule_files {
            info!("  - {}", file.display());
        }
    }

    // Create hot reload configuration
    let hot_reload_config = HotReloadConfig {
        enabled: true,
        check_interval: Duration::from_secs(config.check_interval_secs),
        rule_set_paths: config.rule_files.clone(),
        max_rules: config.max_rules,
        ..Default::default()
    };

    // Create router handle from environment
    let router_handle = Arc::new(RouterHandle::from_env());

    // Create and start hot reload manager
    let mut manager = HotReloadManager::new(hot_reload_config, router_handle);

    if let Err(e) = manager.start().await {
        error!("Failed to start hot reload manager: {}", e);
        return Err(e.into());
    }

    info!("Hot reload manager started successfully");

    // Monitor events if verbose mode is enabled
    if config.verbose {
        let mut event_rx = manager.event_receiver();
        tokio::spawn(async move {
            loop {
                let event = match event_rx.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                };
                match event {
                    crate::router::HotReloadEvent::FileChanged { path } => {
                        info!("Rule file changed: {}", path.display());
                    }
                    crate::router::HotReloadEvent::ValidationSucceeded { path, .. } => {
                        info!("Rule validation succeeded: {}", path.display());
                    }
                    crate::router::HotReloadEvent::ValidationFailed { path, error } => {
                        warn!("Rule validation failed for {}: {}", path.display(), error);
                    }
                    crate::router::HotReloadEvent::Applied { path, generation } => {
                        info!(
                            "Rule set applied: {} (generation: {})",
                            path.display(),
                            generation
                        );
                    }
                    crate::router::HotReloadEvent::RolledBack { path, reason } => {
                        warn!("Rule set rolled back for {}: {}", path.display(), reason);
                    }
                }
            }
        });
    }

    // Wait for shutdown signal (simplified for demo)
    info!("Hot reload monitoring active. Running for 60 seconds...");

    // In a real implementation, you would use proper signal handling
    // For now, just run for a fixed duration
    sleep(std::time::Duration::from_secs(60)).await;

    // Stop hot reload manager
    manager.stop().await;
    info!("Hot reload monitoring stopped");

    Ok(())
}

/// Validate rule set files
pub async fn validate_rule_files(
    rule_files: &[PathBuf],
    max_rules: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Validating {} rule files", rule_files.len());

    let mut all_valid = true;

    for file in rule_files {
        info!("Validating: {}", file.display());

        match tokio::fs::read_to_string(file).await {
            Ok(content) => match HotReloadManager::validate_rule_set(&content, max_rules).await {
                Ok(index) => {
                    info!(
                        "  ✓ Valid ({} rules)",
                        index.exact.len()
                            + index.suffix.len()
                            + index.cidr4.len()
                            + index.cidr6.len()
                    );
                }
                Err(e) => {
                    error!("  ✗ Invalid: {}", e);
                    all_valid = false;
                }
            },
            Err(e) => {
                error!("  ✗ Cannot read file: {}", e);
                all_valid = false;
            }
        }
    }

    if all_valid {
        info!("All rule files are valid");
        Ok(())
    } else {
        Err("Some rule files are invalid".into())
    }
}

/// Show rule set statistics
pub async fn show_rule_stats(rule_files: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    info!("Rule set statistics:");

    for file in rule_files {
        info!("\nFile: {}", file.display());

        match tokio::fs::read_to_string(file).await {
            Ok(content) => match HotReloadManager::validate_rule_set(&content, usize::MAX).await {
                Ok(index) => {
                    info!("  Exact rules: {}", index.exact.len());
                    info!("  Suffix rules: {}", index.suffix.len());
                    info!("  Port rules: {}", index.port_rules.len());
                    info!("  Port ranges: {}", index.port_ranges.len());
                    info!("  IPv4 CIDR rules: {}", index.cidr4.len());
                    info!("  IPv6 CIDR rules: {}", index.cidr6.len());
                    info!("  GeoIP rules: {}", index.geoip_rules.len());
                    info!("  GeoSite rules: {}", index.geosite_rules.len());
                    info!("  Default: {}", index.default);
                    info!("  Generation: {}", index.gen);

                    let total_rules = index.exact.len()
                        + index.suffix.len()
                        + index.port_rules.len()
                        + index.port_ranges.len()
                        + index.cidr4.len()
                        + index.cidr6.len()
                        + index.geoip_rules.len()
                        + index.geosite_rules.len();
                    info!("  Total rules: {}", total_rules);
                }
                Err(e) => {
                    error!("  Error parsing rules: {}", e);
                }
            },
            Err(e) => {
                error!("  Cannot read file: {}", e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_validate_rule_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create valid rule file
        let valid_file = temp_dir.path().join("valid.txt");
        fs::write(&valid_file, "exact:example.com=direct\ndefault=proxy")
            .await
            .unwrap();

        // Create invalid rule file
        let invalid_file = temp_dir.path().join("invalid.txt");
        fs::write(&invalid_file, "invalid syntax here")
            .await
            .unwrap();

        // Test validation of valid file
        let result = validate_rule_files(&[valid_file], 1000).await;
        assert!(result.is_ok());

        // Test validation of invalid file
        let result = validate_rule_files(&[invalid_file], 1000).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_show_rule_stats() {
        let temp_dir = TempDir::new().unwrap();
        let rule_file = temp_dir.path().join("rules.txt");

        let rules = "exact:example.com=direct\nsuffix:google.com=proxy\ncidr4:192.168.1.0/24=direct\ndefault=proxy";
        fs::write(&rule_file, rules).await.unwrap();

        // Should not panic and should complete successfully
        let result = show_rule_stats(&[rule_file]).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_hot_reload_cli_config_default() {
        let config = HotReloadCliConfig::default();
        assert!(config.rule_files.is_empty());
        assert_eq!(config.check_interval_secs, 5);
        assert_eq!(config.max_rules, 10000);
        assert!(!config.verbose);
    }
}
