//! Rule set hot reload demonstration
//!
//! This example shows how to use the rule set hot reload functionality.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;
use tokio::time::sleep;
use tracing::{info, warn};

use sb_core::router::{HotReloadConfig, HotReloadEvent, HotReloadManager, RouterHandle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting rule set hot reload demonstration");

    // Create temporary directory for rule files
    let temp_dir = TempDir::new()?;
    let rule_file = temp_dir.path().join("demo_rules.txt");

    // Create initial rule set
    let initial_rules = r#"
# Initial rule set
exact:example.com=direct
suffix:google.com=proxy
cidr4:192.168.1.0/24=direct
port:443=proxy
default=direct
"#;

    fs::write(&rule_file, initial_rules).await?;
    info!("Created initial rule set at: {}", rule_file.display());

    // Create hot reload configuration
    let config = HotReloadConfig {
        enabled: true,
        check_interval: Duration::from_secs(2),
        rule_set_paths: vec![rule_file.clone()],
        max_rules: 1000,
        ..Default::default()
    };

    // Create router handle
    let router_handle = Arc::new(RouterHandle::from_env());

    // Create hot reload manager
    let mut manager = HotReloadManager::new(config, router_handle.clone());

    // Start monitoring events
    let event_rx = manager.event_receiver();
    let event_monitor = {
        let rx = event_rx.clone();
        tokio::spawn(async move {
            let mut rx = rx.write().await;
            while let Some(event) = rx.recv().await {
                match event {
                    HotReloadEvent::FileChanged { path } => {
                        info!("📁 File changed: {}", path.display());
                    }
                    HotReloadEvent::ValidationSucceeded { path, .. } => {
                        info!("✅ Validation succeeded: {}", path.display());
                    }
                    HotReloadEvent::ValidationFailed { path, error } => {
                        warn!("❌ Validation failed for {}: {}", path.display(), error);
                    }
                    HotReloadEvent::Applied { path, generation } => {
                        info!(
                            "🔄 Rule set applied: {} (gen: {})",
                            path.display(),
                            generation
                        );
                    }
                    HotReloadEvent::RolledBack { path, reason } => {
                        warn!("↩️  Rolled back {}: {}", path.display(), reason);
                    }
                }
            }
        })
    };

    // Start hot reload manager
    manager.start().await?;
    info!("Hot reload manager started");

    // Demonstrate routing decisions
    let routing_demo = {
        let router = router_handle.clone();
        tokio::spawn(async move {
            loop {
                let decision1 = router.decide_udp_async("example.com").await;
                let decision2 = router.decide_udp_async("google.com").await;
                let decision3 = router.decide_udp_async("unknown.com").await;

                info!(
                    "Routing decisions: example.com={}, google.com={}, unknown.com={}",
                    decision1, decision2, decision3
                );

                sleep(Duration::from_secs(5)).await;
            }
        })
    };

    // Wait a bit, then update the rule set
    sleep(Duration::from_secs(3)).await;

    info!("Updating rule set...");
    let updated_rules = r#"
# Updated rule set - changed decisions
exact:example.com=proxy
suffix:google.com=direct
cidr4:192.168.1.0/24=proxy
port:443=direct
port:80=proxy
default=proxy
"#;

    fs::write(&rule_file, updated_rules).await?;
    info!("Rule set updated");

    // Wait for hot reload to process
    sleep(Duration::from_secs(5)).await;

    // Update with invalid rules to demonstrate validation
    info!("Testing validation with invalid rules...");
    let invalid_rules = r#"
# Invalid rule set
invalid_syntax_here
this:is:not:valid=error
"#;

    fs::write(&rule_file, invalid_rules).await?;
    info!("Invalid rules written");

    // Wait for validation failure
    sleep(Duration::from_secs(3)).await;

    // Restore valid rules
    info!("Restoring valid rules...");
    let final_rules = r#"
# Final rule set
exact:example.com=direct
exact:test.com=proxy
suffix:github.com=proxy
cidr4:10.0.0.0/8=direct
port:22=direct
port:80=proxy
port:443=proxy
default=direct
"#;

    fs::write(&rule_file, final_rules).await?;
    info!("Valid rules restored");

    // Let it run for a bit more
    sleep(Duration::from_secs(5)).await;

    // Stop the manager
    info!("Stopping hot reload manager...");
    manager.stop().await;

    // Stop background tasks
    event_monitor.abort();
    routing_demo.abort();

    info!("Hot reload demonstration completed");

    Ok(())
}
