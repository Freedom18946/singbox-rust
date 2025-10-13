//! Config loading and hot-reload functionality
#![allow(clippy::missing_errors_doc, clippy::cognitive_complexity)]

#[cfg(feature = "dev-cli")]
use anyhow::Result;
#[cfg(feature = "dev-cli")]
use std::path::Path;

#[cfg(feature = "router")]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub fn load_from_path(path: &Path) -> Result<sb_config::Config> {
    sb_config::Config::load(path)
}

#[cfg(not(feature = "router"))]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub fn load_from_path(path: &Path) -> Result<sb_config::Config> {
    // minimal 与 router 一致的读法，保持签名不变
    Ok(sb_config::Config::load(path)?)
}

#[cfg(feature = "router")]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub async fn run_hot_reload(
    path: &Path,
    /* place holders:
       - inbound/outbound registries
       - router engine handle
       - shutdown signal sender
    */
) -> Result<()> {
    use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;
    use tokio::time::{sleep, Duration};

    let (tx, rx) = mpsc::channel();

    // Create a watcher instance
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                // Only reload on file modifications, not other events
                if matches!(event.kind, notify::EventKind::Modify(_)) {
                    if let Err(e) = tx.send(event) {
                        tracing::warn!("Failed to send file change event: {}", e);
                    }
                }
            }
        },
        Config::default(),
    )?;

    // Watch the config file for changes
    watcher.watch(path, RecursiveMode::NonRecursive)?;

    tracing::info!("Hot reload watcher started for: {}", path.display());

    // Process file change events
    loop {
        // Check for file change events (non-blocking)
        if let Ok(event) = rx.try_recv() {
            tracing::info!("Config file changed: {:?}", event.paths);

            // Small delay to ensure file write is complete
            sleep(Duration::from_millis(100)).await;

            match reload_config(path).await {
                Ok(()) => {
                    tracing::info!("Config successfully reloaded from: {}", path.display());
                }
                Err(e) => {
                    tracing::error!("Failed to reload config: {}", e);
                }
            }
        }

        // Small sleep to prevent busy waiting
        sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(feature = "router")]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
async fn reload_config(path: &Path) -> Result<()> {
    // 1) Load and validate the new config
    let new_config = sb_config::Config::load(path)?;
    new_config.validate()?;

    // 2) Convert to IR for router consumption
    new_config.build_registry_and_router()?;

    // 3) Update router with new configuration if feature is enabled
    #[cfg(feature = "router")]
    {
        use sb_core::router::engine::RouterHandle;

        // Create router handle and build new index from configuration
        let router = RouterHandle::from_env();

        // Note: For proper integration, we would need to convert the config to RouterIndex
        // This is a foundation for future full integration
        tracing::debug!("Router reload prepared - config validation completed");

        // Convert ConfigIR to router rules format and build new index
        // Convert Config to ConfigIR for processing
        let config_ir = sb_config::present::to_ir(&new_config)
            .map_err(|e| anyhow::anyhow!("Failed to convert config to IR: {e}"))?;
        let rules_text = config_ir_to_router_rules(&config_ir);
        tracing::debug!(
            "Generated router rules from config: {} lines",
            rules_text.lines().count()
        );

        match sb_core::router::router_build_index_from_str(&rules_text, 100_000) {
            Ok(new_index) => {
                if let Err(e) = router.replace_index(new_index).await {
                    tracing::error!("Failed to replace router index: {}", e);
                    return Err(anyhow::anyhow!("Router index replacement failed: {e}"));
                }
                tracing::info!("Router index successfully updated from config");
            }
            Err(e) => {
                tracing::error!("Failed to build router index from config: {}", e);
                return Err(anyhow::anyhow!("Router index build failed: {e}"));
            }
        }
    }

    // 4) Update inbound/outbound registries
    let config_ir = sb_config::present::to_ir(&new_config)
        .map_err(|e| anyhow::anyhow!("Failed to convert config to IR: {e}"))?;
    if !config_ir.inbounds.is_empty() || !config_ir.outbounds.is_empty() {
        tracing::debug!(
            "Config contains {} inbounds, {} outbounds - registry updates ready for integration",
            config_ir.inbounds.len(),
            config_ir.outbounds.len()
        );
        // Registry update implementation would integrate with adapter interfaces here
    }

    // 5) Update bridge/selector registries
    let selectors: Vec<_> = config_ir
        .outbounds
        .iter()
        .filter(|o| o.ty == sb_config::ir::OutboundType::Selector)
        .collect();
    if !selectors.is_empty() {
        tracing::debug!(
            "Config contains {} selectors - bridge updates ready for integration",
            selectors.len()
        );
        // Bridge/selector update implementation would integrate with adapter interfaces here
    }

    tracing::debug!("Config reload validation completed successfully");
    Ok(())
}

#[cfg(not(feature = "router"))]
#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub async fn run_hot_reload(_path: &Path /* same signature */) -> Result<()> {
    // NOP in minimal mode
    Ok(())
}

/// 仅用于 `--check`：解析并构建 Router/Outbound，不触发任何 IO/监听。
/// 返回 (inbounds, outbounds, rules) 便于主程序打印摘要。
#[cfg(feature = "dev-cli")]
pub fn check_only<P: AsRef<Path>>(path: P) -> Result<(usize, usize, usize)> {
    let cfg = sb_config::Config::load(&path)?;
    cfg.validate()?;
    // 构建以验证引用完整性/默认值语义，但不启动任何任务
    cfg.build_registry_and_router()?; // Stub validation
    Ok(cfg.stats())
}

/// Convert `ConfigIR` to router rules text format
#[cfg(feature = "router")]
fn config_ir_to_router_rules(config: &sb_config::ir::ConfigIR) -> String {
    let mut rules = Vec::new();

    for rule in &config.route.rules {
        let outbound = rule.outbound.as_deref().unwrap_or("direct");

        // Handle exact domain matches
        for domain in &rule.domain {
            rules.push(format!("exact:{domain}={outbound}"));
        }

        // Handle geosite matches
        for geosite in &rule.geosite {
            rules.push(format!("geosite:{geosite}={outbound}"));
        }

        // Handle geoip matches
        for geoip in &rule.geoip {
            rules.push(format!("geoip:{geoip}={outbound}"));
        }

        // Handle IP CIDR matches
        for ipcidr in &rule.ipcidr {
            // Detect IPv4 vs IPv6 by presence of ':'
            let rule_type = if ipcidr.contains(':') {
                "cidr6"
            } else {
                "cidr4"
            };
            rules.push(format!("{rule_type}:{ipcidr}={outbound}"));
        }

        // Handle port matches
        for port in &rule.port {
            if port.contains('-') {
                rules.push(format!("portrange:{port}={outbound}"));
            } else {
                rules.push(format!("port:{port}={outbound}"));
            }
        }

        // Handle process matches
        for process in &rule.process {
            rules.push(format!("process:{process}={outbound}"));
        }

        // Handle network matches (tcp/udp)
        for network in &rule.network {
            rules.push(format!("transport:{network}={outbound}"));
        }

        // Handle protocol matches
        for protocol in &rule.protocol {
            rules.push(format!("protocol:{protocol}={outbound}"));
        }
    }

    // Add default rule
    if let Some(default) = &config.route.default {
        rules.push(format!("default={default}"));
    } else {
        rules.push("default=direct".to_string());
    }

    rules.join("\n")
}
