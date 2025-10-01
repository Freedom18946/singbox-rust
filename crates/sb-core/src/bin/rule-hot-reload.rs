use anyhow::{Context, Result};
use clap::{ArgAction, Command};
use std::path::PathBuf;
use tokio::fs;
use tracing::warn;
use tracing_subscriber::fmt;

use sb_core::routing::router::{Router, RouterConfig};

#[tokio::main]
async fn main() -> Result<()> {
    fmt::init();

    let matches = Command::new("rule-hot-reload")
        .about("Hot reload rules for singbox-rust router")
        .arg(
            clap::Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .action(ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("rules-dir")
                .short('r')
                .long("rules-dir")
                .value_name("DIR")
                .help("Directory to watch for rule changes")
                .num_args(1..)
                .action(ArgAction::Append),
        )
        .arg(
            clap::Arg::new("interval")
                .short('i')
                .long("interval")
                .value_name("SECONDS")
                .help("Reload interval in seconds")
                .default_value("5"),
        )
        .get_matches();

    let config_path = if let Some(c) = matches.get_one::<String>("config") {
        PathBuf::from(c)
    } else {
        PathBuf::from("config.json")
    };

    let rules_dirs: Vec<_> = matches
        .get_many::<String>("rules-dir")
        .unwrap_or_default()
        .map(PathBuf::from)
        .collect();

    let interval = matches
        .get_one::<String>("interval")
        .unwrap()
        .parse::<u64>()
        .context("Invalid interval")?;

    let mut router = Router::new(RouterConfig).context("Failed to init router")?;

    reload_rules(&mut router, &config_path, &rules_dirs).await?;

    let mut interval_timer = tokio::time::interval(tokio::time::Duration::from_secs(interval));
    loop {
        interval_timer.tick().await;
        if let Err(e) = reload_rules(&mut router, &config_path, &rules_dirs).await {
            warn!("Interval reload failed: {}", e);
        }
    }
}

async fn reload_rules(
    router: &mut Router,
    config_path: &PathBuf,
    rules_dirs: &[PathBuf],
) -> Result<()> {
    let config = fs::read_to_string(config_path)
        .await
        .context("Read config failed")?;
    let mut new_config: serde_json::Value =
        serde_json::from_str(&config).context("Parse config failed")?;

    for dir in rules_dirs {
        if let Ok(mut read_dir) = fs::read_dir(dir).await {
            while let Ok(Some(entry)) = read_dir.next_entry().await {
                let entry_path = entry.path();
                if let Some(file_name) = entry.file_name().to_str() {
                    if file_name.ends_with(".json") {
                        if let Ok(rule_data) = fs::read_to_string(&entry_path).await {
                            if let Ok(rules) = serde_json::from_str::<serde_json::Value>(&rule_data)
                            {
                                if let Some(rules_array) = rules.as_array() {
                                    new_config["rules"] =
                                        serde_json::Value::Array(rules_array.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    router
        .reload(&new_config)
        .await
        .context("Router reload failed")?; // 修复：添加 .await
    println!("Rules reloaded successfully");
    Ok(())
}
