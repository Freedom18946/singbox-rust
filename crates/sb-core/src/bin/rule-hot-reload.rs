use anyhow::{Context, Result};
use clap::{ArgAction, Command};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::warn;
use tracing_subscriber::fmt;

use sb_core::router::{builder::build_index_from_ir, RouterHandle, RouterIndex};

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
                .action(ArgAction::Set),
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

    let initial_index = load_rules_index(&config_path, &rules_dirs).await?;
    let router = RouterHandle::from_index(initial_index);
    println!("Rules loaded successfully");

    let mut interval_timer = tokio::time::interval(tokio::time::Duration::from_secs(interval));
    loop {
        interval_timer.tick().await;
        if let Err(e) = reload_rules(&router, &config_path, &rules_dirs).await {
            warn!("Interval reload failed: {}", e);
        }
    }
}

async fn reload_rules(
    router: &RouterHandle,
    config_path: &PathBuf,
    rules_dirs: &[PathBuf],
) -> Result<()> {
    let index = load_rules_index(config_path, rules_dirs).await?;
    router
        .replace_index(index)
        .await
        .map_err(anyhow::Error::msg)
        .context("Router reload failed")?;
    println!("Rules reloaded successfully");
    Ok(())
}

async fn load_rules_index(
    config_path: &PathBuf,
    rules_dirs: &[PathBuf],
) -> Result<Arc<RouterIndex>> {
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
                                    new_config["route"]["rules"] =
                                        serde_json::Value::Array(rules_array.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let (_, ir) = sb_config::config_from_raw_value(new_config)
        .context("Convert config through canonical pipeline failed")?;
    build_index_from_ir(&ir).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn external_rules_build_canonical_router_index() {
        let temp = tempfile::tempdir().expect("create temp directory");
        let config_path = temp.path().join("config.json");
        let rules_dir = temp.path().join("rules");
        std::fs::create_dir(&rules_dir).expect("create rules directory");
        std::fs::write(
            &config_path,
            r#"{
                "outbounds": [
                    {"type": "direct", "tag": "direct"},
                    {"type": "direct", "tag": "proxy"}
                ],
                "route": {"rules": [], "final": "direct"}
            }"#,
        )
        .expect("write config");
        std::fs::write(
            rules_dir.join("domains.json"),
            r#"[{"domain_suffix": ["example.com"], "outbound": "proxy"}]"#,
        )
        .expect("write external rules");

        let index = load_rules_index(&config_path, &[rules_dir])
            .await
            .expect("build router index");

        assert_eq!(index.default, "direct");
        let handle = RouterHandle::from_index(index);
        let decision = handle.decide_with_meta(&sb_core::router::RouteCtx {
            host: Some("api.example.com"),
            ..Default::default()
        });
        assert_eq!(decision.rule.as_deref(), Some("rule#0"));
        assert!(matches!(
            decision.decision,
            sb_core::router::rules::Decision::Proxy(Some(ref tag)) if tag == "proxy"
        ));
    }
}
