//! Config loading and hot-reload functionality
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module manages the **Configuration Lifecycle** and **Dynamic Updates**.
//! 本模块管理 **配置生命周期** 和 **动态更新**。
//!
//! ## Key Concepts / 核心概念
//! - **Loading / 加载**: Reads configuration from file or arguments.
//! - **Validation / 验证**: Ensures the configuration is semantically correct before applying.
//! - **Hot Reload / 热重载**: Watches the configuration file for changes and applies updates transactionally without restarting the process.
//!   监视配置文件的更改，并在不重启进程的情况下事务性地应用更新。
//!
//! ## Hot Reload Strategy / 热重载策略
//! The hot reload mechanism uses a "Watcher" loop:
//! 1. **Watch**: Monitor file system events for the config file.
//! 2. **Debounce**: Wait for a short period to ensure the write is complete.
//! 3. **Reload**: Load the new config -> Validate -> Build IR -> Update Router/Registry.
//!    If any step fails, the update is aborted, and the old configuration remains active (Safe Fallback).
//!    如果任何步骤失败，更新将被中止，旧配置保持活动状态（安全回退）。

#![allow(clippy::missing_errors_doc, clippy::cognitive_complexity)]

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum ConfigSource {
    File(PathBuf),
    Stdin,
}

#[derive(Debug, Clone)]
pub struct ConfigEntry {
    pub path: String,
    pub source: ConfigSource,
}

pub fn collect_config_entries(
    config_paths: &[PathBuf],
    config_dirs: &[PathBuf],
) -> Result<Vec<ConfigEntry>> {
    let mut entries = Vec::new();

    if config_paths.is_empty() && config_dirs.is_empty() {
        entries.push(ConfigEntry {
            path: "config.json".to_string(),
            source: ConfigSource::File(PathBuf::from("config.json")),
        });
        return Ok(entries);
    }

    for path in config_paths {
        if is_stdin_path(path) {
            entries.push(ConfigEntry {
                path: "stdin".to_string(),
                source: ConfigSource::Stdin,
            });
            continue;
        }
        entries.push(ConfigEntry {
            path: path.to_string_lossy().to_string(),
            source: ConfigSource::File(path.clone()),
        });
    }

    for dir in config_dirs {
        let entries_iter = fs::read_dir(dir)
            .with_context(|| format!("read config directory {}", dir.display()))?;
        for entry in entries_iter {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            entries.push(ConfigEntry {
                path: path.to_string_lossy().to_string(),
                source: ConfigSource::File(path),
            });
        }
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

pub fn load_merged_value(entries: &[ConfigEntry]) -> Result<Value> {
    if entries.is_empty() {
        return Ok(Value::Null);
    }

    let mut stdin_cache = None::<Vec<u8>>;
    let mut merged = Value::Null;
    for entry in entries {
        let data = read_config_bytes(entry, &mut stdin_cache)?;
        let raw = parse_config_value(&data, &entry.path)?;
        merged = merge_values(merged, raw);
    }
    Ok(merged)
}

pub fn load_config(entries: &[ConfigEntry]) -> Result<sb_config::Config> {
    let raw = load_merged_value(entries)?;
    let migrated = sb_config::compat::migrate_to_v2(&raw);
    let cfg = sb_config::Config::from_value(migrated)?;
    cfg.validate()?;
    Ok(cfg)
}

#[allow(dead_code)]
#[must_use]
pub fn entry_files(entries: &[ConfigEntry]) -> Vec<PathBuf> {
    entries
        .iter()
        .filter_map(|entry| match &entry.source {
            ConfigSource::File(path) => Some(path.clone()),
            ConfigSource::Stdin => None,
        })
        .collect()
}

#[cfg(feature = "dev-cli")]
#[allow(dead_code)]
pub fn check_only(config_paths: &[PathBuf], config_dirs: &[PathBuf]) -> Result<(usize, usize, usize)> {
    let entries = collect_config_entries(config_paths, config_dirs)?;
    let cfg = load_config(&entries)?;
    cfg.build_registry_and_router()?; // Stub validation
    Ok(cfg.stats())
}

fn read_config_bytes(entry: &ConfigEntry, stdin_cache: &mut Option<Vec<u8>>) -> Result<Vec<u8>> {
    match &entry.source {
        ConfigSource::File(path) => fs::read(path)
            .with_context(|| format!("read config at {}", entry.path)),
        ConfigSource::Stdin => {
            if let Some(cached) = stdin_cache.as_ref() {
                return Ok(cached.clone());
            }
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read config from stdin")?;
            *stdin_cache = Some(buf.clone());
            Ok(buf)
        }
    }
}

fn parse_config_value(data: &[u8], path: &str) -> Result<Value> {
    match serde_json::from_slice(data) {
        Ok(v) => Ok(v),
        Err(json_err) => serde_yaml::from_slice(data)
            .with_context(|| format!("parse config {path} (json error: {json_err})")),
    }
}

fn merge_values(base: Value, next: Value) -> Value {
    use serde_json::Value as V;
    match (base, next) {
        (V::Object(mut a), V::Object(b)) => {
            for (k, vb) in b {
                if let Some(va) = a.remove(&k) {
                    a.insert(k, merge_values(va, vb));
                } else {
                    a.insert(k, vb);
                }
            }
            V::Object(a)
        }
        (V::Array(mut a), V::Array(b)) => {
            a.extend(b);
            V::Array(a)
        }
        (V::Null, x) => x,
        (_a, b) => b,
    }
}

fn is_stdin_path(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some("stdin" | "-")
    )
}
