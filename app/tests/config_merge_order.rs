use anyhow::Result;
use serde_json::json;
use std::fs;
use tempfile::tempdir;

#[test]
fn config_merge_order_sorts_paths() -> Result<()> {
    let temp = tempdir()?;
    let dir = temp.path().join("configs");
    fs::create_dir_all(&dir)?;

    let z_path = temp.path().join("z.json");
    let a_path = dir.join("a.json");

    fs::write(
        &z_path,
        serde_json::to_vec(&json!({
            "log": {"level": "error"}
        }))?,
    )?;
    fs::write(
        &a_path,
        serde_json::to_vec(&json!({
            "log": {"level": "info"}
        }))?,
    )?;

    let entries = app::config_loader::collect_config_entries(&[z_path], &[dir])?;
    let merged = app::config_loader::load_merged_value(&entries)?;

    let level = merged
        .pointer("/log/level")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    assert_eq!(level, "error");
    Ok(())
}
