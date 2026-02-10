use crate::orchestrator::latest_run_dir;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn latest_report_path(artifacts_root: &Path, case_id: &str) -> Result<PathBuf> {
    let run_dir = latest_run_dir(artifacts_root, case_id)?;

    let diff_md = run_dir.join("diff.md");
    if diff_md.exists() {
        return Ok(diff_md);
    }

    let summary = run_dir.join("summary.json");
    if summary.exists() {
        return Ok(summary);
    }

    Err(anyhow::anyhow!(
        "no report file found under {}",
        run_dir.display()
    ))
}

pub async fn read_report(path: &Path) -> Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading report {}", path.display()))
}
