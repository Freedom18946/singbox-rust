#![cfg(feature = "dev-cli")]
use crate::cli::{buildinfo, fs_scan, health};
use clap::Parser;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "report",
    about = "Emit structured JSON progress receipt for rust kernel migration"
)]
pub struct Args {
    /// workspace root (default: current directory)
    #[arg(long)]
    pub root: Option<String>,
    /// include admin /__health snapshot if SB_ADMIN_PORTFILE or /tmp/admin.port exists
    #[arg(long)]
    pub with_health: bool,
}

#[derive(Serialize)]
pub struct Receipt<'a> {
    pub ok: bool,
    pub build: crate::cli::buildinfo::BuildInfo,
    pub repo: fs_scan::FsReport,
    pub hints: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<health::HealthReport>,
}

fn fetch_admin_health() -> Option<serde_json::Value> {
    // 轻量方案：用系统 curl 抓取，避免在 report 二进制额外引入 reqwest 依赖
    let url = std::env::var("SB_ADMIN_URL").ok()?;
    let out = std::process::Command::new("curl")
        .arg("-s")
        .arg(format!("{url}/__health"))
        .output()
        .ok()?;
    serde_json::from_slice(&out.stdout).ok()
}

pub fn main(args: Args) -> anyhow::Result<()> {
    let root = args.root.clone().unwrap_or_else(|| ".".to_string());
    let scanner = fs_scan::Scanner::new(&root);
    let repo = scanner.run()?;
    let build = buildinfo::current();
    let mut dyn_hints = vec![
        "P1: unify all 4xx/5xx to respond_json_error(error/hint/code)".to_string(),
        "P2: replace build_single_patch hard-coded match with a registry".to_string(),
        "P3: add E2E for redirect-chain-to-private and size/timeout limits".to_string(),
    ];
    // 把热点文件清单注入 hints，便于你复制到 PR
    if !repo.metrics.error_json.text_plain_files.is_empty() {
        dyn_hints.push(format!(
            "P1-hotspots (text/plain): {:?}",
            repo.metrics
                .error_json
                .text_plain_files
                .iter()
                .map(|o| &o.path)
                .collect::<Vec<_>>()
        ));
    }
    if !repo
        .metrics
        .analyze_dispatch
        .build_single_patch_files
        .is_empty()
    {
        dyn_hints.push(format!(
            "P2-hotspots (build_single_patch): {:?}",
            repo.metrics
                .analyze_dispatch
                .build_single_patch_files
                .iter()
                .map(|o| &o.path)
                .collect::<Vec<_>>()
        ));
    }
    let health = if args.with_health {
        Some(health::probe_from_portfile(
            std::env::var_os("SB_ADMIN_PORTFILE")
                .as_deref()
                .map(|s| s.as_ref()),
            1500,
        ))
    } else {
        None
    };
    let hints_boxed: Vec<&str> = dyn_hints.iter().map(|s| s.as_str()).collect();
    let receipt = Receipt {
        ok: true,
        build,
        repo,
        hints: &hints_boxed,
        health,
    };

    // Convert to serde_json::Value to allow dynamic modification
    let mut payload = serde_json::to_value(&receipt)?;

    if let Some(h) = fetch_admin_health() {
        payload["health"] = serde_json::json!({ "snapshot": h });
    }

    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}
