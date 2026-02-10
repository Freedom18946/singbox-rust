use crate::orchestrator::latest_run_dir;
use crate::snapshot::{HttpResult, NormalizedSnapshot, WsFrameCapture};
use crate::util::sha256_hex;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    pub case_id: String,
    pub run_dir: PathBuf,
    pub compared_at: String,
    pub http_mismatches: Vec<Mismatch>,
    pub ws_mismatches: Vec<Mismatch>,
    pub subscription_mismatches: Vec<Mismatch>,
    pub traffic_mismatches: Vec<Mismatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mismatch {
    pub key: String,
    pub rust_value: serde_json::Value,
    pub go_value: serde_json::Value,
}

impl DiffReport {
    pub fn is_clean(&self) -> bool {
        self.http_mismatches.is_empty()
            && self.ws_mismatches.is_empty()
            && self.subscription_mismatches.is_empty()
            && self.traffic_mismatches.is_empty()
    }
}

pub async fn diff_latest_case(
    artifacts_root: &Path,
    case_id: &str,
) -> Result<(DiffReport, PathBuf)> {
    let run_dir = latest_run_dir(artifacts_root, case_id)?;
    let rust_path = run_dir.join("rust.snapshot.json");
    let go_path = run_dir.join("go.snapshot.json");

    let rust_raw = tokio::fs::read(&rust_path)
        .await
        .with_context(|| format!("reading {}", rust_path.display()))?;
    let go_raw = tokio::fs::read(&go_path)
        .await
        .with_context(|| format!("reading {}", go_path.display()))?;

    let rust_snapshot: NormalizedSnapshot = serde_json::from_slice(&rust_raw)
        .with_context(|| format!("parsing {}", rust_path.display()))?;
    let go_snapshot: NormalizedSnapshot = serde_json::from_slice(&go_raw)
        .with_context(|| format!("parsing {}", go_path.display()))?;

    let report = build_diff_report(case_id, run_dir.clone(), &rust_snapshot, &go_snapshot);

    let diff_json_path = run_dir.join("diff.json");
    let diff_markdown_path = run_dir.join("diff.md");

    let diff_json = serde_json::to_vec_pretty(&report).with_context(|| "serializing diff json")?;
    tokio::fs::write(&diff_json_path, diff_json)
        .await
        .with_context(|| format!("writing {}", diff_json_path.display()))?;

    let markdown = to_markdown(&report);
    tokio::fs::write(&diff_markdown_path, markdown)
        .await
        .with_context(|| format!("writing {}", diff_markdown_path.display()))?;

    Ok((report, diff_markdown_path))
}

fn build_diff_report(
    case_id: &str,
    run_dir: PathBuf,
    rust_snapshot: &NormalizedSnapshot,
    go_snapshot: &NormalizedSnapshot,
) -> DiffReport {
    let http_mismatches = diff_http(&rust_snapshot.http_results, &go_snapshot.http_results);
    let ws_mismatches = diff_ws(&rust_snapshot.ws_frames, &go_snapshot.ws_frames);

    let mut subscription_mismatches = Vec::new();
    if rust_snapshot
        .subscription_result
        .as_ref()
        .map(|v| (v.format.clone(), v.node_count))
        != go_snapshot
            .subscription_result
            .as_ref()
            .map(|v| (v.format.clone(), v.node_count))
    {
        subscription_mismatches.push(Mismatch {
            key: "subscription_result".to_string(),
            rust_value: json!(rust_snapshot.subscription_result),
            go_value: json!(go_snapshot.subscription_result),
        });
    }

    let mut traffic_mismatches = Vec::new();
    let rust_traffic: BTreeMap<String, bool> = rust_snapshot
        .traffic_results
        .iter()
        .map(|item| (item.name.clone(), item.success))
        .collect();
    let go_traffic: BTreeMap<String, bool> = go_snapshot
        .traffic_results
        .iter()
        .map(|item| (item.name.clone(), item.success))
        .collect();

    let keys: std::collections::BTreeSet<_> = rust_traffic
        .keys()
        .chain(go_traffic.keys())
        .cloned()
        .collect();

    for key in keys {
        let left = rust_traffic.get(&key).copied();
        let right = go_traffic.get(&key).copied();
        if left != right {
            traffic_mismatches.push(Mismatch {
                key,
                rust_value: json!(left),
                go_value: json!(right),
            });
        }
    }

    DiffReport {
        case_id: case_id.to_string(),
        run_dir,
        compared_at: Utc::now().to_rfc3339(),
        http_mismatches,
        ws_mismatches,
        subscription_mismatches,
        traffic_mismatches,
    }
}

fn diff_http(rust_http: &[HttpResult], go_http: &[HttpResult]) -> Vec<Mismatch> {
    let mut out = Vec::new();

    let rust_map: BTreeMap<String, (&u16, Option<&String>)> = rust_http
        .iter()
        .map(|item| {
            (
                format!("{} {}", item.method, item.path),
                (&item.status, item.body_hash.as_ref()),
            )
        })
        .collect();
    let go_map: BTreeMap<String, (&u16, Option<&String>)> = go_http
        .iter()
        .map(|item| {
            (
                format!("{} {}", item.method, item.path),
                (&item.status, item.body_hash.as_ref()),
            )
        })
        .collect();

    let keys: std::collections::BTreeSet<_> =
        rust_map.keys().chain(go_map.keys()).cloned().collect();

    for key in keys {
        let left = rust_map.get(&key);
        let right = go_map.get(&key);
        if left != right {
            out.push(Mismatch {
                key,
                rust_value: json!(
                    left.map(|(status, hash)| { json!({"status": status, "hash": hash}) })
                ),
                go_value: json!(
                    right.map(|(status, hash)| { json!({"status": status, "hash": hash}) })
                ),
            });
        }
    }

    out
}

fn diff_ws(rust_ws: &[WsFrameCapture], go_ws: &[WsFrameCapture]) -> Vec<Mismatch> {
    let mut out = Vec::new();

    let rust_map: BTreeMap<String, String> = rust_ws
        .iter()
        .map(|item| {
            let hash = sha256_hex(
                serde_json::to_string(&item.frames)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            (item.path.clone(), format!("{}:{}", item.frames.len(), hash))
        })
        .collect();
    let go_map: BTreeMap<String, String> = go_ws
        .iter()
        .map(|item| {
            let hash = sha256_hex(
                serde_json::to_string(&item.frames)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            (item.path.clone(), format!("{}:{}", item.frames.len(), hash))
        })
        .collect();

    let keys: std::collections::BTreeSet<_> =
        rust_map.keys().chain(go_map.keys()).cloned().collect();

    for key in keys {
        let left = rust_map.get(&key);
        let right = go_map.get(&key);
        if left != right {
            out.push(Mismatch {
                key,
                rust_value: json!(left),
                go_value: json!(right),
            });
        }
    }

    out
}

fn to_markdown(report: &DiffReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# Diff Report: {}\n\n", report.case_id));
    md.push_str(&format!("- Compared at: {}\n", report.compared_at));
    md.push_str(&format!("- Run dir: {}\n", report.run_dir.display()));
    md.push_str(&format!(
        "- HTTP mismatches: {}\n",
        report.http_mismatches.len()
    ));
    md.push_str(&format!(
        "- WS mismatches: {}\n",
        report.ws_mismatches.len()
    ));
    md.push_str(&format!(
        "- Subscription mismatches: {}\n",
        report.subscription_mismatches.len()
    ));
    md.push_str(&format!(
        "- Traffic mismatches: {}\n\n",
        report.traffic_mismatches.len()
    ));

    for (title, items) in [
        ("HTTP", &report.http_mismatches),
        ("WebSocket", &report.ws_mismatches),
        ("Subscription", &report.subscription_mismatches),
        ("Traffic", &report.traffic_mismatches),
    ] {
        md.push_str(&format!("## {}\n\n", title));
        if items.is_empty() {
            md.push_str("No mismatches.\n\n");
            continue;
        }

        for item in items {
            md.push_str(&format!("- `{}`\n", item.key));
            md.push_str(&format!("  - rust: `{}`\n", item.rust_value));
            md.push_str(&format!("  - go: `{}`\n", item.go_value));
        }
        md.push('\n');
    }

    md
}
