use crate::case_spec::{CaseSpec, OracleSpec};
use crate::orchestrator::latest_run_dir;
use crate::snapshot::{HttpResult, NormalizedSnapshot, WsFrameCapture};
use crate::util::sha256_hex;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
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
    pub ignored_http_count: usize,
    pub ignored_ws_count: usize,
    pub ignored_counter_jitter_count: usize,
    pub gate_score: usize,
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
    let case_path = run_dir.join("case.yaml");

    let rust_raw = tokio::fs::read(&rust_path)
        .await
        .with_context(|| format!("reading {}", rust_path.display()))?;
    let go_raw = tokio::fs::read(&go_path)
        .await
        .with_context(|| format!("reading {}", go_path.display()))?;
    let case_raw = tokio::fs::read_to_string(&case_path)
        .await
        .with_context(|| format!("reading {}", case_path.display()))?;

    let rust_snapshot: NormalizedSnapshot = serde_json::from_slice(&rust_raw)
        .with_context(|| format!("parsing {}", rust_path.display()))?;
    let go_snapshot: NormalizedSnapshot = serde_json::from_slice(&go_raw)
        .with_context(|| format!("parsing {}", go_path.display()))?;
    let case_spec: CaseSpec =
        serde_yaml::from_str(&case_raw).with_context(|| format!("parsing {}", case_path.display()))?;

    let report = build_diff_report(
        case_id,
        run_dir.clone(),
        &rust_snapshot,
        &go_snapshot,
        &case_spec.oracle,
    );

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
    oracle: &OracleSpec,
) -> DiffReport {
    let (http_mismatches, ignored_http_count) = diff_http(
        &rust_snapshot.http_results,
        &go_snapshot.http_results,
        &oracle.ignore_http_paths,
    );
    let (ws_mismatches, ignored_ws_count) =
        diff_ws(&rust_snapshot.ws_frames, &go_snapshot.ws_frames, &oracle.ignore_ws_paths);

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
    let mut ignored_counter_jitter_count = 0usize;
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

    let keys: BTreeSet<_> = rust_traffic.keys().chain(go_traffic.keys()).cloned().collect();
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

    for field in ["up", "down"] {
        let left = rust_snapshot
            .traffic_counters
            .as_ref()
            .map(|c| if field == "up" { c.up } else { c.down });
        let right = go_snapshot
            .traffic_counters
            .as_ref()
            .map(|c| if field == "up" { c.up } else { c.down });
        if left == right {
            continue;
        }
        if let (Some(a), Some(b)) = (left, right) {
            if oracle.tolerate_counter_jitter && (a - b).abs() <= oracle.counter_jitter_abs {
                ignored_counter_jitter_count += 1;
                continue;
            }
        }
        traffic_mismatches.push(Mismatch {
            key: format!("traffic_counters.{field}"),
            rust_value: json!(left),
            go_value: json!(right),
        });
    }

    let gate_score = http_mismatches.len()
        + ws_mismatches.len()
        + subscription_mismatches.len()
        + traffic_mismatches.len();

    DiffReport {
        case_id: case_id.to_string(),
        run_dir,
        compared_at: Utc::now().to_rfc3339(),
        http_mismatches,
        ws_mismatches,
        subscription_mismatches,
        traffic_mismatches,
        ignored_http_count,
        ignored_ws_count,
        ignored_counter_jitter_count,
        gate_score,
    }
}

fn diff_http(
    rust_http: &[HttpResult],
    go_http: &[HttpResult],
    ignore_paths: &[String],
) -> (Vec<Mismatch>, usize) {
    let mut out = Vec::new();
    let mut ignored = 0usize;

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

    let keys: BTreeSet<_> = rust_map.keys().chain(go_map.keys()).cloned().collect();
    for key in keys {
        let left = rust_map.get(&key);
        let right = go_map.get(&key);
        if left == right {
            continue;
        }
        let path = key.split_once(' ').map(|(_, path)| path).unwrap_or_default();
        if is_ignored_path(path, ignore_paths) {
            ignored += 1;
            continue;
        }
        out.push(Mismatch {
            key,
            rust_value: json!(left.map(|(status, hash)| { json!({"status": status, "hash": hash}) })),
            go_value: json!(right.map(|(status, hash)| { json!({"status": status, "hash": hash}) })),
        });
    }

    (out, ignored)
}

fn diff_ws(
    rust_ws: &[WsFrameCapture],
    go_ws: &[WsFrameCapture],
    ignore_paths: &[String],
) -> (Vec<Mismatch>, usize) {
    let mut out = Vec::new();
    let mut ignored = 0usize;

    let rust_map: BTreeMap<String, String> = rust_ws
        .iter()
        .map(|item| {
            let hash = sha256_hex(serde_json::to_string(&item.frames).unwrap_or_default().as_bytes());
            (item.path.clone(), format!("{}:{}", item.frames.len(), hash))
        })
        .collect();
    let go_map: BTreeMap<String, String> = go_ws
        .iter()
        .map(|item| {
            let hash = sha256_hex(serde_json::to_string(&item.frames).unwrap_or_default().as_bytes());
            (item.path.clone(), format!("{}:{}", item.frames.len(), hash))
        })
        .collect();

    let keys: BTreeSet<_> = rust_map.keys().chain(go_map.keys()).cloned().collect();
    for key in keys {
        let left = rust_map.get(&key);
        let right = go_map.get(&key);
        if left == right {
            continue;
        }
        if is_ignored_path(&key, ignore_paths) {
            ignored += 1;
            continue;
        }
        out.push(Mismatch {
            key,
            rust_value: json!(left),
            go_value: json!(right),
        });
    }

    (out, ignored)
}

fn is_ignored_path(path: &str, ignore_paths: &[String]) -> bool {
    ignore_paths.iter().any(|rule| {
        if let Some(prefix) = rule.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == rule
        }
    })
}

fn to_markdown(report: &DiffReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# Diff Report: {}\n\n", report.case_id));
    md.push_str(&format!("- Compared at: {}\n", report.compared_at));
    md.push_str(&format!("- Run dir: {}\n", report.run_dir.display()));
    md.push_str(&format!("- HTTP mismatches: {}\n", report.http_mismatches.len()));
    md.push_str(&format!("- WS mismatches: {}\n", report.ws_mismatches.len()));
    md.push_str(&format!(
        "- Subscription mismatches: {}\n",
        report.subscription_mismatches.len()
    ));
    md.push_str(&format!(
        "- Traffic mismatches: {}\n",
        report.traffic_mismatches.len()
    ));
    md.push_str(&format!("- Ignored HTTP: {}\n", report.ignored_http_count));
    md.push_str(&format!("- Ignored WS: {}\n", report.ignored_ws_count));
    md.push_str(&format!(
        "- Ignored Counter Jitter: {}\n",
        report.ignored_counter_jitter_count
    ));
    md.push_str(&format!("- Gate score: {}\n\n", report.gate_score));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{KernelKind, NormalizedSnapshot, TrafficCounters};

    #[test]
    fn oracle_ignore_and_counter_jitter_work() {
        let now = Utc::now();
        let mut rust = NormalizedSnapshot::new("run".into(), "case".into(), KernelKind::Rust, now);
        let mut go = NormalizedSnapshot::new("run".into(), "case".into(), KernelKind::Go, now);

        rust.http_results.push(HttpResult {
            name: "a".into(),
            method: "GET".into(),
            path: "/ignored".into(),
            status: 200,
            body: None,
            body_hash: Some("a".into()),
        });
        go.http_results.push(HttpResult {
            name: "a".into(),
            method: "GET".into(),
            path: "/ignored".into(),
            status: 500,
            body: None,
            body_hash: Some("b".into()),
        });

        rust.traffic_counters = Some(TrafficCounters {
            up: 100,
            down: 200,
            extra: BTreeMap::new(),
        });
        go.traffic_counters = Some(TrafficCounters {
            up: 103,
            down: 201,
            extra: BTreeMap::new(),
        });

        let oracle = OracleSpec {
            ignore_http_paths: vec!["/ignored".into()],
            ignore_ws_paths: vec![],
            tolerate_counter_jitter: true,
            counter_jitter_abs: 5,
        };
        let report = build_diff_report("case", PathBuf::from("."), &rust, &go, &oracle);
        assert_eq!(report.http_mismatches.len(), 0);
        assert_eq!(report.ignored_http_count, 1);
        assert_eq!(report.ignored_counter_jitter_count, 2);
        assert_eq!(report.gate_score, 0);
    }
}
