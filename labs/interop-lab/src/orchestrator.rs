use crate::case_spec::{
    load_case_by_id, load_cases, CaseSpec, EnvClass, KernelControlAction, KernelLaunchSpec,
    KernelMode, KernelTarget, Priority, TrafficAction,
};
use crate::diff_report::{build_diff_report, to_markdown as diff_to_markdown};
use crate::go_collector::{collect_go_snapshot, save_go_snapshot_to_dir};
use crate::gui_replay::run_gui_sequence;
use crate::kernel::{launch_kernel, wait_until_ready, KernelSession};
use crate::snapshot::{KernelKind, NormalizedError, NormalizedSnapshot, TrafficResult};
use crate::upstream::{apply_faults, run_traffic_plan, start_upstreams};
use crate::util::{ensure_dir, resolve_with_env};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use regex::Regex;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RunOutput {
    pub case_id: String,
    pub run_id: String,
    pub run_dir: PathBuf,
    pub snapshot_files: Vec<PathBuf>,
    pub failures: Vec<CaseFailure>,
    /// Path to the diff report markdown, if dual-kernel diff was executed.
    pub diff_report_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CaseFailure {
    pub kernel: KernelKind,
    pub stage: String,
    pub message: String,
}

impl RunOutput {
    pub fn is_failed(&self) -> bool {
        !self.failures.is_empty()
    }
}

/// Optional Go API configuration for passive snapshot collection.
#[derive(Debug, Clone, Default)]
pub struct GoApiConfig {
    pub api_base: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CaseFilter {
    pub priority: Option<Priority>,
    pub include_tags: Vec<String>,
    pub exclude_tags: Vec<String>,
    pub env_class: Option<EnvClass>,
}

impl CaseFilter {
    pub fn matches(&self, case: &CaseSpec) -> bool {
        if let Some(priority) = &self.priority {
            if &case.priority != priority {
                return false;
            }
        }
        if let Some(env_class) = &self.env_class {
            if &case.env_class != env_class {
                return false;
            }
        }
        if self
            .include_tags
            .iter()
            .any(|tag| !case.tags.iter().any(|x| x == tag))
        {
            return false;
        }
        if self
            .exclude_tags
            .iter()
            .any(|tag| case.tags.iter().any(|x| x == tag))
        {
            return false;
        }
        true
    }
}

pub fn list_cases(cases_dir: &Path) -> Result<Vec<CaseSpec>> {
    load_cases(cases_dir)
}

pub fn load_single_case(cases_dir: &Path, id: &str) -> Result<CaseSpec> {
    load_case_by_id(cases_dir, id)
}

pub fn apply_case_filter(cases: Vec<CaseSpec>, filter: &CaseFilter) -> Vec<CaseSpec> {
    cases
        .into_iter()
        .filter(|case| filter.matches(case))
        .collect()
}

pub fn render_run_plan_summary(
    cases: &[CaseSpec],
    kernel_override: Option<KernelMode>,
    filter: &CaseFilter,
) -> String {
    let kernel = kernel_override
        .map(|mode| format!("{mode:?}"))
        .unwrap_or_else(|| "case-default".to_string());
    let priority = filter
        .priority
        .as_ref()
        .map(|p| format!("{p:?}"))
        .unwrap_or_else(|| "-".to_string());
    let env_class = filter
        .env_class
        .as_ref()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "-".to_string());
    let include_tags = if filter.include_tags.is_empty() {
        "-".to_string()
    } else {
        filter.include_tags.join(",")
    };
    let exclude_tags = if filter.exclude_tags.is_empty() {
        "-".to_string()
    } else {
        filter.exclude_tags.join(",")
    };
    let selected_ids = cases
        .iter()
        .map(|c| c.id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "plan_cases={} kernel_override={} priority={} env_class={} include_tags={} exclude_tags={} selected={}",
        cases.len(),
        kernel,
        priority,
        env_class,
        include_tags,
        exclude_tags,
        selected_ids
    )
}

pub async fn run_case(
    case: &CaseSpec,
    kernel_override: Option<KernelMode>,
    artifacts_root: &Path,
    go_api: &GoApiConfig,
) -> Result<RunOutput> {
    let run_id = format!("{}-{}", Utc::now().format("%Y%m%dT%H%M%SZ"), Uuid::new_v4());
    let run_dir = artifacts_root.join(&case.id).join(&run_id);
    let logs_dir = run_dir.join("logs");
    ensure_dir(&run_dir)?;
    ensure_dir(&logs_dir)?;

    let case_file = run_dir.join("case.yaml");
    let case_yaml = serde_yaml::to_string(case).with_context(|| "serializing case yaml")?;
    tokio::fs::write(&case_file, case_yaml)
        .await
        .with_context(|| format!("writing {}", case_file.display()))?;

    let mut harness = start_upstreams(&case.upstream_topology).await?;
    apply_faults(&mut harness, &case.faults)
        .await
        .with_context(|| format!("applying faults for case {}", case.id))?;

    let modes = match kernel_override.unwrap_or_else(|| case.kernel_mode.clone()) {
        KernelMode::Rust => vec![KernelKind::Rust],
        KernelMode::Go => vec![KernelKind::Go],
        KernelMode::Both => vec![KernelKind::Rust, KernelKind::Go],
    };

    let mut snapshot_files = Vec::new();
    let mut failures = Vec::new();

    for mode in modes {
        let started_at = Utc::now();
        let mut snapshot =
            NormalizedSnapshot::new(run_id.clone(), case.id.clone(), mode.clone(), started_at);

        let kernel_log_dir = logs_dir.join(format!("{:?}", mode).to_lowercase());
        ensure_dir(&kernel_log_dir)?;

        let launch_spec = match select_kernel_spec(case, mode.clone()) {
            Ok(spec) => {
                let mut launch_spec = spec.clone();
                launch_spec.api.base_url =
                    harness.resolve_templates(&resolve_with_env(&launch_spec.api.base_url));
                if let Some(secret) = &launch_spec.api.secret {
                    launch_spec.api.secret = Some(resolve_with_env(secret));
                }
                launch_spec
            }
            Err(err) => {
                snapshot.errors.push(NormalizedError {
                    stage: "select_kernel_spec".to_string(),
                    message: err.to_string(),
                });
                snapshot.finished_at = Utc::now();
                let snapshot_name = format!("{:?}.snapshot.json", mode).to_lowercase();
                let snapshot_path = run_dir.join(snapshot_name);
                let content = serde_json::to_vec_pretty(&snapshot)
                    .with_context(|| "serializing normalized snapshot")?;
                tokio::fs::write(&snapshot_path, content)
                    .await
                    .with_context(|| format!("writing {}", snapshot_path.display()))?;
                failures.extend(snapshot.errors.iter().map(|err| CaseFailure {
                    kernel: mode.clone(),
                    stage: err.stage.clone(),
                    message: err.message.clone(),
                }));
                snapshot_files.push(snapshot_path);
                continue;
            }
        };

        match launch_kernel(mode.clone(), &launch_spec, &kernel_log_dir).await {
            Ok(mut session) => {
                if let Err(err) = run_gui_sequence(case, &session.api, &mut snapshot).await {
                    snapshot.errors.push(NormalizedError {
                        stage: "gui_sequence".to_string(),
                        message: err.to_string(),
                    });
                }

                match run_traffic_plan_with_kernel_control(
                    case,
                    &mut harness,
                    &mode,
                    &launch_spec,
                    &kernel_log_dir,
                    &mut session,
                )
                .await
                {
                    Ok(results) => {
                        snapshot.traffic_results = results;
                    }
                    Err(err) => {
                        snapshot.errors.push(NormalizedError {
                            stage: "traffic_plan".to_string(),
                            message: err.to_string(),
                        });
                    }
                }

                if let Some(post_steps) = &case.post_traffic_gui_sequence {
                    let post_case = CaseSpec {
                        gui_sequence: post_steps.clone(),
                        ..case.clone()
                    };
                    if let Err(err) =
                        run_gui_sequence(&post_case, &session.api, &mut snapshot).await
                    {
                        snapshot.errors.push(NormalizedError {
                            stage: "post_traffic_gui_sequence".to_string(),
                            message: err.to_string(),
                        });
                    }
                }

                evaluate_assertions(case, &mut snapshot);

                let _ = session.shutdown().await;
            }
            Err(err) => {
                snapshot.errors.push(NormalizedError {
                    stage: "launch_kernel".to_string(),
                    message: err.to_string(),
                });
            }
        }

        snapshot.finished_at = Utc::now();
        failures.extend(collect_case_failures(case, &mode, &snapshot));
        let snapshot_name = format!("{:?}.snapshot.json", mode).to_lowercase();
        let snapshot_path = run_dir.join(snapshot_name);
        let content = serde_json::to_vec_pretty(&snapshot)
            .with_context(|| "serializing normalized snapshot")?;
        tokio::fs::write(&snapshot_path, content)
            .await
            .with_context(|| format!("writing {}", snapshot_path.display()))?;

        snapshot_files.push(snapshot_path);
    }

    harness.shutdown().await;

    let summary_path = run_dir.join("summary.json");
    let summary = json!({
        "case_id": case.id,
        "run_id": run_id,
        "snapshots": snapshot_files,
        "generated_at": Utc::now(),
    });
    let summary_json =
        serde_json::to_vec_pretty(&summary).with_context(|| "serializing run summary")?;
    tokio::fs::write(&summary_path, summary_json)
        .await
        .with_context(|| format!("writing {}", summary_path.display()))?;

    // --- Go passive snapshot collection (L10.1.2) ---
    let diff_report_path = if let Some(go_api_base) = &go_api.api_base {
        // Collect Go snapshot from the running Clash API
        match collect_go_snapshot(go_api_base, go_api.token.as_deref(), &case.id).await {
            Ok(go_snapshot) => {
                match save_go_snapshot_to_dir(&go_snapshot, &run_dir) {
                    Ok(go_snap_path) => {
                        snapshot_files.push(go_snap_path);
                        // Try to produce a diff if we have a Rust snapshot
                        let rust_snap_path = run_dir.join("rust.snapshot.json");
                        if rust_snap_path.exists() {
                            let rust_raw = std::fs::read_to_string(&rust_snap_path)
                                .with_context(|| "reading rust snapshot for diff")?;
                            let rust_snapshot: NormalizedSnapshot = serde_json::from_str(&rust_raw)
                                .with_context(|| "parsing rust snapshot for diff")?;
                            let report = build_diff_report(
                                &case.id,
                                run_dir.clone(),
                                &rust_snapshot,
                                &go_snapshot,
                                &case.oracle,
                            );
                            let md_path = run_dir.join("diff.md");
                            std::fs::write(&md_path, diff_to_markdown(&report))
                                .with_context(|| "writing diff markdown")?;
                            let json_path = run_dir.join("diff.json");
                            let json = serde_json::to_string_pretty(&report)
                                .with_context(|| "serializing diff report")?;
                            std::fs::write(&json_path, json)
                                .with_context(|| "writing diff json")?;
                            println!(
                                "diff clean={} gate_score={} report={}",
                                report.is_clean(),
                                report.gate_score,
                                md_path.display()
                            );
                            Some(md_path)
                        } else {
                            None
                        }
                    }
                    Err(err) => {
                        eprintln!("warning: failed to save Go snapshot: {err}");
                        None
                    }
                }
            }
            Err(err) => {
                eprintln!("warning: Go passive collection failed: {err}");
                None
            }
        }
    } else {
        None
    };

    Ok(RunOutput {
        case_id: case.id.clone(),
        run_id,
        run_dir,
        snapshot_files,
        failures,
        diff_report_path,
    })
}

async fn run_traffic_plan_with_kernel_control(
    case: &CaseSpec,
    harness: &mut crate::upstream::UpstreamHarness,
    mode: &KernelKind,
    launch_spec: &KernelLaunchSpec,
    kernel_log_dir: &Path,
    session: &mut KernelSession,
) -> Result<Vec<TrafficResult>> {
    let mut outputs = Vec::with_capacity(case.traffic_plan.len());
    for action in &case.traffic_plan {
        match action {
            TrafficAction::KernelControl {
                name,
                action,
                target,
                wait_ready_ms,
            } => {
                let result = execute_kernel_control_action(
                    name,
                    action,
                    target,
                    *wait_ready_ms,
                    mode,
                    launch_spec,
                    kernel_log_dir,
                    session,
                )
                .await;
                outputs.push(result);
            }
            _ => {
                let mut one = run_traffic_plan(harness, std::slice::from_ref(action)).await?;
                if let Some(result) = one.pop() {
                    outputs.push(result);
                }
            }
        }
    }
    Ok(outputs)
}

#[allow(clippy::too_many_arguments)]
async fn execute_kernel_control_action(
    name: &str,
    action: &KernelControlAction,
    target: &KernelTarget,
    wait_ready_ms: u64,
    mode: &KernelKind,
    launch_spec: &KernelLaunchSpec,
    kernel_log_dir: &Path,
    session: &mut KernelSession,
) -> TrafficResult {
    if !target_matches_mode(target, mode) {
        return TrafficResult {
            name: name.to_string(),
            success: true,
            detail: json!({
                "action": "kernel_control",
                "op": format!("{:?}", action),
                "target": format!("{:?}", target),
                "mode": format!("{:?}", mode),
                "skipped": true,
            }),
        };
    }

    let outcome = match action {
        KernelControlAction::Restart => {
            let _ = session.shutdown().await;
            match launch_kernel(mode.clone(), launch_spec, kernel_log_dir).await {
                Ok(new_session) => {
                    *session = new_session;
                    wait_until_ready(
                        &session.api,
                        &launch_spec.ready_path,
                        wait_ready_ms.max(100),
                    )
                    .await
                }
                Err(err) => Err(err),
            }
        }
        KernelControlAction::Reload => {
            let reload_detail = trigger_reload(session).await;
            match wait_until_ready(
                &session.api,
                &launch_spec.ready_path,
                wait_ready_ms.max(100),
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(err) => {
                    let info =
                        reload_detail.unwrap_or_else(|| "reload attempt unavailable".to_string());
                    Err(anyhow!("{err}; {info}"))
                }
            }
        }
    };

    match outcome {
        Ok(()) => TrafficResult {
            name: name.to_string(),
            success: true,
            detail: json!({
                "action": "kernel_control",
                "op": format!("{:?}", action),
                "target": format!("{:?}", target),
                "wait_ready_ms": wait_ready_ms,
            }),
        },
        Err(err) => TrafficResult {
            name: name.to_string(),
            success: false,
            detail: json!({
                "action": "kernel_control",
                "op": format!("{:?}", action),
                "target": format!("{:?}", target),
                "wait_ready_ms": wait_ready_ms,
                "error": err.to_string(),
            }),
        },
    }
}

fn target_matches_mode(target: &KernelTarget, mode: &KernelKind) -> bool {
    matches!(
        (target, mode),
        (KernelTarget::Rust, KernelKind::Rust) | (KernelTarget::Go, KernelKind::Go)
    )
}

async fn trigger_reload(session: &KernelSession) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let mut attempts = Vec::new();
    let candidates = [
        (reqwest::Method::POST, "/-/reload"),
        (reqwest::Method::POST, "/reload"),
        (reqwest::Method::PUT, "/reload"),
    ];
    for (method, path) in candidates {
        let url = format!("{}{}", session.api.base_url.trim_end_matches('/'), path);
        let mut req = client.request(method.clone(), &url);
        if let Some(secret) = &session.api.secret {
            req = req.bearer_auth(secret);
        }
        match req.send().await {
            Ok(resp) => {
                attempts.push(format!("{path}:{}", resp.status()));
                if resp.status().is_success()
                    || resp.status() == StatusCode::NOT_FOUND
                    || resp.status() == StatusCode::METHOD_NOT_ALLOWED
                {
                    break;
                }
            }
            Err(err) => attempts.push(format!("{path}:err={err}")),
        }
    }
    if attempts.is_empty() {
        None
    } else {
        Some(format!("reload_attempts={}", attempts.join(",")))
    }
}

fn evaluate_assertions(case: &CaseSpec, snapshot: &mut NormalizedSnapshot) {
    for assertion in &case.assertions {
        let actual = resolve_assertion_value(snapshot, &assertion.key);
        let passed =
            evaluate_assertion_op(assertion.op.as_str(), actual.as_ref(), &assertion.expected);
        if !passed {
            snapshot.errors.push(NormalizedError {
                stage: format!("assertion:{}", assertion.key),
                message: format!(
                    "assertion failed: key={} op={} expected={} actual={}",
                    assertion.key,
                    assertion.op,
                    assertion.expected,
                    actual
                        .as_ref()
                        .map(Value::to_string)
                        .unwrap_or_else(|| "null".to_string())
                ),
            });
        }
    }
}

fn collect_case_failures(
    case: &CaseSpec,
    mode: &KernelKind,
    snapshot: &NormalizedSnapshot,
) -> Vec<CaseFailure> {
    let has_error_assertions = case
        .assertions
        .iter()
        .any(|assertion| assertion.key == "errors.count" || assertion.key.starts_with("errors."));

    snapshot
        .errors
        .iter()
        .filter(|err| {
            if err.stage.starts_with("assertion:") {
                return true;
            }
            if err.stage == "launch_kernel" {
                return true;
            }
            !has_error_assertions
        })
        .map(|err| CaseFailure {
            kernel: mode.clone(),
            stage: err.stage.clone(),
            message: err.message.clone(),
        })
        .collect()
}

fn evaluate_assertion_op(op: &str, actual: Option<&Value>, expected: &Value) -> bool {
    match (op, actual) {
        ("eq", Some(value)) => value == expected,
        ("ne", Some(value)) => value != expected,
        ("exists", Some(_)) => true,
        ("exists", None) => false,
        ("not_exists", Some(_)) => false,
        ("not_exists", None) => true,
        ("gt", Some(value)) => compare_numeric(value, expected, |a, b| a > b),
        ("gte", Some(value)) => compare_numeric(value, expected, |a, b| a >= b),
        ("lt", Some(value)) => compare_numeric(value, expected, |a, b| a < b),
        ("lte", Some(value)) => compare_numeric(value, expected, |a, b| a <= b),
        ("contains", Some(value)) => contains_value(value, expected),
        ("regex", Some(value)) => matches_regex(value, expected),
        (_unknown, None) => false,
        (_unknown, Some(_)) => false,
    }
}

fn compare_numeric(actual: &Value, expected: &Value, cmp: fn(f64, f64) -> bool) -> bool {
    match (actual.as_f64(), expected.as_f64()) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

fn contains_value(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(a), Value::String(b)) => a.contains(b),
        (Value::Array(items), needle) => items.iter().any(|item| item == needle),
        (Value::Object(map), Value::String(key)) => map.contains_key(key),
        _ => false,
    }
}

fn matches_regex(actual: &Value, expected: &Value) -> bool {
    let text = match actual.as_str() {
        Some(v) => v,
        None => return false,
    };
    let pattern = match expected.as_str() {
        Some(v) => v,
        None => return false,
    };
    Regex::new(pattern)
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

fn resolve_assertion_value(snapshot: &NormalizedSnapshot, key: &str) -> Option<Value> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.is_empty() {
        return None;
    }
    match parts[0] {
        "errors" if parts.as_slice() == ["errors", "count"] => Some(json!(snapshot.errors.len())),
        "errors" if parts.len() >= 2 => {
            let idx = parts[1].parse::<usize>().ok()?;
            let err = snapshot.errors.get(idx)?;
            if parts.len() == 2 {
                return Some(json!({
                    "stage": err.stage.clone(),
                    "message": err.message.clone()
                }));
            }
            match parts[2] {
                "stage" if parts.len() == 3 => Some(json!(err.stage.clone())),
                "message" if parts.len() == 3 => Some(json!(err.message.clone())),
                _ => None,
            }
        }
        "subscription" if parts.len() == 2 => {
            snapshot
                .subscription_result
                .as_ref()
                .and_then(|res| match parts[1] {
                    "node_count" => Some(json!(res.node_count)),
                    "filtered_node_count" => Some(json!(res.filtered_node_count)),
                    "format" => Some(json!(res.format)),
                    "success" => Some(json!(res.success)),
                    _ => None,
                })
        }
        "ws" if parts.len() == 3 => snapshot
            .ws_frames
            .iter()
            .find(|r| r.name == parts[1])
            .and_then(|r| match parts[2] {
                "frame_count" => Some(json!(r.frames.len())),
                _ => None,
            }),
        "http" if parts.len() == 3 => snapshot
            .http_results
            .iter()
            .find(|r| r.name == parts[1])
            .and_then(|r| match parts[2] {
                "status" => Some(json!(r.status)),
                "path" => Some(json!(r.path)),
                "method" => Some(json!(r.method)),
                "body_hash" => Some(json!(r.body_hash)),
                _ => None,
            }),
        "traffic" if parts.len() >= 3 => snapshot
            .traffic_results
            .iter()
            .find(|r| r.name == parts[1])
            .and_then(|r| match parts[2] {
                "success" if parts.len() == 3 => Some(json!(r.success)),
                "detail" if parts.len() == 3 => Some(r.detail.clone()),
                "detail" => resolve_json_path(&r.detail, &parts[3..]),
                _ => None,
            }),
        "connections" => resolve_connections_assertion(snapshot, &parts[1..]),
        _ => None,
    }
}

/// Resolve `connections.count`, `connections.<idx>.<field>`, `connections.<idx>.<field>.<subpath>`
/// conn_summary holds the raw JSON from `GET /connections` which has shape:
/// `{ "connections": [...], "downloadTotal": N, "uploadTotal": N }`
fn resolve_connections_assertion(snapshot: &NormalizedSnapshot, path: &[&str]) -> Option<Value> {
    let conn_summary = snapshot.conn_summary.as_ref()?;
    let conns_array = conn_summary.get("connections")?.as_array()?;

    if path.is_empty() {
        return None;
    }

    match path[0] {
        "count" => Some(json!(conns_array.len())),
        idx_str => {
            if let Ok(idx) = idx_str.parse::<usize>() {
                let conn = conns_array.get(idx)?;
                if path.len() == 1 {
                    return Some(conn.clone());
                }
                return resolve_json_path(conn, &path[1..]);
            }
            if path.len() == 1 {
                return conn_summary.get(idx_str).cloned();
            }
            conn_summary
                .get(idx_str)
                .and_then(|value| resolve_json_path(value, &path[1..]))
        }
    }
}

fn resolve_json_path(root: &Value, path: &[&str]) -> Option<Value> {
    let mut current = root;
    for segment in path {
        match current {
            Value::Object(map) => {
                current = map.get(*segment)?;
            }
            Value::Array(items) => {
                let idx = segment.parse::<usize>().ok()?;
                current = items.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current.clone())
}

pub fn latest_run_dir(artifacts_root: &Path, case_id: &str) -> Result<PathBuf> {
    let case_dir = artifacts_root.join(case_id);
    let entries = std::fs::read_dir(&case_dir)
        .with_context(|| format!("reading case artifact dir {}", case_dir.display()))?;

    let mut runs = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| "reading run dir entry")?;
        let path = entry.path();
        if path.is_dir() {
            runs.push(path);
        }
    }

    runs.sort();
    runs.pop()
        .with_context(|| format!("no runs for case {case_id}"))
}

fn select_kernel_spec(case: &CaseSpec, mode: KernelKind) -> Result<&KernelLaunchSpec> {
    match mode {
        KernelKind::Rust => case
            .bootstrap
            .rust
            .as_ref()
            .with_context(|| format!("case {} missing bootstrap.rust", case.id)),
        KernelKind::Go => case
            .bootstrap
            .go
            .as_ref()
            .with_context(|| format!("case {} missing bootstrap.go", case.id)),
    }
}

pub async fn run_cases(
    cases: &[CaseSpec],
    kernel_override: Option<KernelMode>,
    artifacts_root: &Path,
    go_api: &GoApiConfig,
) -> Result<Vec<RunOutput>> {
    if cases.is_empty() {
        return Err(anyhow!("no cases selected"));
    }

    let mut outputs = Vec::with_capacity(cases.len());
    for case in cases {
        let output = run_case(case, kernel_override.clone(), artifacts_root, go_api)
            .await
            .with_context(|| format!("running case {}", case.id))?;
        outputs.push(output);
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{
        KernelKind, NormalizedSnapshot, SubscriptionResult, TrafficResult, WsFrameCapture,
    };

    #[test]
    fn resolve_assertion_extended_paths() {
        let now = Utc::now();
        let mut snapshot =
            NormalizedSnapshot::new("run".to_string(), "case".to_string(), KernelKind::Rust, now);
        snapshot.ws_frames.push(WsFrameCapture {
            name: "connections_stream".to_string(),
            path: "/connections".to_string(),
            frames: vec![json!({"a": 1}), json!({"a": 2})],
        });
        snapshot.subscription_result = Some(SubscriptionResult {
            source_type: "inline".to_string(),
            success: true,
            format: "json_outbounds".to_string(),
            node_count: 3,
            filtered_node_count: 3,
            protocols: vec!["trojan".to_string()],
            detail: json!({}),
        });
        snapshot.traffic_results.push(TrafficResult {
            name: "probe".to_string(),
            success: true,
            detail: json!({
                "status": 200,
                "nested": { "latency_ms": 123 },
                "labels": ["ok", "fast"],
                "msg": "hello-world"
            }),
        });
        snapshot.errors.push(NormalizedError {
            stage: "subscription_parse".to_string(),
            message: "unsupported subscription format".to_string(),
        });
        snapshot.conn_summary = Some(json!({
            "connections": [],
            "downloadTotal": 42,
            "uploadTotal": 21
        }));

        assert_eq!(
            resolve_assertion_value(&snapshot, "ws.connections_stream.frame_count"),
            Some(json!(2))
        );
        assert_eq!(
            resolve_assertion_value(&snapshot, "subscription.node_count"),
            Some(json!(3))
        );
        assert_eq!(
            resolve_assertion_value(&snapshot, "traffic.probe.detail.nested.latency_ms"),
            Some(json!(123))
        );
        assert_eq!(
            resolve_assertion_value(&snapshot, "errors.0.stage"),
            Some(json!("subscription_parse"))
        );
        assert_eq!(
            resolve_assertion_value(&snapshot, "errors.0.message"),
            Some(json!("unsupported subscription format"))
        );
        assert_eq!(
            resolve_assertion_value(&snapshot, "connections.downloadTotal"),
            Some(json!(42))
        );
    }

    #[test]
    fn evaluate_assertion_new_operators() {
        assert!(evaluate_assertion_op("gt", Some(&json!(10)), &json!(9)));
        assert!(evaluate_assertion_op("gte", Some(&json!(10)), &json!(10)));
        assert!(evaluate_assertion_op("lt", Some(&json!(9)), &json!(10)));
        assert!(evaluate_assertion_op("lte", Some(&json!(10)), &json!(10)));
        assert!(evaluate_assertion_op(
            "contains",
            Some(&json!("abc-hello-xyz")),
            &json!("hello")
        ));
        assert!(evaluate_assertion_op(
            "regex",
            Some(&json!("abc-123")),
            &json!("^abc-\\d+$")
        ));
    }
}
