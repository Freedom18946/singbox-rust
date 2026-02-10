use crate::case_spec::{load_case_by_id, load_cases, CaseSpec, KernelLaunchSpec, KernelMode};
use crate::gui_replay::run_gui_sequence;
use crate::kernel::launch_kernel;
use crate::snapshot::{KernelKind, NormalizedError, NormalizedSnapshot};
use crate::upstream::{run_traffic_plan, start_upstreams};
use crate::util::{ensure_dir, resolve_with_env};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde_json::json;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RunOutput {
    pub case_id: String,
    pub run_id: String,
    pub run_dir: PathBuf,
    pub snapshot_files: Vec<PathBuf>,
}

pub fn list_cases(cases_dir: &Path) -> Result<Vec<CaseSpec>> {
    load_cases(cases_dir)
}

pub fn load_single_case(cases_dir: &Path, id: &str) -> Result<CaseSpec> {
    load_case_by_id(cases_dir, id)
}

pub async fn run_case(
    case: &CaseSpec,
    kernel_override: Option<KernelMode>,
    artifacts_root: &Path,
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

    let harness = start_upstreams(&case.upstream_topology).await?;

    let modes = match kernel_override.unwrap_or_else(|| case.kernel_mode.clone()) {
        KernelMode::Rust => vec![KernelKind::Rust],
        KernelMode::Go => vec![KernelKind::Go],
        KernelMode::Both => vec![KernelKind::Rust, KernelKind::Go],
    };

    let mut snapshot_files = Vec::new();

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

                match run_traffic_plan(&harness, &case.traffic_plan).await {
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

    Ok(RunOutput {
        case_id: case.id.clone(),
        run_id,
        run_dir,
        snapshot_files,
    })
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
) -> Result<Vec<RunOutput>> {
    if cases.is_empty() {
        return Err(anyhow!("no cases selected"));
    }

    let mut outputs = Vec::with_capacity(cases.len());
    for case in cases {
        let output = run_case(case, kernel_override.clone(), artifacts_root)
            .await
            .with_context(|| format!("running case {}", case.id))?;
        outputs.push(output);
    }
    Ok(outputs)
}
