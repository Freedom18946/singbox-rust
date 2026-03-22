mod attribution;
mod case_spec;
mod cli;
mod diff_report;
mod go_collector;
mod gui_replay;
mod kernel;
mod leak_detector;
mod orchestrator;
mod report;
mod snapshot;
mod subscription;
mod upstream;
mod util;

use anyhow::{Context, Result};
use case_spec::{EnvClass, KernelMode, Priority};
use clap::Parser;
use cli::{
    CaseCommand, Cli, EnvClassArg, GoSnapshotArgs, KernelModeArg, PriorityArg, ReportCommand,
    TopCommand,
};
use diff_report::diff_latest_case;
use go_collector::{collect_go_snapshot, save_go_snapshot};
use orchestrator::{
    apply_case_filter, list_cases, load_single_case, render_run_plan_summary, run_case, run_cases,
    CaseFilter, GoApiConfig,
};
use report::{latest_report_path, read_report};
use std::path::Path;
use util::{canonicalize_or, ensure_dir};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    ensure_dir(&cli.artifacts_dir)?;
    let cases_dir = cli.cases_dir.clone();
    let artifacts_dir = cli.artifacts_dir.clone();

    match cli.command {
        TopCommand::Case { command } => {
            handle_case_command(command, &cases_dir, &artifacts_dir).await
        }
        TopCommand::Report { command } => handle_report_command(command, &artifacts_dir).await,
        TopCommand::GoSnapshot(args) => handle_go_snapshot(args, &artifacts_dir).await,
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    match tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false)
        .try_init()
    {
        Ok(()) => {}
        Err(err) => {
            if !err.to_string().contains("already been set") {
                eprintln!("interop tracing init skipped: {err}");
            }
        }
    }
}

async fn handle_case_command(
    command: CaseCommand,
    cases_dir: &Path,
    artifacts_dir: &Path,
) -> Result<()> {
    match command {
        CaseCommand::List => {
            let cases = list_cases(cases_dir)?;
            for case in cases {
                println!(
                    "{}\t{:?}\t{:?}\t{:?}\t{}",
                    case.id,
                    case.priority,
                    case.kernel_mode,
                    case.env_class,
                    case.tags.join(",")
                );
            }
            Ok(())
        }
        CaseCommand::Run {
            id,
            kernel,
            priority,
            tag,
            exclude_tag,
            env_class,
            go_api,
            go_token,
        } => {
            let kernel_override = kernel.map(map_kernel_mode_arg);
            let filter = CaseFilter {
                priority: priority.map(map_priority_arg),
                include_tags: tag,
                exclude_tags: exclude_tag,
                env_class: env_class.map(map_env_class_arg),
            };
            let go_api_cfg = GoApiConfig {
                api_base: go_api,
                token: go_token,
            };

            if let Some(id) = id {
                let case = load_single_case(cases_dir, &id)?;
                if !filter.matches(&case) {
                    anyhow::bail!("case '{}' filtered out by the selected run filters", id);
                }
                println!(
                    "{}",
                    render_run_plan_summary(
                        std::slice::from_ref(&case),
                        kernel_override.clone(),
                        &filter
                    )
                );
                let output = run_case(&case, kernel_override, artifacts_dir, &go_api_cfg)
                    .await
                    .with_context(|| format!("running case {id}"))?;
                println!("case={} run_id={}", output.case_id, output.run_id);
                println!("run_dir={}", canonicalize_or(&output.run_dir).display());
                if let Some(diff_path) = &output.diff_report_path {
                    println!("diff_report={}", canonicalize_or(diff_path).display());
                }
                for snapshot in &output.snapshot_files {
                    println!("snapshot={}", canonicalize_or(snapshot).display());
                }
                if output.is_failed() {
                    eprintln!("case_run_failed_count=1");
                    eprintln!(
                        "case_fail case={} run_id={} run_dir={}",
                        output.case_id,
                        output.run_id,
                        canonicalize_or(&output.run_dir).display()
                    );
                    for failure in &output.failures {
                        eprintln!(
                            "case_fail_detail case={} run_id={} kernel={:?} stage={} message={}",
                            output.case_id,
                            output.run_id,
                            failure.kernel,
                            failure.stage,
                            failure.message
                        );
                    }
                    anyhow::bail!(
                        "case run failed: case={} run_id={} errors={}",
                        output.case_id,
                        output.run_id,
                        output.failures.len()
                    );
                }
                return Ok(());
            }

            let cases = list_cases(cases_dir)?;
            let selected = apply_case_filter(cases, &filter);
            println!(
                "{}",
                render_run_plan_summary(&selected, kernel_override.clone(), &filter)
            );
            let outputs = run_cases(&selected, kernel_override, artifacts_dir, &go_api_cfg).await?;
            let mut failed_count = 0usize;
            for output in &outputs {
                println!("case={} run_id={}", output.case_id, output.run_id);
                println!("run_dir={}", canonicalize_or(&output.run_dir).display());
                if output.is_failed() {
                    failed_count += 1;
                    eprintln!(
                        "case_fail case={} run_id={} run_dir={}",
                        output.case_id,
                        output.run_id,
                        canonicalize_or(&output.run_dir).display()
                    );
                    for failure in &output.failures {
                        eprintln!(
                            "case_fail_detail case={} run_id={} kernel={:?} stage={} message={}",
                            output.case_id,
                            output.run_id,
                            failure.kernel,
                            failure.stage,
                            failure.message
                        );
                    }
                }
            }
            if failed_count > 0 {
                eprintln!("case_run_failed_count={failed_count}");
                anyhow::bail!("case run failed: {failed_count} case(s) failed");
            }
            Ok(())
        }
        CaseCommand::Diff { id } => {
            let (report, markdown_path) = diff_latest_case(artifacts_dir, &id)
                .await
                .with_context(|| format!("diffing case {id}"))?;
            println!("case={}", id);
            println!("clean={}", report.is_clean());
            println!("http_mismatches={}", report.http_mismatches.len());
            println!("ws_mismatches={}", report.ws_mismatches.len());
            println!(
                "subscription_mismatches={}",
                report.subscription_mismatches.len()
            );
            println!("traffic_mismatches={}", report.traffic_mismatches.len());
            println!(
                "connection_mismatches={}",
                report.connection_mismatches.len()
            );
            println!("memory_mismatches={}", report.memory_mismatches.len());
            println!("ignored_http={}", report.ignored_http_count);
            println!("ignored_ws={}", report.ignored_ws_count);
            println!(
                "ignored_counter_jitter={}",
                report.ignored_counter_jitter_count
            );
            println!("gate_score={}", report.gate_score);
            println!("report={}", canonicalize_or(&markdown_path).display());
            Ok(())
        }
    }
}

async fn handle_report_command(command: ReportCommand, artifacts_dir: &Path) -> Result<()> {
    match command {
        ReportCommand::Open { id, print } => {
            let report_path = latest_report_path(artifacts_dir, &id)?;
            println!("{}", canonicalize_or(&report_path).display());
            if print {
                let body = read_report(&report_path).await?;
                println!();
                println!("{body}");
            }
            Ok(())
        }
    }
}

async fn handle_go_snapshot(args: GoSnapshotArgs, artifacts_dir: &Path) -> Result<()> {
    let token = args.token.as_deref();
    println!("Collecting Go snapshot from {} ...", args.api);
    let snapshot = collect_go_snapshot(&args.api, token, &args.case_id)
        .await
        .with_context(|| "collecting Go snapshot")?;
    println!("HTTP results: {}", snapshot.http_results.len());
    println!("WS captures:  {}", snapshot.ws_frames.len());
    println!("Memory pts:   {}", snapshot.memory_series.len());
    println!("Errors:       {}", snapshot.errors.len());
    let path = save_go_snapshot(&snapshot, artifacts_dir)?;
    println!("Saved: {}", canonicalize_or(&path).display());
    Ok(())
}

fn map_kernel_mode_arg(mode: KernelModeArg) -> KernelMode {
    match mode {
        KernelModeArg::Rust => KernelMode::Rust,
        KernelModeArg::Go => KernelMode::Go,
        KernelModeArg::Both => KernelMode::Both,
    }
}

fn map_priority_arg(priority: PriorityArg) -> Priority {
    match priority {
        PriorityArg::P0 => Priority::P0,
        PriorityArg::P1 => Priority::P1,
        PriorityArg::P2 => Priority::P2,
    }
}

fn map_env_class_arg(env_class: EnvClassArg) -> EnvClass {
    match env_class {
        EnvClassArg::Strict => EnvClass::Strict,
        EnvClassArg::EnvLimited => EnvClass::EnvLimited,
    }
}
