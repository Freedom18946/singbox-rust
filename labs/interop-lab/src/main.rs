mod case_spec;
mod cli;
mod diff_report;
mod gui_replay;
mod kernel;
mod orchestrator;
mod report;
mod snapshot;
mod subscription;
mod upstream;
mod util;

use anyhow::{Context, Result};
use case_spec::KernelMode;
use clap::Parser;
use cli::{CaseCommand, Cli, KernelModeArg, ReportCommand, TopCommand};
use diff_report::diff_latest_case;
use orchestrator::{list_cases, load_single_case, run_case, run_cases};
use report::{latest_report_path, read_report};
use std::path::Path;
use util::{canonicalize_or, ensure_dir};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    ensure_dir(&cli.artifacts_dir)?;
    let cases_dir = cli.cases_dir.clone();
    let artifacts_dir = cli.artifacts_dir.clone();

    match cli.command {
        TopCommand::Case { command } => {
            handle_case_command(command, &cases_dir, &artifacts_dir).await
        }
        TopCommand::Report { command } => handle_report_command(command, &artifacts_dir).await,
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
                println!("{}\t{:?}\t{:?}", case.id, case.priority, case.kernel_mode);
            }
            Ok(())
        }
        CaseCommand::Run { id, kernel } => {
            let kernel_override = kernel.map(map_kernel_mode_arg);

            if let Some(id) = id {
                let case = load_single_case(cases_dir, &id)?;
                let output = run_case(&case, kernel_override, artifacts_dir)
                    .await
                    .with_context(|| format!("running case {id}"))?;
                println!("case={} run_id={}", output.case_id, output.run_id);
                println!("run_dir={}", canonicalize_or(&output.run_dir).display());
                for snapshot in output.snapshot_files {
                    println!("snapshot={}", canonicalize_or(&snapshot).display());
                }
                return Ok(());
            }

            let cases = list_cases(cases_dir)?;
            let outputs = run_cases(&cases, kernel_override, artifacts_dir).await?;
            for output in outputs {
                println!("case={} run_id={}", output.case_id, output.run_id);
                println!("run_dir={}", canonicalize_or(&output.run_dir).display());
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

fn map_kernel_mode_arg(mode: KernelModeArg) -> KernelMode {
    match mode {
        KernelModeArg::Rust => KernelMode::Rust,
        KernelModeArg::Go => KernelMode::Go,
        KernelModeArg::Both => KernelMode::Both,
    }
}
