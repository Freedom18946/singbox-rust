use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "interop-lab", about = "Go/Rust/GUI interop simulation harness")]
pub struct Cli {
    #[command(subcommand)]
    pub command: TopCommand,
    /// Case definitions directory.
    #[arg(global = true, long, default_value = "labs/interop-lab/cases")]
    pub cases_dir: PathBuf,
    /// Artifacts output directory.
    #[arg(global = true, long, default_value = "labs/interop-lab/artifacts")]
    pub artifacts_dir: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum TopCommand {
    /// Manage and execute interop cases.
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Open generated reports.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum CaseCommand {
    /// List all available cases.
    List,
    /// Run one case, or all cases when id is omitted.
    Run {
        /// Optional case id. When omitted all cases are executed.
        id: Option<String>,
        /// Override target kernel mode.
        #[arg(long)]
        kernel: Option<KernelModeArg>,
    },
    /// Compare latest Go/Rust snapshots for one case.
    Diff {
        /// Case id.
        id: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    /// Print the latest report path for one case.
    Open {
        /// Case id.
        id: String,
        /// Print report markdown body as well.
        #[arg(long)]
        print: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KernelModeArg {
    Rust,
    Go,
    Both,
}
