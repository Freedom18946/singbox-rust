#![cfg_attr(feature = "strict_warnings", deny(warnings))]
//! Full-featured config checker shim for the standalone `check` binary.

use anyhow::Result;
use app::cli::check::CheckArgs;
use clap::{ArgAction, Parser};

#[derive(Parser, Debug)]
#[command(name = "check", version, about = "singbox-rs config checker")]
struct CheckCli {
    #[command(flatten)]
    args: CheckArgs,
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    help_json: bool,
}

fn main() -> Result<()> {
    if std::env::args().skip(1).any(|arg| arg == "--help-json") {
        app::cli::help::print_help_json::<CheckCli>();
    }
    let cli = CheckCli::parse();
    if cli.help_json {
        app::cli::help::print_help_json::<CheckCli>();
    }
    let code = app::cli::check::run(cli.args)?;
    std::process::exit(code);
}
