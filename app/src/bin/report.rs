#![cfg(feature = "dev-cli")]
use app::cli::report::{self, Args};
use clap::Parser;

fn main() {
    let args = Args::parse();
    if let Err(e) = report::main(args) {
        tracing::error!(target: "app::report", error = %e, "report error");
        std::process::exit(1);
    }
}
