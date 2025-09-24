pub mod check;
pub mod buildinfo;
pub mod fs_scan;
pub mod report;
pub mod health;
pub mod json;
#[cfg(feature = "router")]
pub mod route;
#[cfg(feature = "router")]
pub mod run;

use clap::Parser;

/// CLI
#[derive(Parser, Debug)]
#[command(
    name = "singbox-rust",
    version,
    author,
    about = "Minimal runnable entrypoint"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Validate configuration without starting I/O
    Check(check::CheckArgs),
    #[cfg(feature = "router")]
    /// Run main service (existing)
    Run(run::RunArgs),
    #[cfg(feature = "router")]
    /// Route explain and test
    Route(route::RouteArgs),
}
