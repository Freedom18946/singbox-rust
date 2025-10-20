//! Config formatter CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = app::cli::format::FormatArgs::parse();
    app::cli::format::run(args)
}
