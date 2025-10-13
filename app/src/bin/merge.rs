//! Config merge CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = app::cli::merge::MergeArgs::parse();
    app::cli::merge::run(args).await
}
