//! Tools CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = app::cli::tools::ToolsArgs::parse();
    app::cli::tools::run(args).await
}
