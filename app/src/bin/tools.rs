//! Tools CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = app::cli::tools::ToolsArgs::parse();
    app::cli::tools::run(args).await
}
