//! Tools CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use tracing_subscriber::EnvFilter;

    #[derive(Parser, Debug)]
    #[command(name = "tools", version, about = "Utility tools")]
    struct ToolsCli {
        #[command(flatten)]
        global: app::cli::GlobalArgs,
        #[command(flatten)]
        args: app::cli::tools::ToolsArgs,
    }

    let cli = ToolsCli::parse();
    app::cli::apply_global_options(&cli.global)?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    app::cli::tools::run(&cli.global, cli.args).await
}
