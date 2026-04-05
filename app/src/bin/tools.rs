//! Tools CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

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

    // Initialize logging via canonical tracing init contract
    let _ = app::tracing_init::init_tracing_once();
    app::cli::tools::run(&cli.global, cli.args).await
}
