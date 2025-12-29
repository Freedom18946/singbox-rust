//! Config formatter CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "format", version, about = "Format configuration")]
    struct FormatCli {
        #[command(flatten)]
        global: app::cli::GlobalArgs,
        #[command(flatten)]
        args: app::cli::format::FormatArgs,
    }

    let cli = FormatCli::parse();
    app::cli::apply_global_options(&cli.global)?;
    app::cli::format::run(&cli.global, cli.args)
}
