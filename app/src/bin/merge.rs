//! Config merge CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "merge", version, about = "Merge configurations")]
    struct MergeCli {
        #[command(flatten)]
        global: app::cli::GlobalArgs,
        #[command(flatten)]
        args: app::cli::merge::MergeArgs,
    }

    let cli = MergeCli::parse();
    app::cli::apply_global_options(&cli.global)?;
    app::cli::merge::run(&cli.global, cli.args)
}
