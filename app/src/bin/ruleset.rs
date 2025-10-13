//! Rule-set CLI shim.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    let args = app::cli::ruleset::RulesetArgs::parse();
    app::cli::ruleset::run(args).await
}
