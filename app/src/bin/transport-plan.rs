use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "transport-plan", about = "Print derived transport chain for each outbound")] 
    struct Args {
        /// Path to config file (YAML/JSON)
        #[arg(short, long, value_name = "FILE", default_value = "./config.yaml")]
        config: PathBuf,
    }

    let args = Args::parse();

    // Load config and convert to IR
    let cfg = sb_config::Config::load(&args.config)?;
    cfg.validate()?;
    let ir = sb_config::present::to_ir(&cfg)?;

    println!("transport-plan for: {}", args.config.display());
    for ob in &ir.outbounds {
        let name = ob.name.clone().unwrap_or_else(|| ob.ty_str().to_string());
        let kind = ob.ty_str();
        let chain = sb_core::runtime::transport::map::chain_from_ir(ob);
        let sni = ob.tls_sni.clone().unwrap_or_default();
        let alpn = ob.tls_alpn.clone().unwrap_or_default();
        println!(
            "- outbound: {name}\n  kind: {kind}\n  chain: [{chain}]\n  sni: {sni}\n  alpn: {alpn}",
            name = name,
            kind = kind,
            chain = chain.join(","),
            sni = sni,
            alpn = alpn,
        );
    }

    Ok(())
}

