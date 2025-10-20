use anyhow::{Context, Result};
use clap::Parser;
use sb_core::routing::ExplainEngine;
use crate::cli::{output, Format};

#[derive(Parser, Debug, Clone)]
pub struct RouteArgs {
    /// Path to config file
    #[arg(short = 'c', long = "config")]
    pub config: String,
    /// Destination host:port or ip
    #[arg(long = "dest")]
    pub dest: String,
    /// Use UDP path
    #[arg(long = "udp", default_value_t = false)]
    pub udp: bool,
    /// Output format
    #[arg(long = "format", value_enum, default_value_t = Format::Human)]
    pub format: Format,
    /// Explain routing decision with matched rule and chain
    #[arg(long = "explain", default_value_t = false)]
    pub explain: bool,
    /// Include detailed trace information (adds 'trace' field to output without changing core fields: dest, matched_rule, chain, outbound)
    #[arg(long = "with-trace", alias = "trace", default_value_t = false)]
    pub with_trace: bool,
}

pub fn run(args: RouteArgs) -> Result<()> {
    // Load and parse config file (support both JSON and YAML)
    let cfg = if args.config.ends_with(".yaml") || args.config.ends_with(".yml") {
        let data = std::fs::read_to_string(&args.config)
            .with_context(|| format!("read config {}", &args.config))?;
        serde_yaml::from_str::<sb_config::Config>(&data).with_context(|| "parse config as yaml")?
    } else {
        sb_config::Config::load(&args.config)
            .with_context(|| format!("load config from {}", &args.config))?
    };

    if args.explain {
        // Use real ExplainEngine instead of stub
        let engine = ExplainEngine::from_config(&cfg)
            .with_context(|| "create explain engine from config")?;
        let result = engine.explain(&args.dest, args.with_trace);

        output::emit(
            args.format,
            || format!("{} → {} (rule={})", result.dest, result.outbound, result.matched_rule),
            &result,
        );
    } else {
        // Keep simple OK output for non-explain path
        output::emit(
            args.format,
            || "OK".to_string(),
            &serde_json::json!({"ok": true}),
        );
    }
    Ok(())
}
