use crate::cli::{output, Format, GlobalArgs};
use crate::config_loader;
use anyhow::{Context, Result};
use clap::Parser;
use sb_core::routing::ExplainEngine;

#[derive(Parser, Debug, Clone)]
pub struct RouteArgs {
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
    /// Include detailed trace information (adds 'trace' field to output without changing core fields: dest, `matched_rule`, chain, outbound)
    #[arg(long = "with-trace", alias = "trace", default_value_t = false)]
    pub with_trace: bool,
}

pub fn run(global: &GlobalArgs, args: RouteArgs) -> Result<()> {
    let entries = config_loader::collect_config_entries(&global.config, &global.config_directory)?;
    let cfg =
        config_loader::load_config(&entries).with_context(|| "load config for route explain")?;

    if args.explain {
        // Use real ExplainEngine instead of stub
        let engine = ExplainEngine::from_config(&cfg)
            .with_context(|| "create explain engine from config")?;
        let net = if args.udp { "udp" } else { "tcp" };
        let result = engine.explain_with_network(&args.dest, net, args.with_trace);

        output::emit(
            args.format,
            || {
                format!(
                    "{} → {} (rule={})",
                    result.dest, result.outbound, result.matched_rule
                )
            },
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
