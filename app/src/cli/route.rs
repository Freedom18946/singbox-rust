use anyhow::{Context, Result};
use clap::Parser;
use sb_core::routing::explain::{ExplainEngine, ExplainResult};
use sb_core::routing::trace::Trace;

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
    #[arg(long = "format", default_value = "text")]
    pub format: String,
    /// Explain
    #[arg(long = "explain", default_value_t = false)]
    pub explain: bool,
    /// Include detailed trace (opt-in; contract fields不变；仅额外增加 trace)
    #[arg(long = "trace", default_value_t = false)]
    pub trace: bool,
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
        let result = engine.explain(&args.dest, args.trace);

        if args.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "dest={} matched_rule={} chain={:?} outbound={}",
                result.dest, result.matched_rule, result.chain, result.outbound
            );
            if let Some(trace) = &result.trace {
                println!("trace: {} steps", trace.steps.len());
            }
        }
    } else {
        println!("OK");
    }
    Ok(())
}
