use clap::{Parser, Subcommand};
use sb_subscribe::config_merge::{diff, merge};
use serde_json::Value;
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "subs")]
#[command(about = "Subscription utilities: merge/diff")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Merge multiple config fragments into one. Example:
    /// subs merge base.json extra1.json extra2.json -o merged.json
    Merge {
        base: String,
        extras: Vec<String>,
        #[arg(short = 'o', long = "out")]
        out: String,
    },
    /// Diff two configs. Example: subs diff old.json new.json
    Diff { old: String, new: String },
}

fn read_json(p: &str) -> anyhow::Result<Value> {
    let bytes = fs::read(p).map_err(|err| anyhow::anyhow!("failed to read {p}: {err}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| anyhow::anyhow!("failed to parse JSON from {p}: {err}"))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Merge { base, extras, out } => {
            let base = read_json(&base)?;
            let extras_v = extras
                .iter()
                .map(|p| read_json(p))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let (merged, mres) = merge(base, &extras_v);
            let merged_json = serde_json::to_string_pretty(&merged)?;
            fs::write(&out, merged_json)
                .map_err(|err| anyhow::anyhow!("failed to write {out}: {err}"))?;
            let report = serde_json::json!({
                "task":"subs.merge",
                "out": out,
                "added":{"inbounds":mres.added_inbounds,"outbounds":mres.added_outbounds,"rules":mres.added_rules}
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Cmd::Diff { old, new } => {
            let o = read_json(&old)?;
            let n = read_json(&new)?;
            let d = diff(&o, &n);
            let report = serde_json::json!({
                "task":"subs.diff",
                "added": d.added,
                "removed": d.removed
            });
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}
