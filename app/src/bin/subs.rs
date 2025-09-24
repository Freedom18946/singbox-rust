use clap::{Parser, Subcommand};
use sb_core::subscribe::{diff, merge};
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

fn read_json(p: &str) -> Value {
    let b = fs::read(p).expect("read file");
    serde_json::from_slice(&b).expect("parse json")
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Merge { base, extras, out } => {
            let base = read_json(&base);
            let extras_v = extras.iter().map(|p| read_json(p)).collect::<Vec<_>>();
            let (merged, mres) = merge(base, &extras_v);
            fs::write(&out, serde_json::to_string_pretty(&merged).unwrap()).expect("write out");
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "task":"subs.merge",
                "out": out,
                "added":{"inbounds":mres.added_inbounds,"outbounds":mres.added_outbounds,"rules":mres.added_rules}
            })).unwrap());
        }
        Cmd::Diff { old, new } => {
            let o = read_json(&old);
            let n = read_json(&new);
            let d = diff(&o, &n);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "task":"subs.diff",
                    "added": d.added,
                    "removed": d.removed
                }))
                .unwrap()
            );
        }
    }
}
