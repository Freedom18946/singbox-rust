//! Config merge subcommand (parity with sing-box `merge`)

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::fs;
use std::path::PathBuf;

use crate::cli::GlobalArgs;
use crate::config_loader;

#[derive(Parser, Debug, Clone)]
#[command(name = "merge")]
#[command(about = "Merge configurations", long_about = None)]
pub struct MergeArgs {
    /// Output file path
    #[arg(value_name = "OUTPUT_PATH")]
    pub output: PathBuf,
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    pub help_json: bool,
}

pub fn run(global: &GlobalArgs, args: MergeArgs) -> Result<()> {
    if args.help_json {
        crate::cli::help::print_help_json::<MergeArgs>();
    }

    let entries = config_loader::collect_config_entries(&global.config, &global.config_directory)?;
    let mut merged = config_loader::load_merged_value(&entries)?;

    // Inline known path resources for TLS/ECH/SSH compatibility
    inline_path_resources(&mut merged);

    // Pretty output
    let output_pretty = serde_json::to_string_pretty(&merged).context("encode merged JSON")?;

    // Only write if changed
    let need_write = match fs::read(&args.output) {
        Ok(existing) => match std::str::from_utf8(&existing) {
            Ok(s) => normalize(s) != normalize(&output_pretty),
            Err(_) => true,
        },
        Err(_) => true,
    };

    if need_write {
        if let Some(parent) = args.output.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        fs::write(&args.output, output_pretty.as_bytes())
            .with_context(|| format!("write {}", args.output.display()))?;
        // Print abs path to stderr
        if let Ok(abs) = args.output.canonicalize() {
            eprintln!("{}", abs.display());
        } else {
            eprintln!("{}", args.output.display());
        }
    }

    Ok(())
}

fn normalize(s: &str) -> String {
    s.replace('\r', "").trim_end().to_string()
}

/// Inline known path resources (TLS cert/key, ECH config/key, SSH private key)
fn inline_path_resources(v: &mut serde_json::Value) {
    use serde_json::Value as V;
    match v {
        V::Object(map) => {
            // Handle TLS certificate/key paths at this level
            if let Some(V::String(path)) = map.get("certificate_path") {
                if let Some(lines) = read_path_lines(path) {
                    map.insert(
                        "certificate".to_string(),
                        V::Array(lines.into_iter().map(V::String).collect()),
                    );
                }
            }
            if let Some(V::String(path)) = map.get("key_path") {
                if let Some(lines) = read_path_lines(path) {
                    map.insert(
                        "key".to_string(),
                        V::Array(lines.into_iter().map(V::String).collect()),
                    );
                }
            }
            // SSH private key path
            if let Some(V::String(path)) = map.get("private_key_path") {
                if let Some(lines) = read_path_lines(path) {
                    map.insert(
                        "private_key".to_string(),
                        V::Array(lines.into_iter().map(V::String).collect()),
                    );
                }
            }
            // ECH nested object
            if let Some(V::Object(ech_map)) = map.get_mut("ech") {
                if let Some(V::String(path)) = ech_map.get("key_path") {
                    if let Some(lines) = read_path_lines(path) {
                        ech_map.insert(
                            "key".to_string(),
                            V::Array(lines.into_iter().map(V::String).collect()),
                        );
                    }
                }
                if let Some(V::String(path)) = ech_map.get("config_path") {
                    if let Some(lines) = read_path_lines(path) {
                        ech_map.insert(
                            "config".to_string(),
                            V::Array(lines.into_iter().map(V::String).collect()),
                        );
                    }
                }
            }

            for value in map.values_mut() {
                inline_path_resources(value);
            }
        }
        V::Array(arr) => {
            for v in arr {
                inline_path_resources(v);
            }
        }
        _ => {}
    }
}

fn read_path_lines(path: &str) -> Option<Vec<String>> {
    let content = fs::read_to_string(path).ok()?;
    Some(content.lines().map(|s| s.trim_end().to_string()).collect())
}
