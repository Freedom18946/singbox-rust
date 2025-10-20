//! Config merge subcommand (parity with sing-box `merge`)

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "merge")]
#[command(about = "Merge configurations", long_about = None)]
pub struct MergeArgs {
    /// Configuration file path(s)
    #[arg(short = 'c', long = "config")]
    pub config: Vec<PathBuf>,

    /// Configuration directory path(s) (non-recursive)
    #[arg(short = 'C', long = "config-directory")]
    pub config_directory: Vec<PathBuf>,

    /// Output file path
    #[arg(value_name = "OUTPUT_PATH")]
    pub output: PathBuf,
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    pub help_json: bool,
}

pub fn run(args: MergeArgs) -> Result<()> {
    if args.help_json {
        crate::cli::help::print_help_json::<MergeArgs>();
    }

    let mut entries = collect_inputs(&args.config, &args.config_directory)?;

    if entries.is_empty() {
        // Default to config.json similar to upstream behavior
        let default = PathBuf::from("config.json");
        if default.exists() {
            entries.push(default);
        } else {
            // Nothing to do
            return Ok(());
        }
    }

    // Stable sort by path for reproducibility
    entries.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    // Merge all
    let mut merged = serde_json::Value::Null;
    for path in entries {
        let content = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let json: serde_json::Value = serde_json::from_slice(&content)
            .with_context(|| format!("parse JSON: {}", path.display()))?;
        merged = merge_values(merged, json);
    }

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

fn collect_inputs(files: &[PathBuf], dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in files {
        if p.is_file() {
            out.push(p.clone());
        } else {
            anyhow::bail!("config path not found: {}", p.display());
        }
    }
    for d in dirs {
        let meta = fs::metadata(d).with_context(|| format!("stat: {}", d.display()))?;
        if !meta.is_dir() {
            anyhow::bail!("not a directory: {}", d.display());
        }
        let mut dir_files: Vec<PathBuf> = fs::read_dir(d)
            .with_context(|| format!("read_dir: {}", d.display()))?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
            .collect();
        dir_files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        out.extend(dir_files);
    }
    Ok(out)
}

fn normalize(s: &str) -> String {
    s.replace('\r', "").trim_end().to_string()
}

fn merge_values(base: serde_json::Value, next: serde_json::Value) -> serde_json::Value {
    use serde_json::Value as V;
    match (base, next) {
        (V::Object(mut a), V::Object(b)) => {
            for (k, vb) in b {
                if let Some(va) = a.remove(&k) {
                    a.insert(k, merge_values(va, vb));
                } else {
                    a.insert(k, vb);
                }
            }
            V::Object(a)
        }
        (V::Array(mut a), V::Array(b)) => {
            a.extend(b);
            V::Array(a)
        }
        // Prefer non-null when encountering null vs array/object
        (V::Null, x) => x,
        (_a, b) => b, // scalars and mismatched types: next overrides
    }
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
