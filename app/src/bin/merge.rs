//! Merge configurations (parity with sing-box `merge <output-path>`)
//! - Accepts multiple `-c/--config` files and `-C/--config-directory` directories
//! - Merges JSON with stable ordering: objects merged (arrays concatenated, objects deep-merged, scalars overridden by later files)
//! - Writes pretty JSON to output path; prints the absolute output path to stderr when writing

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "merge")]
#[command(about = "Merge configurations", long_about = None)]
struct Args {
    /// Configuration file path(s)
    #[arg(short = 'c', long = "config")]
    config: Vec<PathBuf>,

    /// Configuration directory path(s) (non-recursive)
    #[arg(short = 'C', long = "config-directory")]
    config_directory: Vec<PathBuf>,

    /// Output file path
    #[arg(value_name = "OUTPUT_PATH")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
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
    let mut merged = merged;
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
            .filter_map(|e| e.ok())
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
                    map.insert("certificate".to_string(), V::Array(lines.into_iter().map(V::String).collect()));
                }
            }
            if let Some(V::String(path)) = map.get("key_path") {
                if let Some(lines) = read_path_lines(path) {
                    map.insert("key".to_string(), V::Array(lines.into_iter().map(V::String).collect()));
                }
            }
            // SSH private key path
            if let Some(V::String(path)) = map.get("private_key_path") {
                if let Some(lines) = read_path_lines(path) {
                    map.insert("private_key".to_string(), V::Array(lines.into_iter().map(V::String).collect()));
                }
            }
            // ECH nested object
            if let Some(ech) = map.get_mut("ech") {
                if let V::Object(ech_map) = ech {
                    if let Some(V::String(path)) = ech_map.get("key_path") {
                        if let Some(lines) = read_path_lines(path) {
                            ech_map.insert("key".to_string(), V::Array(lines.into_iter().map(V::String).collect()));
                        }
                    }
                    if let Some(V::String(path)) = ech_map.get("config_path") {
                        if let Some(lines) = read_path_lines(path) {
                            ech_map.insert("config".to_string(), V::Array(lines.into_iter().map(V::String).collect()));
                        }
                    }
                }
            }
            // Recurse into children
            for (_k, child) in map.iter_mut() {
                inline_path_resources(child);
            }
        }
        V::Array(arr) => {
            for child in arr.iter_mut() {
                inline_path_resources(child);
            }
        }
        _ => {}
    }
}

fn read_path_lines(path: &str) -> Option<Vec<String>> {
    let expanded = expand_env(path);
    match std::fs::read_to_string(&expanded) {
        Ok(content) => {
            let lines: Vec<String> = content
                .lines()
                .map(|s| s.trim_end().to_string())
                .filter(|s| !s.trim().is_empty())
                .collect();
            Some(lines)
        }
        Err(_) => None,
    }
}

fn expand_env(s: &str) -> String {
    // Simple $VAR expansion; ${VAR} also supported
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                if let Some(end) = s[i + 2..].find('}') {
                    let var = &s[i + 2..i + 2 + end];
                    out.push_str(&std::env::var(var).unwrap_or_default());
                    i += end + 3; // skip ${VAR}
                    continue;
                }
            }
            // $VAR
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b'_' || bytes[j].is_ascii_alphanumeric()) {
                j += 1;
            }
            if j > i + 1 {
                let var = &s[i + 1..j];
                out.push_str(&std::env::var(var).unwrap_or_default());
                i = j;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
