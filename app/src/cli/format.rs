//! Config formatter subcommand (parity with sing-box `format`)
//! - Supports multiple `-c/--config` files
//! - Supports multiple `-C/--config-directory` directories (non-recursive)
//! - `-w/--write` to write in-place; otherwise prints to stdout

use crate::cli::output;
use crate::cli::Format as OutFormat;
use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug, Clone)]
#[command(name = "format")]
#[command(about = "Format configuration", long_about = None)]
pub struct FormatArgs {
    /// Configuration file path(s)
    #[arg(short = 'c', long = "config")]
    pub config: Vec<PathBuf>,

    /// Configuration directory path(s) (non-recursive)
    #[arg(short = 'C', long = "config-directory")]
    pub config_directory: Vec<PathBuf>,

    /// Write result to (source) file instead of stdout
    #[arg(short = 'w', long = "write")]
    pub write: bool,
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    pub help_json: bool,
}

pub fn run(args: FormatArgs) -> Result<()> {
    if args.help_json {
        crate::cli::help::print_help_json::<FormatArgs>();
    }

    let mut entries = Vec::new();

    // Gather files from -c/--config
    for p in &args.config {
        if p.is_file() {
            entries.push(p.clone());
        } else {
            anyhow::bail!("config path not found: {}", p.display());
        }
    }

    // Gather files from -C/--config-directory (non-recursive, *.json)
    for d in &args.config_directory {
        let meta = fs::metadata(d).with_context(|| format!("stat: {}", d.display()))?;
        if !meta.is_dir() {
            anyhow::bail!("not a directory: {}", d.display());
        }
        for ent in fs::read_dir(d).with_context(|| format!("read_dir: {}", d.display()))? {
            let ent = ent?;
            let path = ent.path();
            if let Some(ext) = path.extension() {
                if ext == "json" && path.is_file() {
                    entries.push(path);
                }
            }
        }
    }

    if entries.is_empty() {
        // Default to config.json if nothing specified (matches upstream default behavior)
        let default = PathBuf::from("config.json");
        if default.exists() {
            entries.push(default);
        } else {
            // Nothing to do
            return Ok(());
        }
    }

    let multi = entries.len() > 1;
    for path in entries {
        format_one(&path, args.write, multi)?;
    }

    Ok(())
}

fn format_one(path: &Path, write: bool, multi: bool) -> Result<()> {
    let orig = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let val: serde_json::Value =
        serde_json::from_slice(&orig).with_context(|| format!("parse JSON: {}", path.display()))?;

    // Pretty-print with 2 spaces to match upstream
    let formatted = serde_json::to_string_pretty(&val).context("encode pretty JSON")?;

    if write {
        // Only write when changed
        if let Ok(orig_str) = std::str::from_utf8(&orig) {
            if normalize(orig_str) == normalize(&formatted) {
                return Ok(());
            }
        }
        fs::write(path, formatted.as_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        // Print absolute path to stderr like upstream
        if let Ok(abs) = path.canonicalize() {
            eprintln!("{}", abs.display());
        } else {
            eprintln!("{}", path.display());
        }
    } else {
        // Print absolute path prefix when multiple inputs
        if multi {
            let head = if let Ok(abs) = path.canonicalize() {
                abs.display().to_string()
            } else {
                path.display().to_string()
            };
            output::emit(
                OutFormat::Human,
                || head,
                &serde_json::json!({"path": path.display().to_string()}),
            );
        }
        output::emit(
            OutFormat::Human,
            || format!("{formatted}\n"),
            &serde_json::json!({"formatted": val}),
        );
    }
    Ok(())
}

fn normalize(s: &str) -> String {
    // Remove trailing whitespace-only differences for change detection
    s.replace('\r', "").trim_end().to_string()
}
