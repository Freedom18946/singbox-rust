//! Config formatter subcommand (parity with sing-box `format`)
//! - Supports multiple `-c/--config` files
//! - Supports multiple `-C/--config-directory` directories (non-recursive)
//! - `-w/--write` to write in-place; otherwise prints to stdout

use crate::cli::output;
use crate::cli::Format as OutFormat;
use crate::cli::GlobalArgs;
use crate::config_loader::{self, ConfigEntry, ConfigSource};
use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use std::fs;
use std::io::Read;

#[derive(Parser, Debug, Clone)]
#[command(name = "format")]
#[command(about = "Format configuration", long_about = None)]
pub struct FormatArgs {
    /// Write result to (source) file instead of stdout
    #[arg(short = 'w', long = "write")]
    pub write: bool,
    /// Print help information in JSON format and exit
    #[arg(long = "help-json", action = ArgAction::SetTrue)]
    pub help_json: bool,
}

pub fn run(global: &GlobalArgs, args: FormatArgs) -> Result<()> {
    if args.help_json {
        crate::cli::help::print_help_json::<FormatArgs>();
    }

    let entries =
        config_loader::collect_config_entries(&global.config, &global.config_directory)?;
    if entries.is_empty() {
        return Ok(());
    }
    let mut stdin_cache = None::<Vec<u8>>;
    let multi = entries.len() > 1;
    for entry in entries {
        format_one(&entry, args.write, multi, &mut stdin_cache)?;
    }

    Ok(())
}

fn format_one(
    entry: &ConfigEntry,
    write: bool,
    multi: bool,
    stdin_cache: &mut Option<Vec<u8>>,
) -> Result<()> {
    let orig = match &entry.source {
        ConfigSource::File(path) => {
            fs::read(path).with_context(|| format!("read {}", path.display()))?
        }
        ConfigSource::Stdin => {
            if let Some(cached) = stdin_cache.as_ref() {
                cached.clone()
            } else {
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .context("read config from stdin")?;
                *stdin_cache = Some(buf.clone());
                buf
            }
        }
    };
    let val: serde_json::Value =
        serde_json::from_slice(&orig).with_context(|| format!("parse JSON: {}", entry.path))?;

    // Pretty-print with 2 spaces to match upstream
    let formatted = serde_json::to_string_pretty(&val).context("encode pretty JSON")?;

    if write {
        // Only write when changed
        if let Ok(orig_str) = std::str::from_utf8(&orig) {
            if normalize(orig_str) == normalize(&formatted) {
                return Ok(());
            }
        }
        if let ConfigSource::File(path) = &entry.source {
            fs::write(path, formatted.as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
        } else {
            fs::write(&entry.path, formatted.as_bytes())
                .with_context(|| format!("write {}", entry.path))?;
        }
        // Print absolute path to stderr like upstream
        if let ConfigSource::File(path) = &entry.source {
            if let Ok(abs) = path.canonicalize() {
                eprintln!("{}", abs.display());
            } else {
                eprintln!("{}", path.display());
            }
        } else {
            eprintln!("{}", entry.path);
        }
    } else {
        // Print absolute path prefix when multiple inputs
        if multi {
            let head = if let ConfigSource::File(path) = &entry.source {
                if let Ok(abs) = path.canonicalize() {
                    abs.display().to_string()
                } else {
                    path.display().to_string()
                }
            } else {
                entry.path.clone()
            };
            output::emit(
                OutFormat::Human,
                || head,
                &serde_json::json!({"path": entry.path.clone()}),
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
