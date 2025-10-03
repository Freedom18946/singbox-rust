//! Rule-Set management CLI tool
//!
//! Provides utilities for working with sing-box rule-sets:
//! - Validate JSON rule-sets
//! - Inspect binary .srs files
//! - Show rule-set information

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ruleset")]
#[command(about = "Rule-Set management tool", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate a rule-set file (JSON or binary)
    Validate {
        /// Path to rule-set file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Show information about a rule-set file
    Info {
        /// Path to rule-set file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },

    /// Format a JSON rule-set (prettify)
    Format {
        /// Path to JSON rule-set file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Validate { file } => validate_ruleset(file).await,
        Commands::Info { file } => show_info(file).await,
        Commands::Format { file, output } => format_ruleset(file, output).await,
    }
}

/// Validate a rule-set file
async fn validate_ruleset(file: PathBuf) -> Result<()> {
    use sb_core::router::ruleset::{binary, source};

    println!("Validating rule-set: {}", file.display());

    // Detect format from file extension
    let format = source::infer_format_from_path(file.to_str().unwrap_or(""))
        .context("Failed to detect rule-set format (use .srs or .json extension)")?;

    println!("Format: {:?}", format);

    // Load and parse
    let ruleset = binary::load_from_file(&file, format)
        .await
        .context("Failed to load rule-set")?;

    println!("✓ Rule-set is valid!");
    println!("  Rules: {}", ruleset.rules.len());
    println!("  Version: {}", ruleset.version);

    if let Some(ref etag) = ruleset.etag {
        println!("  ETag: {}", etag);
    }

    Ok(())
}

/// Show detailed information about a rule-set
async fn show_info(file: PathBuf) -> Result<()> {
    use sb_core::router::ruleset::{binary, source, Rule};

    let format = source::infer_format_from_path(file.to_str().unwrap_or(""))
        .context("Failed to detect rule-set format (use .srs or .json extension)")?;

    let ruleset = binary::load_from_file(&file, format)
        .await
        .context("Failed to load rule-set")?;

    println!("Rule-Set Information");
    println!("====================");
    println!("File: {}", file.display());
    println!("Format: {:?}", ruleset.format);
    println!("Version: {}", ruleset.version);
    println!("Total Rules: {}", ruleset.rules.len());

    // Count rule types
    let mut default_count = 0;
    let mut logical_count = 0;

    for rule in &ruleset.rules {
        match rule {
            Rule::Default(_) => default_count += 1,
            Rule::Logical(_) => logical_count += 1,
        }
    }

    println!("  Default Rules: {}", default_count);
    println!("  Logical Rules: {}", logical_count);

    println!("Domain Index: Optimized matching enabled");
    println!("IP Prefix Tree: Optimized CIDR matching");

    if let Some(ref etag) = ruleset.etag {
        println!("ETag: {}", etag);
    }

    println!("Last Updated: {:?}", ruleset.last_updated);

    Ok(())
}

/// Format a JSON rule-set (prettify)
async fn format_ruleset(file: PathBuf, output: Option<PathBuf>) -> Result<()> {
    use std::fs;

    // Read JSON file
    let data = fs::read(&file)
        .context("Failed to read file")?;

    let json_str = std::str::from_utf8(&data)
        .context("Invalid UTF-8 in file")?;

    // Parse as JSON value
    let value: serde_json::Value = serde_json::from_str(json_str)
        .context("Invalid JSON format")?;

    // Pretty-print
    let formatted = serde_json::to_string_pretty(&value)
        .context("Failed to format JSON")?;

    // Output
    if let Some(output_file) = output {
        fs::write(&output_file, formatted)
            .context("Failed to write output file")?;
        println!("✓ Formatted rule-set written to: {}", output_file.display());
    } else {
        println!("{}", formatted);
    }

    Ok(())
}
