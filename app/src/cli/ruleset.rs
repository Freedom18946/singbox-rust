//! Rule-set management subcommand (parity with sing-box `rule-set`)

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ruleset")]
#[command(about = "Rule-Set management tool", long_about = None)]
pub struct RulesetArgs {
    #[command(subcommand)]
    pub command: RulesetCmd,
}

#[derive(Subcommand, Debug)]
pub enum RulesetCmd {
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

    /// Decompile a binary .srs file into JSON source format
    Decompile {
        /// Path to .srs file
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Match helper: test whether a domain/IP/port matches the rule-set
    Match {
        /// Path to rule-set file (.srs or .json)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Domain name to test (e.g., example.com)
        #[arg(long)]
        domain: Option<String>,

        /// Destination IP to test
        #[arg(long)]
        ip: Option<String>,

        /// Destination port to test (default: 443)
        #[arg(long, default_value_t = 443u16)]
        port: u16,

        /// Network type (tcp/udp)
        #[arg(long)]
        network: Option<String>,
    },

    /// Compile a JSON rule-set into binary .srs
    Compile {
        /// Input JSON rule-set
        #[arg(value_name = "INPUT_JSON")]
        input: PathBuf,
        /// Output .srs file
        #[arg(value_name = "OUTPUT_SRS")]
        output: PathBuf,
        /// Version to write (default: from JSON or current)
        #[arg(long)]
        version: Option<u8>,
    },

    /// Convert between JSON and SRS formats based on extension
    Convert {
        /// Input file (.json or .srs)
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output file (.json or .srs)
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
        /// Version to write when output is SRS
        #[arg(long)]
        version: Option<u8>,
    },

    /// Merge multiple rule-set files (append rules) and write to output
    Merge {
        /// Input files (.json or .srs)
        #[arg(value_name = "INPUTS")]
        inputs: Vec<PathBuf>,
        /// Output file (.json or .srs)
        #[arg(short, long)]
        output: PathBuf,
        /// Version to write when output is SRS
        #[arg(long)]
        version: Option<u8>,
    },
    /// Upgrade rule-set version (JSON or SRS input)
    Upgrade {
        /// Input file (.json or .srs)
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output file (.json or .srs)
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
        /// Target version (default: current)
        #[arg(long)]
        version: Option<u8>,
    },
}

pub async fn run(args: RulesetArgs) -> Result<()> {
    match args.command {
        RulesetCmd::Validate { file } => validate_ruleset(file).await,
        RulesetCmd::Info { file } => show_info(file).await,
        RulesetCmd::Format { file, output } => format_ruleset(file, output).await,
        RulesetCmd::Decompile { file, output } => decompile_ruleset(file, output).await,
        RulesetCmd::Match {
            file,
            domain,
            ip,
            port,
            network,
        } => match_ruleset(file, domain, ip, port, network).await,
        RulesetCmd::Compile {
            input,
            output,
            version,
        } => compile_ruleset(input, output, version).await,
        RulesetCmd::Convert {
            input,
            output,
            version,
        } => convert_ruleset(input, output, version).await,
        RulesetCmd::Merge {
            inputs,
            output,
            version,
        } => merge_rulesets(inputs, output, version).await,
        RulesetCmd::Upgrade {
            input,
            output,
            version,
        } => upgrade_ruleset(input, output, version).await,
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
    let data = fs::read(&file).context("Failed to read file")?;

    let json_str = std::str::from_utf8(&data).context("Invalid UTF-8 in file")?;

    // Parse as JSON value
    let value: serde_json::Value = serde_json::from_str(json_str).context("Invalid JSON format")?;

    // Pretty-print
    let formatted = serde_json::to_string_pretty(&value).context("Failed to format JSON")?;

    // Output
    if let Some(output_file) = output {
        fs::write(&output_file, formatted).context("Failed to write output file")?;
        println!("✓ Formatted rule-set written to: {}", output_file.display());
    } else {
        println!("{}", formatted);
    }

    Ok(())
}

/// Decompile a binary .srs file into JSON source format expected by our parser
async fn decompile_ruleset(file: PathBuf, output: Option<PathBuf>) -> Result<()> {
    use sb_core::router::ruleset::{binary, source, RuleSetFormat};
    use std::fs;

    // Infer format and ensure it's binary; if JSON, just pretty-print
    let fmt = source::infer_format_from_path(file.to_str().unwrap_or(""))
        .context("Failed to infer input format")?;

    let value = match fmt {
        RuleSetFormat::Source => {
            // Already JSON: pretty format through formatter
            let data = fs::read(&file).context("read input JSON")?;
            let v: serde_json::Value = serde_json::from_slice(&data).context("parse input JSON")?;
            v
        }
        RuleSetFormat::Binary => {
            let ruleset = binary::load_from_file(&file, RuleSetFormat::Binary)
                .await
                .context("Failed to load SRS file")?;

            // Build JSON value: {"version": N, "rules": [ ... ]}
            let mut rules_json = Vec::new();
            for r in &ruleset.rules {
                rules_json.push(rule_to_json(r));
            }
            serde_json::json!({
                "version": ruleset.version,
                "rules": rules_json,
            })
        }
    };

    let pretty = serde_json::to_string_pretty(&value).context("format output JSON")?;
    if let Some(out) = output {
        fs::write(&out, pretty).context("write output file")?;
        println!("{}", out.display());
    } else {
        println!("{}", pretty);
    }
    Ok(())
}

fn rule_to_json(rule: &sb_core::router::ruleset::Rule) -> serde_json::Value {
    use sb_core::router::ruleset::{DomainRule, LogicalMode, Rule};
    match rule {
        Rule::Default(r) => {
            let mut domain_exact = Vec::new();
            let mut domain_suffix = r.domain_suffix.clone();
            let mut domain_keyword = r.domain_keyword.clone();
            let mut domain_regex = r.domain_regex.clone();
            for d in &r.domain {
                match d {
                    DomainRule::Exact(s) => domain_exact.push(s.clone()),
                    DomainRule::Suffix(s) => {
                        if !domain_suffix.contains(s) {
                            domain_suffix.push(s.clone());
                        }
                    }
                    DomainRule::Keyword(s) => {
                        if !domain_keyword.contains(s) {
                            domain_keyword.push(s.clone());
                        }
                    }
                    DomainRule::Regex(s) => {
                        if !domain_regex.contains(s) {
                            domain_regex.push(s.clone());
                        }
                    }
                }
            }

            let ip_cidr: Vec<String> = r
                .ip_cidr
                .iter()
                .map(|c| match c.addr {
                    std::net::IpAddr::V4(v4) => format!("{}/{}", v4, c.prefix_len),
                    std::net::IpAddr::V6(v6) => format!("{}/{}", v6, c.prefix_len),
                })
                .collect();

            let mut obj = serde_json::json!({});
            if r.invert {
                obj["invert"] = serde_json::json!(true);
            }
            if !domain_exact.is_empty() {
                let mut v = domain_exact;
                v.sort();
                obj["domain"] = serde_json::json!(v);
            }
            if !domain_suffix.is_empty() {
                let mut v = domain_suffix;
                v.sort();
                obj["domain_suffix"] = serde_json::json!(v);
            }
            if !domain_keyword.is_empty() {
                let mut v = domain_keyword;
                v.sort();
                obj["domain_keyword"] = serde_json::json!(v);
            }
            if !domain_regex.is_empty() {
                let mut v = domain_regex;
                v.sort();
                obj["domain_regex"] = serde_json::json!(v);
            }
            if !ip_cidr.is_empty() {
                obj["ip_cidr"] = serde_json::json!(ip_cidr);
            }
            if !r.port.is_empty() {
                obj["port"] = serde_json::json!(r.port);
            }
            if !r.port_range.is_empty() {
                obj["port_range"] = serde_json::json!(r.port_range);
            }
            if !r.network.is_empty() {
                obj["network"] = serde_json::json!(r.network);
            }
            if !r.process_name.is_empty() {
                obj["process_name"] = serde_json::json!(r.process_name);
            }
            if !r.process_path.is_empty() {
                obj["process_path"] = serde_json::json!(r.process_path);
            }
            if !r.process_path_regex.is_empty() {
                obj["process_path_regex"] = serde_json::json!(r.process_path_regex);
            }
            obj
        }
        Rule::Logical(r) => {
            let rules: Vec<_> = r.rules.iter().map(rule_to_json).collect();
            let mode = match r.mode {
                LogicalMode::And => "and",
                LogicalMode::Or => "or",
            };
            let mut obj = serde_json::json!({
                "type": "logical",
                "mode": mode,
                "rules": rules,
            });
            if r.invert {
                obj["invert"] = serde_json::json!(true);
            }
            obj
        }
    }
}

/// Test whether a flow matches the rule-set
async fn match_ruleset(
    file: PathBuf,
    domain: Option<String>,
    ip: Option<String>,
    port: u16,
    network: Option<String>,
) -> Result<()> {
    use sb_core::router::ruleset::{binary, source};

    let fmt = source::infer_format_from_path(file.to_str().unwrap_or(""))
        .context("Failed to infer input format")?;
    let ruleset = binary::load_from_file(&file, fmt)
        .await
        .context("load rule-set")?;
    let ruleset = std::sync::Arc::new(ruleset);
    let matcher = sb_core::router::ruleset::matcher::RuleMatcher::new(ruleset);

    let dest_ip = match ip.as_deref() {
        Some(s) => Some(s.parse::<std::net::IpAddr>().context("invalid ip")?),
        None => None,
    };
    let ctx = sb_core::router::ruleset::matcher::MatchContext {
        domain,
        destination_ip: dest_ip,
        destination_port: port,
        network,
        process_name: None,
        process_path: None,
        source_ip: None,
        source_port: None,
    };
    let matched = matcher.matches(&ctx);
    println!("matched: {}", matched);
    Ok(())
}

async fn compile_ruleset(input: PathBuf, output: PathBuf, version: Option<u8>) -> Result<()> {
    use sb_core::router::ruleset::{binary, source, RuleSetFormat};
    // Load JSON ruleset via binary::load_from_file(Source)
    let fmt = source::infer_format_from_path(input.to_str().unwrap_or(""))
        .ok_or_else(|| anyhow::anyhow!("cannot infer input format"))?;
    if fmt != RuleSetFormat::Source {
        anyhow::bail!("compile expects JSON input (.json)");
    }
    let rs = binary::load_from_file(&input, RuleSetFormat::Source).await?;
    let ver = version.unwrap_or(
        rs.version
            .max(sb_core::router::ruleset::RULESET_VERSION_CURRENT),
    );
    binary::write_to_file(&output, &rs.rules, ver).await?;
    println!("{}", output.display());
    Ok(())
}

async fn convert_ruleset(input: PathBuf, output: PathBuf, version: Option<u8>) -> Result<()> {
    use sb_core::router::ruleset::{binary, source, RuleSetFormat};
    let in_fmt = source::infer_format_from_path(input.to_str().unwrap_or(""))
        .ok_or_else(|| anyhow::anyhow!("cannot infer input format"))?;
    let out_fmt = source::infer_format_from_path(output.to_str().unwrap_or(""))
        .ok_or_else(|| anyhow::anyhow!("cannot infer output format"))?;
    match (in_fmt, out_fmt) {
        (RuleSetFormat::Source, RuleSetFormat::Binary) => {
            let rs = binary::load_from_file(&input, RuleSetFormat::Source).await?;
            let ver = version.unwrap_or(
                rs.version
                    .max(sb_core::router::ruleset::RULESET_VERSION_CURRENT),
            );
            binary::write_to_file(&output, &rs.rules, ver).await?;
        }
        (RuleSetFormat::Binary, RuleSetFormat::Source) => {
            decompile_ruleset(input, Some(output)).await?;
        }
        _ => anyhow::bail!("convert requires changing format (.json <-> .srs)"),
    }
    Ok(())
}

async fn merge_rulesets(inputs: Vec<PathBuf>, output: PathBuf, version: Option<u8>) -> Result<()> {
    use sb_core::router::ruleset::{binary, source, RuleSetFormat};
    if inputs.is_empty() {
        anyhow::bail!("no inputs provided");
    }
    let out_fmt = source::infer_format_from_path(output.to_str().unwrap_or(""))
        .ok_or_else(|| anyhow::anyhow!("cannot infer output format"))?;
    let mut all_rules: Vec<sb_core::router::ruleset::Rule> = Vec::new();
    let mut out_ver = sb_core::router::ruleset::RULESET_VERSION_CURRENT;
    for p in inputs {
        let in_fmt = source::infer_format_from_path(p.to_str().unwrap_or(""))
            .ok_or_else(|| anyhow::anyhow!("cannot infer input format for {}", p.display()))?;
        let rs = binary::load_from_file(&p, in_fmt).await?;
        all_rules.extend(rs.rules);
        out_ver = out_ver.max(rs.version);
    }
    if let Some(v) = version {
        out_ver = v;
    }
    match out_fmt {
        RuleSetFormat::Binary => {
            binary::write_to_file(&output, &all_rules, out_ver).await?;
            println!("{}", output.display());
        }
        RuleSetFormat::Source => {
            let mut arr = Vec::new();
            for r in &all_rules {
                arr.push(rule_to_json(r));
            }
            let v = serde_json::json!({"version": out_ver, "rules": arr});
            std::fs::write(&output, serde_json::to_string_pretty(&v)?)?;
            println!("{}", output.display());
        }
    }
    Ok(())
}

async fn upgrade_ruleset(input: PathBuf, output: PathBuf, version: Option<u8>) -> Result<()> {
    use sb_core::router::ruleset::{binary, source, RuleSetFormat, RULESET_VERSION_CURRENT};
    let in_fmt = source::infer_format_from_path(input.to_str().unwrap_or(""))
        .ok_or_else(|| anyhow::anyhow!("cannot infer input format"))?;
    let out_fmt = source::infer_format_from_path(output.to_str().unwrap_or(""))
        .ok_or_else(|| anyhow::anyhow!("cannot infer output format"))?;
    let target_ver = version.unwrap_or(RULESET_VERSION_CURRENT);
    let rs = binary::load_from_file(&input, in_fmt).await?;
    match out_fmt {
        RuleSetFormat::Binary => {
            binary::write_to_file(&output, &rs.rules, target_ver).await?;
            println!("{}", output.display());
        }
        RuleSetFormat::Source => {
            let mut arr = Vec::new();
            for r in &rs.rules {
                arr.push(rule_to_json(r));
            }
            let v = serde_json::json!({"version": target_ver, "rules": arr});
            std::fs::write(&output, serde_json::to_string_pretty(&v)?)?;
            println!("{}", output.display());
        }
    }
    Ok(())
}
