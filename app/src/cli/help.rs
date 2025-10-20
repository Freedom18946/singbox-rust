//! Helper utilities for emitting Clap help/usage information as JSON.

use clap::CommandFactory;
use serde::Serialize;

/// Emit help/usage information for the given [`CommandFactory`] in JSON format.
///
/// This ensures downstream tooling can ingest structured help output instead of
/// parsing human-oriented text. The JSON payload includes the command name,
/// usage line, optional `about`/`long_about` descriptions, rendered help text,
/// version metadata, and the list of direct subcommands.
pub fn print_help_json<T>() -> !
where
    T: CommandFactory,
{
    let mut cmd = T::command();
    // Disable ANSI styling to keep JSON deterministic across environments.
    cmd = cmd.disable_colored_help(true);

    // Align rendered usage/help with the current binary name so the output matches
    // what users see from `--help`.
    if let Some(bin) = std::env::args().next() {
        if let Some(stem) = std::path::Path::new(&bin)
            .file_name()
            .and_then(|s| s.to_str())
        {
            cmd = cmd.bin_name(stem.to_owned());
            cmd = cmd.display_name(stem.to_owned());
        }
    }

    let usage = cmd.render_usage().to_string();
    let help = cmd.render_long_help().to_string();

    let about = cmd.get_about().map(std::string::ToString::to_string);
    let long_about = cmd.get_long_about().map(std::string::ToString::to_string);
    let version = cmd.get_version().map(std::string::ToString::to_string);
    let long_version = cmd.get_long_version().map(std::string::ToString::to_string);
    let before_help = cmd.get_before_help().map(std::string::ToString::to_string);
    let after_help = cmd.get_after_help().map(std::string::ToString::to_string);

    #[derive(Serialize)]
    struct HelpPayload {
        name: String,
        usage: String,
        help: String,
        about: Option<String>,
        long_about: Option<String>,
        before_help: Option<String>,
        after_help: Option<String>,
        version: Option<String>,
        long_version: Option<String>,
        subcommands: Vec<String>,
    }

    let command_name = cmd
        .get_display_name()
        .map(std::string::ToString::to_string)
        .or_else(|| cmd.get_bin_name().map(std::string::ToString::to_string))
        .unwrap_or_else(|| cmd.get_name().to_string());

    let payload = HelpPayload {
        name: command_name,
        usage: usage.trim().to_string(),
        help,
        about,
        long_about,
        before_help,
        after_help,
        version,
        long_version,
        subcommands: cmd
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect(),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
    );

    // Exit early to mimic standard Clap `--help` behaviour.
    std::process::exit(0);
}
