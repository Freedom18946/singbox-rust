use crate::cli::Format;
use serde::Serialize;

/// Unified output adapter for CLI commands
pub fn emit<T: Serialize>(fmt: Format, human: impl FnOnce() -> String, json: &T) {
    match fmt {
        Format::Human => println!("{}", human()),
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(json).unwrap_or_else(|_| "{}".into())
        ),
        Format::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(json).unwrap_or_else(|_| "{}".into())
        ), // route 先复用JSON，check单独SARIF
    }
}

/// Emit SARIF-specific output
#[allow(dead_code)] // Scaffolding for future SARIF support
pub fn emit_sarif(sarif_json_text: &str) {
    println!("{sarif_json_text}");
}
