//! trycmd CLI contract tests
//!
//! Tests CLI commands for contract compliance:
//! - version: JSON output format
//! - check: Success and failure cases with JSON output
//! - route-explain: Help and basic functionality
//! - run: Help text validation

use std::path::PathBuf;

#[test]
fn cli_tests() {
    let bin_dir = PathBuf::from(env!("CARGO_BIN_EXE_version")).parent().unwrap().to_string_lossy().to_string();

    trycmd::TestCases::new()
        .case("tests/cli/*.trycmd")
        .env("PATH", bin_dir)  // Add binary directory to PATH
        .env("FORCE_COLOR", "0")  // Disable colors for consistent output
        .env("NO_COLOR", "1")     // Ensure no color codes in output
        .run();
}