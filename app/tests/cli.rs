#![cfg(feature = "admin_tests")]
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
    use std::sync::mpsc;
    use std::time::Duration;

    let bin_dir = PathBuf::from(env!("CARGO_BIN_EXE_version"))
        .parent()
        .unwrap()
        .to_string_lossy()
        .to_string();

    let timeout_secs: u64 = std::env::var("TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);

    let (tx, rx) = mpsc::channel();
    let bin_dir_clone = bin_dir.clone();
    std::thread::spawn(move || {
        trycmd::TestCases::new()
            .case("tests/cli/*.trycmd")
            .env("PATH", bin_dir_clone)
            .env("FORCE_COLOR", "0")
            .env("NO_COLOR", "1")
            .run();
        let _ = tx.send(());
    });

    if rx
        .recv_timeout(Duration::from_secs(timeout_secs))
        .is_err()
    {
        eprintln!("cli trycmd tests timed out after {}s; aborting", timeout_secs);
        std::process::exit(101);
    }
}
