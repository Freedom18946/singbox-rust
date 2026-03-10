//! Integration test harness crate utilities.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir
}

/// Locate a workspace binary by name, preferring Cargo-provided hints.
pub fn workspace_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    let mut path = workspace_root();
    path.push("target");
    let profile = std::env::var("CARGO_PROFILE")
        .ok()
        .or_else(|| std::env::var("PROFILE").ok())
        .unwrap_or_else(|| "debug".into());
    path.push(profile);
    path.push(name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

/// Build a workspace binary before executing it from tests.
pub fn ensure_workspace_bin(package: &str, name: &str, features: &[&str]) -> PathBuf {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg(package)
        .arg("--bin")
        .arg(name)
        .current_dir(workspace_root());
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let output = cmd.output().expect("build workspace binary");
    assert!(
        output.status.success(),
        "failed to build {package}:{name}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let path = workspace_bin(name);
    assert!(path.exists(), "workspace binary not found at {:?}", path);
    path
}

/// Run a command with a wall-clock timeout and capture stdout/stderr for assertions.
pub fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> std::io::Result<Output> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output()?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "command {:?} exceeded {:?}\nstdout:\n{}\nstderr:\n{}",
                    cmd,
                    timeout,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
