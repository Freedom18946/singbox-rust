#![cfg(all(feature = "explain", feature = "pprof"))]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn pprof_endpoint_smoke() {
    if std::env::var("XT_PPROF_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping pprof smoke; set XT_PPROF_SMOKE=1 to enable");
        return;
    }

    if Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        panic!("curl not found in PATH");
    }

    let bin = resolved_bin("sb-explaind");
    assert!(
        bin.exists(),
        "sb-explaind binary is not available at {:?}; build with explain+pprof features",
        bin
    );

    let workdir = std::env::current_dir().expect("cwd");
    let e2e_dir = workdir.join(".e2e");
    std::fs::create_dir_all(&e2e_dir).expect("create .e2e");
    let svg_path = e2e_dir.join("flame.svg");
    let _ = std::fs::remove_file(&svg_path);

    let addr = "127.0.0.1:28089";
    let child = Command::new(bin)
        .env("SB_PPROF", "1")
        .env("SB_DEBUG_ADDR", addr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sb-explaind");
    let guard = ChildGuard(child);

    // give the server time to boot
    sleep(Duration::from_secs(1));

    let mut curl_status = None;
    for _ in 0..5 {
        let status = Command::new("curl")
            .args([
                "-fsS",
                &format!("http://{}/debug/pprof?sec=1", addr),
                "-o",
                svg_path.to_str().unwrap(),
            ])
            .status()
            .expect("run curl");
        if status.success() {
            curl_status = Some(status);
            break;
        }
        sleep(Duration::from_millis(500));
    }

    assert!(curl_status.is_some(), "curl did not execute successfully");

    assert!(
        curl_status.unwrap().success(),
        "curl failed to fetch pprof output"
    );

    // ensure we clean up the process
    drop(guard);

    let meta = std::fs::metadata(&svg_path).expect("pprof output");
    assert!(meta.len() > 0, "flamegraph output is empty");
}

fn resolved_bin(name: &str) -> PathBuf {
    xtests::workspace_bin(name)
}
