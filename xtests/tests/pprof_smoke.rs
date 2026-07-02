#![cfg(all(feature = "explain", feature = "pprof"))]
use std::net::TcpListener;
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
#[ignore = "manual smoke: builds and runs sb-explaind with pprof enabled"]
fn pprof_endpoint_smoke() {
    if Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        panic!("curl not found in PATH");
    }

    let bin = xtests::ensure_workspace_bin("app", "sb-explaind", &["explain", "pprof"]);
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

    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve pprof port");
    let addr = listener.local_addr().expect("pprof addr").to_string();
    drop(listener);
    let child = Command::new(bin)
        .env("SB_PPROF", "1")
        .env("SB_DEBUG_ADDR", &addr)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sb-explaind");
    let guard = ChildGuard(child);

    let mut ready = false;
    for _ in 0..20 {
        let status = Command::new("curl")
            .args(["-fsS", &format!("http://{}/debug/pprof/status", addr)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run curl");
        if status.success() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(250));
    }
    assert!(
        ready,
        "sb-explaind pprof status endpoint did not become ready"
    );

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

    drop(guard);

    let meta = std::fs::metadata(&svg_path).expect("pprof output");
    assert!(meta.len() > 0, "flamegraph output is empty");
}
