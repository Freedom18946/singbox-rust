use serde_json::Value;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn spawn_tcp_echo(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&buf);
        }
    });
    Ok(())
}

fn spawn_udp_echo(addr: &str) -> std::io::Result<()> {
    let socket = UdpSocket::bind(addr)?;
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..n], peer);
            }
        }
    });
    Ok(())
}

#[test]
fn bench_outputs_json() {
    let root = project_root();
    let tcp_addr = "127.0.0.1:17007";
    let udp_addr = "127.0.0.1:17099";

    if let Err(e) = spawn_tcp_echo(tcp_addr) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("skip bench_outputs_json: tcp bind permission denied");
            return;
        }
        panic!("bind tcp: {e}");
    }
    if let Err(e) = spawn_udp_echo(udp_addr) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("skip bench_outputs_json: udp bind permission denied");
            return;
        }
        panic!("bind udp: {e}");
    }
    thread::sleep(Duration::from_millis(100));

    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--quiet")
        .arg("--bin")
        .arg("sb-bench")
        .arg("--features")
        .arg("bench")
        .current_dir(&root)
        .env("SB_BENCH", "1")
        .env("SB_BENCH_N", "20")
        .env("SB_BENCH_TCP", tcp_addr)
        .env("SB_BENCH_UDP", udp_addr);

    let output = cmd.output().expect("run sb-bench");
    assert!(
        output.status.success(),
        "sb-bench failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout).expect("bench output json");
    for key in ["tcp_connect_ms", "udp_rtt_ms", "dns_rtt_ms"] {
        assert!(json.get(key).is_some(), "{} missing", key);
    }
}
