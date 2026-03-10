use serde_json::Value;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::Duration;

fn spawn_tcp_echo() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&buf);
        }
    });
    Ok(addr)
}

fn spawn_udp_echo() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let addr = socket.local_addr()?;
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            if let Ok((n, peer)) = socket.recv_from(&mut buf) {
                let _ = socket.send_to(&buf[..n], peer);
            }
        }
    });
    Ok(addr)
}

#[test]
fn bench_outputs_json() {
    let tcp_addr = match spawn_tcp_echo() {
        Ok(addr) => addr,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skip bench_outputs_json: tcp bind permission denied");
            return;
        }
        Err(e) => panic!("bind tcp: {e}"),
    };
    let udp_addr = match spawn_udp_echo() {
        Ok(addr) => addr,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skip bench_outputs_json: udp bind permission denied");
            return;
        }
        Err(e) => panic!("bind udp: {e}"),
    };
    let dns_addr = match spawn_udp_echo() {
        Ok(addr) => addr,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skip bench_outputs_json: dns bind permission denied");
            return;
        }
        Err(e) => panic!("bind dns: {e}"),
    };
    thread::sleep(Duration::from_millis(100));

    let bin = xtests::ensure_workspace_bin("app", "sb-bench", &["bench"]);
    let mut cmd = Command::new(&bin);
    cmd.env("SB_BENCH", "1")
        .env("SB_BENCH_N", "20")
        .env("SB_BENCH_PAR", "4")
        .env("SB_BENCH_TCP", tcp_addr.to_string())
        .env("SB_BENCH_UDP", udp_addr.to_string())
        .env("SB_BENCH_DNS", dns_addr.to_string());

    let output =
        xtests::run_with_timeout(&mut cmd, Duration::from_secs(30)).expect("run prebuilt sb-bench");
    assert!(
        output.status.success(),
        "sb-bench failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value = serde_json::from_slice(&output.stdout).expect("bench output json");
    for key in ["tcp_connect_ms", "udp_rtt_ms", "dns_rtt_ms"] {
        assert!(json.get(key).is_some(), "{} missing", key);
    }
}
