use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

fn spawn_tcp_echo() -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let addr = l.local_addr()?;
    std::thread::spawn(move || {
        for mut stream in l.incoming().flatten() {
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&buf);
        }
    });
    Ok(addr)
}

fn spawn_udp_echo() -> std::io::Result<SocketAddr> {
    let s = UdpSocket::bind("127.0.0.1:0")?;
    let addr = s.local_addr()?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        loop {
            if let Ok((n, peer)) = s.recv_from(&mut buf) {
                let _ = s.send_to(&buf[..n], peer);
            }
        }
    });
    Ok(addr)
}

#[test]
fn bench_v2_produces_csv_and_json() {
    let tcp_addr = match spawn_tcp_echo() {
        Ok(addr) => addr,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skip bench_v2_produces_csv_and_json: tcp bind permission denied");
            return;
        }
        Err(e) => panic!("bind tcp: {e}"),
    };
    let udp_addr = match spawn_udp_echo() {
        Ok(addr) => addr,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skip bench_v2_produces_csv_and_json: udp bind permission denied");
            return;
        }
        Err(e) => panic!("bind udp: {e}"),
    };
    thread::sleep(Duration::from_millis(100));
    let csv_path = std::env::temp_dir().join(format!("sb-bench-udp-{}.csv", std::process::id()));
    let dns_path = PathBuf::from(format!("{}_dns", csv_path.display()));
    let _ = std::fs::remove_file(&csv_path);
    let _ = std::fs::remove_file(&dns_path);

    let bin = xtests::ensure_workspace_bin("app", "sb-bench", &["bench"]);
    let mut cmd = Command::new(&bin);
    cmd.env("SB_BENCH", "1")
        .env("SB_BENCH_N", "80")
        .env("SB_BENCH_PAR", "8")
        .env("SB_BENCH_TCP", tcp_addr.to_string())
        .env("SB_BENCH_UDP", udp_addr.to_string())
        .env("SB_BENCH_CSV", &csv_path);
    let out =
        xtests::run_with_timeout(&mut cmd, Duration::from_secs(30)).expect("run prebuilt bench");
    assert!(
        out.status.success(),
        "bench failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("udp_rtt_ms").is_some(), "no udp_rtt_ms");
    assert!(std::fs::metadata(&csv_path).is_ok(), "csv missing");
    let _ = std::fs::remove_file(csv_path);
    let _ = std::fs::remove_file(dns_path);
}
