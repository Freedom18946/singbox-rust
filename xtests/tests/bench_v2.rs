use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    process::Command,
    thread,
    time::Duration,
};

fn spawn_tcp_echo(addr: &str) -> std::io::Result<()> {
    let l = TcpListener::bind(addr)?;
    std::thread::spawn(move || {
        for mut stream in l.incoming().flatten() {
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&buf);
        }
    });
    Ok(())
}
fn spawn_udp_echo(addr: &str) -> std::io::Result<()> {
    let s = UdpSocket::bind(addr)?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        loop {
            if let Ok((n, peer)) = s.recv_from(&mut buf) {
                let _ = s.send_to(&buf[..n], peer);
            }
        }
    });
    Ok(())
}

#[test]
fn bench_v2_produces_csv_and_json() {
    if let Err(e) = spawn_tcp_echo("127.0.0.1:17107") {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("skip bench_v2_produces_csv_and_json: tcp bind permission denied");
            return;
        }
        panic!("bind tcp: {e}");
    }
    if let Err(e) = spawn_udp_echo("127.0.0.1:17199") {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            eprintln!("skip bench_v2_produces_csv_and_json: udp bind permission denied");
            return;
        }
        panic!("bind udp: {e}");
    }
    thread::sleep(Duration::from_millis(100));
    let out=Command::new("bash").args(["-lc",
        "SB_BENCH=1 SB_BENCH_N=80 SB_BENCH_PAR=8 SB_BENCH_TCP=127.0.0.1:17107 SB_BENCH_UDP=127.0.0.1:17199 SB_BENCH_CSV=.e2e/bench_udp.csv cargo run --features bench --bin sb-bench --quiet"
    ]).output().expect("run bench");
    assert!(out.status.success(), "bench failed");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("udp_rtt_ms").is_some(), "no udp_rtt_ms");
    assert!(
        std::fs::metadata(".e2e/bench_udp.csv").is_ok(),
        "csv missing"
    );
}
