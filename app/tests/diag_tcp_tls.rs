#![cfg(feature = "dev-cli")]
use assert_cmd::Command;
use std::io::Write;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

#[test]
fn tcp_refused_is_classified() {
    // 127.0.0.1:9 一般未监听 -> ConnectionRefused
    let out = Command::cargo_bin("diag")
        .unwrap()
        .args(["tcp", "--addr", "127.0.0.1:9", "--timeout-ms", "200"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.get("tool").unwrap(), "tcp");
    assert_eq!(v.get("ok").unwrap(), false);
}

#[test]
fn tls_protocol_error_when_server_not_tls() {
    // 启一个普通 TCP 服务端，不进行 TLS 握手
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"hello"); // 非 TLS 内容
            thread::sleep(Duration::from_millis(50));
        }
    });
    let out = Command::cargo_bin("diag")
        .unwrap()
        .args([
            "tls",
            "--addr",
            &format!("{}", addr),
            "--sni",
            "example.com",
            "--timeout-ms",
            "500",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.get("tool").unwrap(), "tls");
    assert_eq!(v.get("ok").unwrap(), false);
}
