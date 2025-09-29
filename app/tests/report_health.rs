use assert_cmd::prelude::*;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::Duration;

fn serve_once(addr: &str) {
    let listener = TcpListener::bind(addr).expect("bind");
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let body =
                r#"{"ok":true,"pid":123,"uptime_ms":1,"features":[],"supported_kinds_count":0}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
}

#[test]
fn report_with_health_snapshot_if_portfile_present() {
    // fake admin on 127.0.0.1:19090
    serve_once("127.0.0.1:19090");
    // write a temp portfile
    let pf = tempfile::NamedTempFile::new().unwrap();
    fs::write(pf.path(), "19090").unwrap();
    // run report with --with-health and env SB_ADMIN_PORTFILE
    let mut cmd = Command::cargo_bin("report").unwrap();
    let out = cmd
        .arg("--with-health")
        .env("SB_ADMIN_PORTFILE", pf.path())
        .output()
        .expect("run report");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let health = v.get("health").expect("health");
    assert!(health.get("tried").unwrap().as_bool().unwrap());
    assert!(health.get("snapshot").is_some());
}
