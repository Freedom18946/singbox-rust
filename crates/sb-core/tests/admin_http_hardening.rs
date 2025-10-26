use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use sb_core::admin::http::spawn_admin;
use sb_core::runtime::Runtime;

fn connect(addr: &str) -> TcpStream {
    let mut tries = 0;
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(_) if tries < 10 => {
                tries += 1;
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("Connection failed after retries: {e}"),
        }
    }
}

fn start_admin() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    let h = format!("{}:{}", addr.ip(), addr.port());
    let _jh = spawn_admin(
        &h,
        Runtime::dummy_engine(),
        Runtime::dummy_bridge(),
        None,
        None,
        None,
    )
    .expect("spawn admin");
    // give it a moment
    thread::sleep(Duration::from_millis(50));
    h
}

#[test]
fn large_header_is_rejected() {
    std::env::set_var("SB_ADMIN_MAX_HEADER_BYTES", "1024");
    let addr = start_admin();
    let mut s = connect(&addr);
    // build a request with huge header block
    let mut req = format!("GET /healthz HTTP/1.1\r\nHost: {}\r\n", addr);
    let big = "X-Long: ".to_string() + &"a".repeat(2000) + "\r\n"; // >1KB
    req.push_str(&big);
    req.push_str("\r\n");
    let _ = s.write_all(req.as_bytes());
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("HTTP/1.1"));
    // either 400 or 431 depending on OS TCP behavior; ensure JSON error shape
    assert!(text.contains("\"error\""));
    assert!(text.contains("\"detail\""));
}

#[test]
fn large_body_is_rejected() {
    std::env::set_var("SB_ADMIN_MAX_BODY_BYTES", "1024");
    let addr = start_admin();
    let mut s = connect(&addr);
    let body = "x".repeat(2048);
    let req = format!(
        "POST /explain HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        addr,
        body.len(),
        body
    );
    let _ = s.write_all(req.as_bytes());
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains(" 413 ") || text.contains(" 400 "));
    assert!(text.contains("\"error\""));
    assert!(text.contains("\"detail\""));
}

#[test]
fn first_byte_timeout_closes_conn() {
    std::env::set_var("SB_ADMIN_FIRSTBYTE_TIMEOUT_MS", "100");
    let addr = start_admin();
    let mut s = connect(&addr);
    // wait beyond timeout without sending any byte
    thread::sleep(Duration::from_millis(150));
    // now attempt to write a request; server likely closed
    let req = format!("GET /healthz HTTP/1.1\r\nHost: {}\r\n\r\n", addr);
    let wr = s.write_all(req.as_bytes());
    if wr.is_ok() {
        // try read; expect close/no response
        let mut buf = [0u8; 64];
        let r = s.read(&mut buf);
        assert!(r.is_err() || matches!(r, Ok(0)));
    }
}

#[test]
fn per_ip_concurrency_is_limited() {
    std::env::set_var("SB_ADMIN_MAX_CONN_PER_IP", "1");
    std::env::set_var("SB_ADMIN_FIRSTLINE_TIMEOUT_MS", "300");
    let addr = start_admin();

    // Hold first connection without sending CRLF to keep it open
    let mut s1 = connect(&addr);
    let pfx = format!("GET /healthz HTTP/1.1\r\nHost: {}\r\n", addr);
    let _ = s1.write_all(pfx.as_bytes());

    // Second connection should be rejected with 429
    let mut s2 = connect(&addr);
    let _ = s2.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut buf = Vec::new();
    let _ = s2.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains(" 429 "));
    assert!(text.contains("\"error\""));
    assert!(text.contains("\"detail\""));
}
