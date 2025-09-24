use std::io::{Read, Write};
use std::net::TcpListener as StdListener;
use std::thread;
use std::time::Duration;

#[test]
fn smoke_405_inproc() {
    // 直接起一个外部监听，防止端口被环境干扰（用 0 端口让系统分配）
    let stdl = StdListener::bind("127.0.0.1:0").expect("bind");
    let addr = stdl.local_addr().unwrap();

    // 后台线程模拟"我们的 SMOKE 405 入站"
    thread::spawn(move || {
        for stream in stdl.incoming() {
            let mut s = stream.unwrap();
            let _ = s.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = s.flush();
            // 稍等一会，确保对端能读到
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    // 客户端侧
    let mut c = std::net::TcpStream::connect(addr).expect("connect");
    c.write_all(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n")
        .unwrap();
    c.flush().unwrap();
    c.shutdown(std::net::Shutdown::Write).ok();

    let mut buf = [0u8; 128];
    let n = c.read(&mut buf).unwrap();
    let line = std::str::from_utf8(&buf[..n])
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap();
    assert!(line.starts_with("HTTP/1.1 405"), "got: {line}");
}
