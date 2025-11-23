//! A tiny HTTP exporter for Prometheus, with failure classification & noise reduction.
//! 通过环境变量 `PROM_LISTEN=127.0.0.1:19090` 或 CLI flag 启动.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn handle_conn(mut s: TcpStream) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0u8; 1024];
    let _ = s.read(&mut buf); // 读请求（忽略）

    // Use sb_metrics::export_prometheus() to avoid code duplication
    let body = sb_metrics::export_prometheus().into_bytes();

    let hdr = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(hdr.as_bytes())?;
    s.write_all(&body)?;
    Ok(())
}

fn classify_err(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind::{
        AddrInUse, AddrNotAvailable, BrokenPipe, ConnectionAborted, ConnectionRefused,
        ConnectionReset, Interrupted, NotConnected, PermissionDenied, TimedOut, WouldBlock,
    };
    match e.kind() {
        AddrInUse | AddrNotAvailable | PermissionDenied => "bind",
        ConnectionRefused | ConnectionAborted | ConnectionReset | NotConnected => "conn",
        TimedOut | WouldBlock | Interrupted | BrokenPipe => "io",
        _ => "other",
    }
}

pub fn run_exporter(addr: &str) -> std::io::Result<()> {
    match TcpListener::bind(addr) {
        Ok(l) => {
            l.set_nonblocking(true)?;
            loop {
                match l.accept() {
                    Ok((s, _)) => {
                        // 每个连接一个轻线程
                        thread::spawn(move || {
                            let _ = handle_conn(s);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        let class = classify_err(&e);
                        // 降噪：只做指标计数，不刷控制台
                        sb_metrics::inc_prom_http_fail(class);
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }
        Err(e) => {
            // 绑定失败：记指标 + 返回错误；由调用方决定是否重试
            let class = classify_err(&e);
            sb_metrics::inc_prom_http_fail(class);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classify() {
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert_eq!(classify_err(&e), "bind");
    }
}
