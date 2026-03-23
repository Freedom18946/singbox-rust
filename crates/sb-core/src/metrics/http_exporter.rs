//! A tiny HTTP exporter for Prometheus, with failure classification & noise reduction.
//! 通过环境变量 `PROM_LISTEN=127.0.0.1:19090` 或 CLI flag 启动.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn metrics_body_with_registry(registry: &sb_metrics::MetricsRegistryHandle) -> Vec<u8> {
    sb_metrics::export_prometheus_with(registry).into_bytes()
}

fn handle_conn_with_registry(
    mut s: TcpStream,
    registry: &sb_metrics::MetricsRegistryHandle,
) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = [0u8; 1024];
    let _ = s.read(&mut buf); // 读请求（忽略）

    let body = metrics_body_with_registry(registry);

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

#[deprecated(
    since = "0.1.0",
    note = "Use sb_metrics::spawn_http_exporter_from_env(sb_metrics::MetricsRegistryHandle::global()) instead (async, same Registry)"
)]
pub fn run_exporter(addr: &str) -> std::io::Result<()> {
    run_exporter_with_registry(addr, sb_metrics::shared_registry())
}

pub fn run_exporter_with_registry(
    addr: &str,
    registry: sb_metrics::MetricsRegistryHandle,
) -> std::io::Result<()> {
    match TcpListener::bind(addr) {
        Ok(l) => {
            l.set_nonblocking(true)?;
            loop {
                match l.accept() {
                    Ok((s, _)) => {
                        let registry = registry.clone();
                        // 每个连接一个轻线程
                        thread::spawn(move || {
                            let _ = handle_conn_with_registry(s, &registry);
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
    use prometheus::{IntGauge, Registry};
    use std::sync::Arc;

    #[test]
    fn classify() {
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        assert_eq!(classify_err(&e), "bind");
    }

    #[test]
    fn metrics_body_with_registry_exports_owned_metric_without_shared_registry() {
        let registry = sb_metrics::MetricsRegistryHandle::Owned(Arc::new(Registry::new()));
        let gauge = IntGauge::new(
            "codex_metrics_http_exporter_owned_body",
            "codex metrics http exporter owned body test",
        )
        .unwrap();
        registry
            .register_cloned("codex_metrics_http_exporter_owned_body", &gauge)
            .unwrap();
        gauge.set(29);

        let body = String::from_utf8(metrics_body_with_registry(&registry)).unwrap();
        assert!(body.contains("codex_metrics_http_exporter_owned_body"));
        assert!(body.contains(" 29"));
        assert!(!sb_metrics::export_prometheus().contains("codex_metrics_http_exporter_owned_body"));
    }
}
