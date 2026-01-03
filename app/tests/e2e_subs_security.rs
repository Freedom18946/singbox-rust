#![allow(unused_imports, dead_code)]
use serial_test::serial;
use std::collections::HashSet;
use std::io;
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const SUBS_ENV_KEYS: [&str; 18] = [
    "SB_ADMIN_URL_DENY_PRIVATE",
    "SB_SUBS_BR_FAILS",
    "SB_SUBS_BR_OPEN_MS",
    "SB_SUBS_BR_RATIO",
    "SB_SUBS_BR_WIN_MS",
    "SB_SUBS_CACHE_BYTES",
    "SB_SUBS_CACHE_CAP",
    "SB_SUBS_CACHE_DISK",
    "SB_SUBS_CACHE_TTL_MS",
    "SB_SUBS_HEAD_PRECHECK",
    "SB_SUBS_MAX_BYTES",
    "SB_SUBS_MAX_CONCURRENCY",
    "SB_SUBS_MAX_REDIRECTS",
    "SB_SUBS_MIME_ALLOW",
    "SB_SUBS_MIME_DENY",
    "SB_SUBS_PRIVATE_ALLOWLIST",
    "SB_SUBS_RPS",
    "SB_SUBS_TIMEOUT_MS",
];

const ADMIN_ENV_KEYS: [&str; 2] = ["SB_ADMIN_NO_AUTH", "SB_ADMIN_TOKEN"];

fn should_skip_local_network_tests() -> bool {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            eprintln!("Skipping subs security tests: {}", err);
            true
        }
        Err(err) => panic!("Failed to bind test listener: {}", err),
    }
}

struct EnvGuard {
    saved: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn set(vars: &[(&str, Option<&str>)]) -> Self {
        let mut saved = Vec::new();
        let mut seen = HashSet::new();
        for (key, value) in vars {
            if seen.insert(*key) {
                saved.push(((*key).to_string(), std::env::var(key).ok()));
            }
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            match value {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
    }
}

#[cfg(feature = "subs_http")]
fn subs_env_guard(overrides: &[(&str, Option<&str>)]) -> EnvGuard {
    let mut vars = Vec::new();
    for key in SUBS_ENV_KEYS {
        vars.push((key, None));
    }
    vars.extend_from_slice(overrides);
    let guard = EnvGuard::set(&vars);
    app::admin_debug::reloadable::reload();
    if let Ok(mut breaker) = app::admin_debug::breaker::global().lock() {
        breaker.reset();
    }
    guard
}

fn admin_env_guard(overrides: &[(&str, Option<&str>)]) -> EnvGuard {
    let mut vars = Vec::new();
    for key in ADMIN_ENV_KEYS {
        vars.push((key, None));
    }
    vars.extend_from_slice(overrides);
    EnvGuard::set(&vars)
}

fn expect_ok<T>(res: anyhow::Result<T>) -> T {
    match res {
        Ok(val) => val,
        Err(err) => panic!("expected Ok result, got Err: {err}"),
    }
}

fn expect_err_contains<T>(res: anyhow::Result<T>, needle: &str) {
    match res {
        Ok(_) => panic!("expected Err containing {needle}"),
        Err(err) => assert!(
            err.to_string().contains(needle),
            "unexpected error: {err}"
        ),
    }
}

async fn serve_once_302_to_loopback(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
}

async fn serve_once_large_body(port: u16, bytes: usize) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let body = "x".repeat(bytes);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
}

#[tokio::test]
#[serial]
async fn subs_block_private_redirect() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[]);
        let port = 19091;
        serve_once_302_to_loopback(port).await;
        let url = format!("http://127.0.0.1:{port}/first");
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(r, "private");
    }
}

#[tokio::test]
#[serial]
async fn subs_size_limit() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_MAX_BYTES", Some("8192")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        let port = 19092;
        serve_once_large_body(port, 16 * 1024).await;
        let url = format!("http://127.0.0.1:{port}/large");
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(r, "exceed size limit");
    }
}

#[tokio::test]
#[serial]
async fn subs_timeout_limit() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_TIMEOUT_MS", Some("200")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let port = 19100u16;
        let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
                .await;
        });
        let url = format!("http://127.0.0.1:{port}/slow");
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(r, "timeout");
    }
}

#[tokio::test]
#[serial]
async fn subs_allowlist_pass() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // 直连到 127.0.0.1，但通过 allowlist 放行（仅示例：真实灰度请谨慎配置）
        let _env = subs_env_guard(&[("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1"))]);
        let port = 19101u16;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            let body = "ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
        let url = format!("http://127.0.0.1:{port}/ok");
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        let body = expect_ok(r);
        assert_eq!(body, "ok");
    }
}

#[tokio::test]
#[serial]
async fn subs_ipv6_block_loopback() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[]);
        // 仅校验路径：解析 ::1 应被拒
        let url = "http://[::1]:8080/evil";
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(url).await;
        assert!(r.is_err());
    }
}

#[tokio::test]
#[serial]
async fn subs_redirect_loop() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_MAX_REDIRECTS", Some("2")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let a = 19110u16;
        let b = 19111u16;
        let la = TcpListener::bind(("127.0.0.1", a)).await.unwrap();
        let lb = TcpListener::bind(("127.0.0.1", b)).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = la.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            let resp = format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/next\r\nContent-Length: 0\r\n\r\n", b);
            let _ = s.write_all(resp.as_bytes()).await;
        });
        tokio::spawn(async move {
            let (mut s, _) = lb.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            let resp = format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{}/back\r\nContent-Length: 0\r\n\r\n", a);
            let _ = s.write_all(resp.as_bytes()).await;
        });
        let url = format!("http://127.0.0.1:{}/first", a);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(r.is_err(), "should fail on redirect loop");
    }
}

#[tokio::test]
#[serial]
async fn subs_slow_loris_timeout() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_TIMEOUT_MS", Some("800")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let port = 19112u16;
        let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            // 只回 header，不发 body，拖时间
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                .await;
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        });
        let url = format!("http://127.0.0.1:{}/loris", port);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(r, "timeout");
    }
}

#[tokio::test]
#[serial]
async fn subs_mime_allow() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_MIME_ALLOW", Some("application/json,text/plain")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let port = 19113u16;
        let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            let body = "{\"ok\":true}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
        let url = format!("http://127.0.0.1:{}/ok", port);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        let _body = expect_ok(r);
    }
}

#[tokio::test]
#[serial]
async fn subs_allowlist_cidr_pass() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // 直连 127.0.0.1，CIDR 允许 127.0.0.0/8
        let _env = subs_env_guard(&[("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.0/8"))]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let port = 19114u16;
        let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut _buf = [0u8; 1024];
            let _ = s.read(&mut _buf).await;
            let body = "ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
        });
        let url = format!("http://127.0.0.1:{}/ok", port);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        let _body = expect_ok(r);
    }
} // === Package A: Observability Enhancement Tests ===

#[tokio::test]
#[serial]
async fn metrics_endpoint_prometheus_format() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "observe")]
    {
        use std::io::Cursor;
        let mut buf = Vec::new();
        let mut cursor = Cursor::new(&mut buf);

        // Call the metrics handler
        app::admin_debug::endpoints::metrics::handle(&mut cursor)
            .await
            .unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Verify Prometheus format
        assert!(output.contains("# HELP sb_subs_requests_total"));
        assert!(output.contains("# TYPE sb_subs_requests_total counter"));
        assert!(output.contains("sb_subs_requests_total"));
        assert!(output.contains("sb_subs_failures_total"));
        assert!(output.contains("sb_subs_rate_limited_total"));
    }
}

#[tokio::test]
#[serial]
async fn security_metrics_error_ringbuffer() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // Generate some errors to populate the ring buffer
        for i in 0..5 {
            app::admin_debug::security_metrics::set_last_error_with_url(
                app::admin_debug::security_metrics::SecurityErrorKind::Other,
                &format!("http://example{}.com", i),
                format!("test error {}", i),
            );
        }

        let snapshot = app::admin_debug::security_metrics::snapshot();
        assert!(!snapshot.last_errors.is_empty());
        assert!(snapshot.last_errors.len() <= 32); // MAX_ERRORS = 32

        // Check that errors have proper structure
        for error in &snapshot.last_errors {
            assert!(error.ts > 0);
            assert!(!error.msg.is_empty());
        }
    }
}

// === Package B: Traffic Governance Tests ===

#[tokio::test]
#[serial]
async fn subs_rate_limiting_concurrency() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_MAX_CONCURRENCY", Some("2")),
            ("SB_SUBS_RPS", Some("10")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);

        // Create a slow server
        let port = 19120u16;
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            for _ in 0..5 {
                if let Ok((mut stream, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf).await;

                        // Delay response to test concurrency
                        tokio::time::sleep(Duration::from_millis(500)).await;

                        let body = "slow response";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            }
        });

        let url = format!("http://127.0.0.1:{}/slow", port);

        // Launch multiple concurrent requests without spawning tasks to avoid Send bounds
        let start = Instant::now();
        let (r1, r2, r3, r4) = tokio::join!(
            app::admin_debug::endpoints::subs::fetch_with_limits(&url),
            app::admin_debug::endpoints::subs::fetch_with_limits(&url),
            app::admin_debug::endpoints::subs::fetch_with_limits(&url),
            app::admin_debug::endpoints::subs::fetch_with_limits(&url),
        );
        let results = [r1, r2, r3, r4];
        let elapsed = start.elapsed();

        // With concurrency limit of 2, requests should be serialized
        assert!(
            elapsed > Duration::from_millis(800),
            "elapsed {elapsed:?}, results {results:?}"
        ); // At least 2 batches of 500ms each

        let successes = results.iter().filter(|r| r.as_ref().is_ok()).count();
        assert!(successes >= 2); // At least some should succeed
    }
}

#[tokio::test]
#[serial]
async fn subs_mime_denylist() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            (
                "SB_SUBS_MIME_DENY",
                Some("application/octet-stream,application/x-executable"),
            ),
            ("SB_SUBS_MIME_ALLOW", None),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let port = 19121u16;
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                let body = "malicious executable content";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/malicious", port);
        let result = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(result, "content-type denied");
    }
}

#[tokio::test]
#[serial]
async fn subs_mime_denylist_overrides_allowlist() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_MIME_ALLOW", Some("text/javascript,text/plain")),
            ("SB_SUBS_MIME_DENY", Some("text/javascript")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let port = 19122u16;
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                let body = "blocked despite allowlist";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/blocked", port);
        let result = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(result, "content-type denied");
    }
}

// === Package C: Stability & Coverage Tests ===

#[tokio::test]
#[serial]
async fn idna_normalization_punycode() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // Test IDNA normalization with internationalized domain
        let host = "例え.テスト";
        let normalized = app::admin_debug::security::normalize_host(host);

        assert!(normalized.is_ok());
        let ascii_host = normalized.unwrap();
        assert!(ascii_host.contains("xn--")); // Should contain punycode
        assert!(!ascii_host.contains("例え")); // Should not contain original unicode
    }
}

#[tokio::test]
#[serial]
async fn idna_normalization_trailing_dot() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // Test trailing dot removal
        let host_with_dot = "example.com.";
        let host_without_dot = "example.com";

        let normalized1 = app::admin_debug::security::normalize_host(host_with_dot).unwrap();
        let normalized2 = app::admin_debug::security::normalize_host(host_without_dot).unwrap();

        assert_eq!(normalized1, normalized2);
        assert_eq!(normalized1, "example.com");
    }
}

#[tokio::test]
#[serial]
async fn idna_invalid_domain_rejection() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // Test invalid domain names are properly rejected
        let toolong_host = "toolong.".repeat(100);
        let invalid_hosts = vec![
            "invalid..domain",
            "domain.with.invalid.chars!",
            ".invalid.start",
            &toolong_host,
        ];

        for host in invalid_hosts {
            let result = app::admin_debug::security::normalize_host(host);
            assert!(result.is_err(), "Should reject invalid host: {}", host);
        }
    }
}

#[tokio::test]
#[serial]
async fn comprehensive_security_integration() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_MAX_CONCURRENCY", Some("3")),
            ("SB_SUBS_RPS", Some("5")),
            ("SB_SUBS_MAX_BYTES", Some("1024")),
            ("SB_SUBS_TIMEOUT_MS", Some("2000")),
            ("SB_SUBS_MIME_ALLOW", Some("text/plain,application/json")),
            ("SB_SUBS_MIME_DENY", Some("text/javascript")),
        ]);
        // Integration test combining all security features
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let port = 19123u16;
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                let body = "valid content";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        // Test with normalized domain (though using IP here for localhost)
        let url = format!("http://127.0.0.1:{}/integrated", port);

        // This should fail due to private IP blocking
        let result = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        expect_err_contains(result, "private");

        // Verify metrics were updated
        let snapshot = app::admin_debug::security_metrics::snapshot();
        assert!(snapshot.total_requests > 0);
        assert!(snapshot.subs_block_private_ip > 0);
    }
}

// === Package D: New Feature Tests (Cache, Circuit Breaker, Auth) ===

#[tokio::test]
#[serial]
async fn subs_cache_etag_flow() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_CACHE_CAP", Some("8")),
            ("SB_SUBS_CACHE_TTL_MS", Some("60000")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let port = 19130u16;

        // First request - server returns ETag
        let listener1 = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener1.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                let body = "cached content";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/cached", port);
        let result1 = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        let body1 = expect_ok(result1);
        assert_eq!(body1, "cached content");

        // Second request - server returns 304 Not Modified
        tokio::time::sleep(Duration::from_millis(100)).await;

        let listener2 = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener2.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                // Verify If-None-Match header was sent
                let request = String::from_utf8_lossy(&buf);
                let request_lower = request.to_ascii_lowercase();
                assert!(request_lower.contains("if-none-match"), "request: {request}");

                let response = "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let result2 = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        let body2 = expect_ok(result2);
        assert_eq!(body2, "cached content"); // Should return cached content
    }
}

#[tokio::test]
#[serial]
async fn circuit_breaker_trips_and_blocks() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        let _env = subs_env_guard(&[
            ("SB_SUBS_BR_FAILS", Some("3")),
            ("SB_SUBS_BR_OPEN_MS", Some("3000")),
            ("SB_SUBS_PRIVATE_ALLOWLIST", Some("127.0.0.1")),
        ]);
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let port = 19131u16;
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

        // Server always returns 500
        tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;

                    let response =
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });

        let url = format!("http://127.0.0.1:{}/bad", port);

        // Make 3 requests to trip the circuit breaker
        for _ in 0..3 {
            let _ = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Next request should be blocked by circuit breaker
        let blocked = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(blocked.is_err());
        assert!(blocked
            .err()
            .unwrap()
            .to_string()
            .contains("circuit breaker open"));
    }
}

#[tokio::test]
#[serial]
async fn admin_auth_bearer_token() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "admin_debug")]
    {
        let _env = admin_env_guard(&[
            ("SB_ADMIN_TOKEN", Some("test-secret-token")),
            ("SB_ADMIN_NO_AUTH", None),
        ]);

        let mut headers = std::collections::HashMap::new();

        // Test without auth header - should fail
        let result1 = app::admin_debug::http_server::check_auth(&headers, "/__health");
        assert!(!result1);

        // Test with correct Bearer token - should pass
        headers.insert(
            "authorization".to_string(),
            "Bearer test-secret-token".to_string(),
        );
        let result2 = app::admin_debug::http_server::check_auth(&headers, "/__health");
        assert!(result2);

        // Test with incorrect token - should fail
        headers.insert(
            "authorization".to_string(),
            "Bearer wrong-token".to_string(),
        );
        let result3 = app::admin_debug::http_server::check_auth(&headers, "/__health");
        assert!(!result3);

    }
}

#[tokio::test]
#[serial]
async fn admin_auth_disabled() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "admin_debug")]
    {
        let _env = admin_env_guard(&[
            ("SB_ADMIN_NO_AUTH", Some("1")),
            ("SB_ADMIN_TOKEN", None),
        ]);

        let headers = std::collections::HashMap::new();

        // Even without token, should pass when auth is disabled
        let result = app::admin_debug::http_server::check_auth(&headers, "/__health");
        assert!(result);

    }
}

#[tokio::test]
#[serial]
async fn config_hot_reload() {
    if should_skip_local_network_tests() {
        return;
    }
    #[cfg(feature = "subs_http")]
    {
        // Set initial config
        let _env = subs_env_guard(&[
            ("SB_SUBS_MAX_REDIRECTS", Some("3")),
            ("SB_SUBS_TIMEOUT_MS", Some("5000")),
        ]);

        let config1 = app::admin_debug::reloadable::get();
        assert_eq!(config1.max_redirects, 3);
        assert_eq!(config1.timeout_ms, 5000);

        // Change environment variables
        std::env::set_var("SB_SUBS_MAX_REDIRECTS", "10");
        std::env::set_var("SB_SUBS_TIMEOUT_MS", "8000");

        // Trigger reload
        app::admin_debug::reloadable::reload();

        // Get config again - should have new values
        let config2 = app::admin_debug::reloadable::get();
        assert_eq!(config2.max_redirects, 10);
        assert_eq!(config2.timeout_ms, 8000);

    }
}
