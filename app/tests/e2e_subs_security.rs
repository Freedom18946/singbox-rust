#![allow(unused_imports, dead_code)]
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

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
async fn subs_block_private_redirect() {
    #[cfg(feature = "subs_http")]
    {
        let port = 19091;
        serve_once_302_to_loopback(port).await;
        let url = format!("http://127.0.0.1:{port}/first");
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(r.is_err(), "should block redirect to loopback, got {:?}", r);
        assert!(r.err().unwrap().to_string().contains("private"));
    }
}

#[tokio::test]
async fn subs_size_limit() {
    #[cfg(feature = "subs_http")]
    {
        std::env::set_var("SB_SUBS_MAX_BYTES", "8192");
        let port = 19092;
        serve_once_large_body(port, 16 * 1024).await;
        let url = format!("http://127.0.0.1:{port}/large");
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(r.is_err(), "should exceed size limit");
        assert!(r.err().unwrap().to_string().contains("exceed size limit"));
    }
}

#[tokio::test]
async fn subs_timeout_limit() {
    #[cfg(feature = "subs_http")]
    {
        std::env::set_var("SB_SUBS_TIMEOUT_MS", "200");
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
        assert!(r.is_err());
        assert!(r.err().unwrap().to_string().contains("timeout"));
    }
}

#[tokio::test]
async fn subs_allowlist_pass() {
    #[cfg(feature = "subs_http")]
    {
        // 直连到 127.0.0.1，但通过 allowlist 放行（仅示例：真实灰度请谨慎配置）
        std::env::set_var("SB_SUBS_PRIVATE_ALLOWLIST", "127.0.0.1");
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
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), "ok");
    }
}

#[tokio::test]
async fn subs_ipv6_block_loopback() {
    #[cfg(feature = "subs_http")]
    {
        // 仅校验路径：解析 ::1 应被拒
        let url = "http://[::1]:8080/evil";
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(url).await;
        assert!(r.is_err());
    }
}

#[tokio::test]
async fn subs_redirect_loop() {
    #[cfg(feature = "subs_http")]
    {
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
        std::env::set_var("SB_SUBS_MAX_REDIRECTS", "2");
        let url = format!("http://127.0.0.1:{}/first", a);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(r.is_err(), "should fail on redirect loop");
    }
}

#[tokio::test]
async fn subs_slow_loris_timeout() {
    #[cfg(feature = "subs_http")]
    {
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
        std::env::set_var("SB_SUBS_TIMEOUT_MS", "800");
        let url = format!("http://127.0.0.1:{}/loris", port);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(r.is_err());
        assert!(r.err().unwrap().to_string().contains("timeout"));
    }
}

#[tokio::test]
async fn subs_mime_allow() {
    #[cfg(feature = "subs_http")]
    {
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
        std::env::set_var("SB_SUBS_MIME_ALLOW", "application/json,text/plain");
        let url = format!("http://127.0.0.1:{}/ok", port);
        let r = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(r.is_ok());
    }
}

#[tokio::test]
async fn subs_allowlist_cidr_pass() {
    #[cfg(feature = "subs_http")]
    {
        // 直连 127.0.0.1，CIDR 允许 127.0.0.0/8
        std::env::set_var("SB_SUBS_PRIVATE_ALLOWLIST", "127.0.0.0/8");
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
        assert!(r.is_ok());
    }
} // === Package A: Observability Enhancement Tests ===

#[tokio::test]
async fn metrics_endpoint_prometheus_format() {
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
async fn security_metrics_error_ringbuffer() {
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
        assert!(snapshot.last_errors.len() > 0);
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
async fn subs_rate_limiting_concurrency() {
    #[cfg(feature = "subs_http")]
    {
        std::env::set_var("SB_SUBS_MAX_CONCURRENCY", "2");
        std::env::set_var("SB_SUBS_RPS", "10");

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
        let results = vec![r1, r2, r3, r4];
        let elapsed = start.elapsed();

        // With concurrency limit of 2, requests should be serialized
        assert!(elapsed > Duration::from_millis(800)); // At least 2 batches of 500ms each

        let successes = results.iter().filter(|r| r.as_ref().is_ok()).count();
        assert!(successes >= 2); // At least some should succeed
    }
}

#[tokio::test]
async fn subs_mime_denylist() {
    #[cfg(feature = "subs_http")]
    {
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

        // Set up denylist
        std::env::set_var(
            "SB_SUBS_MIME_DENY",
            "application/octet-stream,application/x-executable",
        );
        std::env::remove_var("SB_SUBS_MIME_ALLOW"); // Clear allowlist

        let url = format!("http://127.0.0.1:{}/malicious", port);
        let result = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("content-type denied"));
    }
}

#[tokio::test]
async fn subs_mime_denylist_overrides_allowlist() {
    #[cfg(feature = "subs_http")]
    {
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

        // Set both allowlist and denylist - denylist should take precedence
        std::env::set_var("SB_SUBS_MIME_ALLOW", "text/javascript,text/plain");
        std::env::set_var("SB_SUBS_MIME_DENY", "text/javascript");

        let url = format!("http://127.0.0.1:{}/blocked", port);
        let result = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("content-type denied"));
    }
}

// === Package C: Stability & Coverage Tests ===

#[tokio::test]
async fn idna_normalization_punycode() {
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
async fn idna_normalization_trailing_dot() {
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
async fn idna_invalid_domain_rejection() {
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
async fn comprehensive_security_integration() {
    #[cfg(feature = "subs_http")]
    {
        // Integration test combining all security features
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        // Set up comprehensive security config
        std::env::set_var("SB_SUBS_MAX_CONCURRENCY", "3");
        std::env::set_var("SB_SUBS_RPS", "5");
        std::env::set_var("SB_SUBS_MAX_BYTES", "1024");
        std::env::set_var("SB_SUBS_TIMEOUT_MS", "2000");
        std::env::set_var("SB_SUBS_MIME_ALLOW", "text/plain,application/json");
        std::env::set_var("SB_SUBS_MIME_DENY", "text/javascript");
        std::env::remove_var("SB_SUBS_PRIVATE_ALLOWLIST");

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
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("private"));

        // Verify metrics were updated
        let snapshot = app::admin_debug::security_metrics::snapshot();
        assert!(snapshot.total_requests > 0);
        assert!(snapshot.subs_block_private_ip > 0);
    }
}

// === Package D: New Feature Tests (Cache, Circuit Breaker, Auth) ===

#[tokio::test]
async fn subs_cache_etag_flow() {
    #[cfg(feature = "subs_http")]
    {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        std::env::set_var("SB_SUBS_CACHE_CAP", "8");
        std::env::set_var("SB_SUBS_CACHE_TTL_MS", "60000");
        std::env::set_var("SB_SUBS_PRIVATE_ALLOWLIST", "127.0.0.1");

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
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), "cached content");

        // Second request - server returns 304 Not Modified
        tokio::time::sleep(Duration::from_millis(100)).await;

        let listener2 = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener2.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;

                // Verify If-None-Match header was sent
                let request = String::from_utf8_lossy(&buf);
                assert!(request.contains("If-None-Match"));

                let response = "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let result2 = app::admin_debug::endpoints::subs::fetch_with_limits(&url).await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), "cached content"); // Should return cached content
    }
}

#[tokio::test]
async fn circuit_breaker_trips_and_blocks() {
    #[cfg(feature = "subs_http")]
    {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        std::env::set_var("SB_SUBS_BR_FAILS", "3");
        std::env::set_var("SB_SUBS_BR_OPEN_MS", "3000");
        std::env::set_var("SB_SUBS_PRIVATE_ALLOWLIST", "127.0.0.1");

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
async fn admin_auth_bearer_token() {
    #[cfg(feature = "admin_debug")]
    {
        std::env::set_var("SB_ADMIN_TOKEN", "test-secret-token");
        std::env::remove_var("SB_ADMIN_NO_AUTH");

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

        std::env::remove_var("SB_ADMIN_TOKEN");
    }
}

#[tokio::test]
async fn admin_auth_disabled() {
    #[cfg(feature = "admin_debug")]
    {
        std::env::set_var("SB_ADMIN_NO_AUTH", "1");

        let headers = std::collections::HashMap::new();

        // Even without token, should pass when auth is disabled
        let result = app::admin_debug::http_server::check_auth(&headers, "/__health");
        assert!(result);

        std::env::remove_var("SB_ADMIN_NO_AUTH");
    }
}

#[tokio::test]
async fn config_hot_reload() {
    #[cfg(feature = "subs_http")]
    {
        // Set initial config
        std::env::set_var("SB_SUBS_MAX_REDIRECTS", "3");
        std::env::set_var("SB_SUBS_TIMEOUT_MS", "5000");

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

        // Cleanup
        std::env::remove_var("SB_SUBS_MAX_REDIRECTS");
        std::env::remove_var("SB_SUBS_TIMEOUT_MS");
    }
}
