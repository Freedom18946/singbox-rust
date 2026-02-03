#![cfg(feature = "adapter-http")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! E2E tests for HTTP CONNECT over TLS functionality
//!
//! This module tests HTTPS proxy support with mock TLS servers.

use sb_adapters::{
    error::AdapterError,
    outbound::http::HttpProxyConnector,
    traits::{DialOpts, OutboundConnector, ResolveMode, Target},
    Result,
};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn is_permission_denied(err: &AdapterError) -> bool {
    matches!(err, AdapterError::Io(io_err) if io_err.kind() == ErrorKind::PermissionDenied)
}

/// Mock HTTP proxy server for testing
struct MockHttpProxy {
    listener: TcpListener,
    with_auth: bool,
}

impl MockHttpProxy {
    async fn new(with_auth: bool) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self {
            listener,
            with_auth,
        })
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Handle a single HTTP CONNECT request
    async fn handle_connect(&self) -> Result<()> {
        let (mut stream, _) = self.listener.accept().await?;
        let mut reader = BufReader::new(&mut stream);

        // Read HTTP request line
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;

        // Should be something like "CONNECT target:port HTTP/1.1"
        assert!(request_line.starts_with("CONNECT "));

        // Read headers until empty line
        let mut auth_header = None;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).await?;

            if header.trim().is_empty() {
                break;
            }

            if header.to_lowercase().starts_with("proxy-authorization:") {
                auth_header = Some(header);
            }
        }

        // Check authentication if required
        if self.with_auth && auth_header.is_none() {
            // Send 407 Proxy Authentication Required
            let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
            stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }

        // Send 200 Connection established
        let response = "HTTP/1.1 200 Connection established\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;

        // Echo any data that comes through (simulate tunnel)
        let mut buf = [0u8; 1024];
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await?;
        }

        Ok(())
    }
}

#[cfg(feature = "adapter-http")]
#[tokio::test]
async fn test_http_connect_basic() -> Result<()> {
    use serial_test::serial;

    #[serial]
    async fn run_test() -> Result<()> {
        let proxy = match MockHttpProxy::new(false).await {
            Ok(proxy) => proxy,
            Err(err) if is_permission_denied(&err) => {
                eprintln!("skipping http tls basic test: PermissionDenied binding listener");
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let proxy_addr = proxy.addr();

        // Start proxy server
        let proxy_task = tokio::spawn(async move { proxy.handle_connect().await });

        // Give server a moment to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Create HTTP connector
        let connector = HttpProxyConnector::no_auth(proxy_addr.to_string());

        // Test connection
        let target = Target::tcp("example.com", 80);
        let opts = DialOpts {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            retry_policy: Default::default(),
            resolve_mode: ResolveMode::Remote,
        };

        let result = connector.dial(target, opts).await;
        assert!(result.is_ok());

        // Clean up
        proxy_task.abort();

        Ok(())
    }

    run_test().await
}

#[cfg(feature = "adapter-http")]
#[tokio::test]
async fn test_http_connect_with_auth() -> Result<()> {
    use serial_test::serial;

    #[serial]
    async fn run_test() -> Result<()> {
        let proxy = match MockHttpProxy::new(true).await {
            Ok(proxy) => proxy,
            Err(err) if is_permission_denied(&err) => {
                eprintln!("skipping http tls auth test: PermissionDenied binding listener");
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let proxy_addr = proxy.addr();

        // Start proxy server
        let proxy_task = tokio::spawn(async move { proxy.handle_connect().await });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Test without auth (should fail)
        let connector_no_auth = HttpProxyConnector::no_auth(proxy_addr.to_string());
        let target = Target::tcp("example.com", 80);
        let opts = DialOpts {
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(1),
            retry_policy: Default::default(),
            resolve_mode: ResolveMode::Remote,
        };

        let result = connector_no_auth.dial(target.clone(), opts.clone()).await;
        // Should fail with 407 or connection error
        assert!(result.is_err());

        proxy_task.abort();

        // Test with auth (mock server doesn't validate actual credentials)
        let proxy2 = match MockHttpProxy::new(true).await {
            Ok(proxy) => proxy,
            Err(err) if is_permission_denied(&err) => {
                eprintln!("skipping http tls auth test: PermissionDenied binding listener");
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let proxy2_addr = proxy2.addr().to_string();
        let proxy_task2 = tokio::spawn(async move { proxy2.handle_connect().await });

        tokio::time::sleep(Duration::from_millis(10)).await;

        let connector_with_auth =
            HttpProxyConnector::with_auth(proxy2_addr, "testuser", "testpass");

        let result = connector_with_auth.dial(target, opts).await;
        assert!(result.is_ok());

        proxy_task2.abort();

        Ok(())
    }

    run_test().await
}

#[cfg(all(feature = "adapter-http", feature = "http-tls"))]
#[tokio::test]
async fn test_https_proxy_creation() -> Result<()> {
    // Test TLS connector creation (we can't easily test actual TLS without certificates)
    let connector = HttpProxyConnector::no_auth_tls("proxy.example.com:443");

    // Test that it's created correctly
    assert_eq!(connector.name(), "http");

    // Test start method
    let result = connector.start().await;
    assert!(result.is_ok());

    Ok(())
}

#[cfg(feature = "adapter-http")]
#[tokio::test]
async fn test_http_resolve_modes() -> Result<()> {
    // Test different resolve modes without actually connecting
    let connector = HttpProxyConnector::no_auth("127.0.0.1:8080");

    // Test with domain name target
    let target = Target::tcp("example.com", 80);

    // Test Remote resolve mode (should try to connect and fail)
    let opts_remote = DialOpts {
        connect_timeout: Duration::from_millis(100),
        read_timeout: Duration::from_secs(1),
        retry_policy: Default::default(),
        resolve_mode: ResolveMode::Remote,
    };

    let result = connector.dial(target.clone(), opts_remote).await;
    assert!(result.is_err()); // Should fail since no server

    // Test Local resolve mode (should also fail but after resolving)
    let opts_local = DialOpts {
        connect_timeout: Duration::from_millis(100),
        read_timeout: Duration::from_secs(1),
        retry_policy: Default::default(),
        resolve_mode: ResolveMode::Local,
    };

    let result = connector.dial(target, opts_local).await;
    assert!(result.is_err()); // Should also fail

    Ok(())
}
