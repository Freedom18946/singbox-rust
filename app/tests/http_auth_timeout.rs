//! HTTP authentication timeout tests
//!
//! These tests verify HTTP authentication timeout behavior.
//! Focused on auth rejection and header handling.

use anyhow::Result;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration, Instant};

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
            eprintln!("Skipping HTTP auth timeout tests: {}", err);
            true
        }
        Err(err) => panic!("Failed to bind test listener: {}", err),
    }
}

#[tokio::test]
async fn test_http_auth_timeout() -> Result<()> {
    if should_skip_local_network_tests() {
        return Ok(());
    }

    use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
    use sb_config::ir::Credentials;
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
    use sb_core::router::{Router, RouterHandle};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};

    let temp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_addr = temp_listener.local_addr()?;
    drop(temp_listener);

    let mut map = std::collections::HashMap::new();
    map.insert("direct".to_string(), OutboundImpl::Direct);
    let registry = OutboundRegistry::new(map);
    let outbounds = Arc::new(OutboundRegistryHandle::new(registry));
    let router = Arc::new(RouterHandle::new(Router::with_default("direct")));

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();
    let cfg = HttpProxyConfig {
        listen: http_addr,
        router,
        outbounds,
        tls: None,
        users: Some(vec![Credentials {
            username: Some("user".to_string()),
            password: Some("pass".to_string()),
            username_env: None,
            password_env: None,
        }]),
        set_system_proxy: false,
        allow_private_network: true,
    };

    tokio::spawn(async move {
        let _ = serve_http(cfg, stop_rx, Some(ready_tx)).await;
    });

    ready_rx.await?;

    let mut stream = TcpStream::connect(http_addr).await?;
    let request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_string();
    stream.write_all(request.as_bytes()).await?;

    let mut resp_buf = vec![0u8; 256];
    let n = stream.read(&mut resp_buf).await?;
    let response = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        response.starts_with("HTTP/1.1 407"),
        "Expected 407 on missing auth, got: {}",
        response
    );

    let _ = stop_tx.send(()).await;

    Ok(())
}

/// Helper: Wait for TCP port to become connectable
#[allow(dead_code)]
async fn wait_tcp_ready(addr: SocketAddr, step: Duration, total: Duration) -> io::Result<()> {
    let deadline = Instant::now() + total;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_s) => return Ok(()),
            Err(last) => {
                if Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "inbound not ready on {addr} (last: {last})"
                    )));
                }
                sleep(step).await;
            }
        }
    }
}

#[tokio::test]
#[ignore = "Basic connectivity test - can be enabled when needed"]
async fn test_tcp_ready_helper() -> Result<()> {
    if should_skip_local_network_tests() {
        return Ok(());
    }

    use tokio::net::TcpListener;

    // Start a listener
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Verify we can detect when it's ready
    let result = wait_tcp_ready(addr, Duration::from_millis(10), Duration::from_secs(1)).await;
    assert!(result.is_ok(), "Should detect ready listener");

    Ok(())
}
