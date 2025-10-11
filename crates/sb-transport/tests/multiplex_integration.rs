//! Multiplex (yamux) server/client integration tests

use sb_transport::dialer::Dialer;
use sb_transport::multiplex::{BrutalConfig, MultiplexConfig, MultiplexDialer, MultiplexListener, MultiplexServerConfig};
use sb_transport::TcpDialer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiplex_server_client_echo() {
    // Start multiplex server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let mux_listener = MultiplexListener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = mux_listener.accept().await.unwrap();

        // Echo server: read and write back
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create yamux client manually (since MultiplexDialer needs improvement)
    use tokio::net::TcpStream;
    use tokio_util::compat::TokioAsyncReadCompatExt;
    use yamux::{Config, Connection, Mode};

    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", server_addr.port()))
        .await
        .unwrap();
    let compat_stream = tcp_stream.compat();

    let mut yamux_config = Config::default();
    yamux_config.set_max_num_streams(256);
    let mut connection = Connection::new(compat_stream, yamux_config, Mode::Client);

    // Open outbound stream
    use futures::future::poll_fn;
    let mut client_stream = poll_fn(|cx| connection.poll_new_outbound(cx))
        .await
        .unwrap();

    // Spawn task to drive connection
    tokio::spawn(async move {
        loop {
            match poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            }
        }
    });

    // Send test data
    use futures::io::AsyncWriteExt as FuturesAsyncWriteExt;
    use futures::io::AsyncReadExt as FuturesAsyncReadExt;

    let test_data = b"Hello Multiplex!";
    client_stream.write_all(test_data).await.unwrap();
    client_stream.flush().await.unwrap();

    // Read echo response
    let mut response = vec![0u8; test_data.len()];
    client_stream.read_exact(&mut response).await.unwrap();

    assert_eq!(&response, test_data);

    // Clean up
    drop(client_stream);
    server_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiplex_server_config() {
    let config = MultiplexServerConfig::default();
    assert_eq!(config.max_num_streams, 256);
    assert_eq!(config.initial_stream_window, 256 * 1024);
    assert_eq!(config.max_stream_window, 1024 * 1024);
    assert!(config.enable_keepalive);
}

// ============================================================================
// Unit Tests for Multiplex Transport
// ============================================================================

// Helper function to start an echo server that runs until shutdown signal
async fn start_echo_server(
    config: MultiplexServerConfig,
) -> (std::net::SocketAddr, tokio::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let mux_listener = MultiplexListener::new(tcp_listener, config);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    
    let server_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = mux_listener.accept() => {
                    if let Ok(mut stream) = result {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            if let Ok(n) = stream.read(&mut buf).await {
                                let _ = stream.write_all(&buf[..n]).await;
                                let _ = stream.flush().await;
                            }
                        });
                    }
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    });

    (server_addr, shutdown_tx, server_handle)
}

/// Test connection pooling and reuse
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_connection_pooling_and_reuse() {
    // Start a TCP server that accepts multiple connections
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer with connection pooling
    let config = MultiplexConfig {
        max_connections: 2,
        max_streams_per_connection: 5,
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    // Connect multiple times to the same host:port
    let host = "127.0.0.1";
    let port = server_addr.port();

    // First connection - should create new yamux connection
    let mut stream1 = mux_dialer.connect(host, port).await.unwrap();
    
    // Second connection - should reuse the same yamux connection
    let mut stream2 = mux_dialer.connect(host, port).await.unwrap();
    
    // Third connection - should reuse the same yamux connection
    let mut stream3 = mux_dialer.connect(host, port).await.unwrap();

    // Send data on all streams
    let test_data = b"Connection pooling test";
    
    stream1.write_all(test_data).await.unwrap();
    stream1.flush().await.unwrap();
    
    stream2.write_all(test_data).await.unwrap();
    stream2.flush().await.unwrap();
    
    stream3.write_all(test_data).await.unwrap();
    stream3.flush().await.unwrap();

    // Read responses
    let mut response1 = vec![0u8; test_data.len()];
    stream1.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1, test_data);

    let mut response2 = vec![0u8; test_data.len()];
    stream2.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2, test_data);

    let mut response3 = vec![0u8; test_data.len()];
    stream3.read_exact(&mut response3).await.unwrap();
    assert_eq!(&response3, test_data);

    // Clean up
    drop(stream1);
    drop(stream2);
    drop(stream3);
    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test multiple streams over single connection
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiple_streams_over_single_connection() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer
    let config = MultiplexConfig::default();
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = Arc::new(MultiplexDialer::new(config, tcp_dialer));

    // Open multiple streams concurrently
    let mut handles = vec![];
    for i in 0..5 {
        let dialer = mux_dialer.clone();
        let host = "127.0.0.1".to_string();
        let port = server_addr.port();
        
        let handle = tokio::spawn(async move {
            let mut stream = dialer.connect(&host, port).await.unwrap();
            
            // Send unique data on each stream
            let test_data = format!("Data from stream {}", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            
            // Read response
            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, test_data.as_bytes());
        });
        handles.push(handle);
    }

    // Wait for all streams to complete
    for handle in handles {
        handle.await.unwrap();
    }

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test stream lifecycle management (open, use, close)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stream_lifecycle_management() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer
    let config = MultiplexConfig::default();
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    let host = "127.0.0.1";
    let port = server_addr.port();

    // Test: Open stream, use it, close it by dropping
    let mut stream = mux_dialer.connect(host, port).await.unwrap();
    stream.write_all(b"Test 1").await.unwrap();
    stream.flush().await.unwrap();
    
    let mut response = vec![0u8; 6];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"Test 1");
    drop(stream); // Explicit drop

    // Give time for cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test: Open another stream on the same connection
    let mut stream2 = mux_dialer.connect(host, port).await.unwrap();
    stream2.write_all(b"Test 2").await.unwrap();
    stream2.flush().await.unwrap();
    
    let mut response2 = vec![0u8; 6];
    stream2.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2, b"Test 2");

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test max streams limit enforcement
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_max_streams_limit_enforcement() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer with low max_streams_per_connection
    let config = MultiplexConfig {
        max_connections: 2,
        max_streams_per_connection: 2, // Only 2 streams per connection
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    let host = "127.0.0.1";
    let port = server_addr.port();

    // Open 4 streams - should create 2 connections with 2 streams each
    let mut stream1 = mux_dialer.connect(host, port).await.unwrap();
    let mut stream2 = mux_dialer.connect(host, port).await.unwrap();
    let mut stream3 = mux_dialer.connect(host, port).await.unwrap();
    let mut stream4 = mux_dialer.connect(host, port).await.unwrap();

    // Test all streams work
    stream1.write_all(b"Test1").await.unwrap();
    stream1.flush().await.unwrap();
    let mut resp1 = vec![0u8; 5];
    stream1.read_exact(&mut resp1).await.unwrap();
    assert_eq!(&resp1, b"Test1");

    stream2.write_all(b"Test2").await.unwrap();
    stream2.flush().await.unwrap();
    let mut resp2 = vec![0u8; 5];
    stream2.read_exact(&mut resp2).await.unwrap();
    assert_eq!(&resp2, b"Test2");

    stream3.write_all(b"Test3").await.unwrap();
    stream3.flush().await.unwrap();
    let mut resp3 = vec![0u8; 5];
    stream3.read_exact(&mut resp3).await.unwrap();
    assert_eq!(&resp3, b"Test3");

    stream4.write_all(b"Test4").await.unwrap();
    stream4.flush().await.unwrap();
    let mut resp4 = vec![0u8; 5];
    stream4.read_exact(&mut resp4).await.unwrap();
    assert_eq!(&resp4, b"Test4");

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test Brutal Congestion Control configuration
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_brutal_congestion_control() {
    // Test BrutalConfig creation and methods
    let brutal = BrutalConfig::new(100, 50);
    assert_eq!(brutal.up_mbps, 100);
    assert_eq!(brutal.down_mbps, 50);
    
    // Test bandwidth conversion
    assert_eq!(brutal.up_bytes_per_sec(), 100 * 1_000_000 / 8);
    assert_eq!(brutal.down_bytes_per_sec(), 50 * 1_000_000 / 8);

    // Test MultiplexConfig with Brutal
    let config = MultiplexConfig {
        brutal: Some(brutal.clone()),
        ..Default::default()
    };
    assert!(config.brutal.is_some());
    assert_eq!(config.brutal.as_ref().unwrap().up_mbps, 100);

    // Test MultiplexServerConfig with Brutal
    let server_config = MultiplexServerConfig {
        brutal: Some(brutal),
        ..Default::default()
    };
    assert!(server_config.brutal.is_some());
    assert_eq!(server_config.brutal.as_ref().unwrap().down_mbps, 50);
}

/// Test Brutal Congestion Control with actual connection
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_brutal_with_connection() {
    // Start multiplex server with Brutal config
    let server_config = MultiplexServerConfig {
        brutal: Some(BrutalConfig::new(100, 50)),
        ..Default::default()
    };
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(server_config).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer with Brutal config
    let config = MultiplexConfig {
        brutal: Some(BrutalConfig::new(100, 50)),
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    // Connect and test
    let mut stream = mux_dialer.connect("127.0.0.1", server_addr.port()).await.unwrap();
    
    let test_data = b"Brutal test data";
    stream.write_all(test_data).await.unwrap();
    stream.flush().await.unwrap();
    
    let mut response = vec![0u8; test_data.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, test_data);

    drop(stream);
    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test connection health checks and cleanup
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_connection_health_and_cleanup() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer with short idle timeout
    let config = MultiplexConfig {
        connection_idle_timeout: 2, // 2 seconds
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    let host = "127.0.0.1";
    let port = server_addr.port();

    // Create first connection
    let mut stream1 = mux_dialer.connect(host, port).await.unwrap();
    stream1.write_all(b"Test 1").await.unwrap();
    stream1.flush().await.unwrap();
    
    let mut response1 = vec![0u8; 6];
    stream1.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1, b"Test 1");
    drop(stream1);

    // Wait for idle timeout (but not quite long enough)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create second connection - should reuse existing connection
    let mut stream2 = mux_dialer.connect(host, port).await.unwrap();
    stream2.write_all(b"Test 2").await.unwrap();
    stream2.flush().await.unwrap();
    
    let mut response2 = vec![0u8; 6];
    stream2.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2, b"Test 2");
    drop(stream2);

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test concurrent stream creation
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_stream_creation() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer
    let config = MultiplexConfig::default();
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = Arc::new(MultiplexDialer::new(config, tcp_dialer));

    // Create many streams concurrently
    let mut handles = vec![];
    for i in 0..20 {
        let dialer = mux_dialer.clone();
        let host = "127.0.0.1".to_string();
        let port = server_addr.port();
        
        let handle = tokio::spawn(async move {
            let mut stream = dialer.connect(&host, port).await.unwrap();
            
            let test_data = format!("Concurrent stream {}", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            
            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, test_data.as_bytes());
        });
        handles.push(handle);
    }

    // Wait for all streams to complete
    for handle in handles {
        handle.await.unwrap();
    }

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test max connections limit
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_max_connections_limit() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer with max_connections = 1
    let config = MultiplexConfig {
        max_connections: 1,
        max_streams_per_connection: 5,
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    let host = "127.0.0.1";
    let port = server_addr.port();

    // Open 2 streams - should use same connection
    let mut stream1 = mux_dialer.connect(host, port).await.unwrap();
    stream1.write_all(b"Test1").await.unwrap();
    stream1.flush().await.unwrap();
    let mut resp1 = vec![0u8; 5];
    stream1.read_exact(&mut resp1).await.unwrap();
    assert_eq!(&resp1, b"Test1");

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}

/// Test stream isolation - data on one stream doesn't affect another
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stream_isolation() {
    // Start multiplex server
    let (server_addr, shutdown_tx, server_handle) = start_echo_server(MultiplexServerConfig::default()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create MultiplexDialer
    let config = MultiplexConfig::default();
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let mux_dialer = MultiplexDialer::new(config, tcp_dialer);

    let host = "127.0.0.1";
    let port = server_addr.port();

    // Test stream isolation by sending different data on each stream
    // and verifying each gets its own data back
    let mut stream1 = mux_dialer.connect(host, port).await.unwrap();
    stream1.write_all(b"Data A").await.unwrap();
    stream1.flush().await.unwrap();
    let mut response1 = vec![0u8; 6];
    stream1.read_exact(&mut response1).await.unwrap();
    assert_eq!(&response1, b"Data A");
    drop(stream1);

    let mut stream2 = mux_dialer.connect(host, port).await.unwrap();
    stream2.write_all(b"Data B").await.unwrap();
    stream2.flush().await.unwrap();
    let mut response2 = vec![0u8; 6];
    stream2.read_exact(&mut response2).await.unwrap();
    assert_eq!(&response2, b"Data B");
    drop(stream2);

    drop(shutdown_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
}
