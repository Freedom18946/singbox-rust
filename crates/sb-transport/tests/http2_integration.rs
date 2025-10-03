//! HTTP/2 server/client integration tests

use sb_transport::http2::{Http2Dialer, Http2Listener, Http2ServerConfig, Http2Config};
use sb_transport::{Dialer, TcpDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_http2_server_client_echo() {
    // Start HTTP/2 server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let h2_listener = Http2Listener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = h2_listener.accept().await.unwrap();

        // Echo server: read and write back
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create HTTP/2 client
    let config = Http2Config {
        path: "/".to_string(),
        host: "localhost".to_string(),
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let h2_dialer = Http2Dialer::new(config, tcp_dialer);

    // Connect to server
    let mut client_stream = h2_dialer
        .connect("127.0.0.1", server_addr.port())
        .await
        .unwrap();

    // Send test data
    let test_data = b"Hello HTTP/2!";
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

#[tokio::test]
async fn test_http2_server_config() {
    let config = Http2ServerConfig::default();
    assert_eq!(config.max_concurrent_streams, 256);
    assert_eq!(config.initial_window_size, 1024 * 1024);
    assert_eq!(config.initial_connection_window_size, 1024 * 1024);
}

#[tokio::test]
async fn test_http2_large_message() {
    // Start HTTP/2 server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let h2_listener = Http2Listener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = h2_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create HTTP/2 client
    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let h2_dialer = Http2Dialer::new(Http2Config::default(), tcp_dialer);

    let mut client_stream = h2_dialer
        .connect("127.0.0.1", server_addr.port())
        .await
        .unwrap();

    // Send large message (100KB)
    let test_data = vec![0xCD; 100 * 1024];
    client_stream.write_all(&test_data).await.unwrap();
    client_stream.flush().await.unwrap();

    // Read echo response
    let mut response = vec![0u8; test_data.len()];
    client_stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response, test_data);

    drop(client_stream);
    server_handle.await.unwrap();
}
