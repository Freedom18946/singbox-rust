#![cfg(feature = "transport_ws")]
//! WebSocket server/client integration tests

use sb_transport::websocket::{
    WebSocketConfig, WebSocketDialer, WebSocketListener, WebSocketServerConfig,
};
use sb_transport::{Dialer, TcpDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_websocket_server_client_echo() {
    // Start WebSocket server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let ws_listener = WebSocketListener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = ws_listener.accept().await.unwrap();

        // Echo server: read and write back
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create WebSocket client
    let config = WebSocketConfig {
        path: "/".to_string(),
        ..Default::default()
    };
    let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
    let ws_dialer = WebSocketDialer::new(config, tcp_dialer);

    // Connect to server
    let mut client_stream = ws_dialer
        .connect("127.0.0.1", server_addr.port())
        .await
        .unwrap();

    // Send test data
    let test_data = b"Hello WebSocket!";
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
async fn test_websocket_server_multiple_clients() {
    // Start WebSocket server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let ws_listener = WebSocketListener::with_default_config(tcp_listener);

    // Spawn server task that handles multiple connections
    let server_handle = tokio::spawn(async move {
        for _ in 0..3 {
            let mut stream = ws_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                stream.write_all(&buf[..n]).await.unwrap();
                stream.flush().await.unwrap();
            });
        }
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect 3 clients concurrently
    let mut handles = vec![];
    for i in 0..3 {
        let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
        let ws_dialer = WebSocketDialer::new(WebSocketConfig::default(), tcp_dialer);
        let port = server_addr.port();

        let handle = tokio::spawn(async move {
            let mut stream = ws_dialer.connect("127.0.0.1", port).await.unwrap();
            let test_data = format!("Client {}", i);
            stream.write_all(test_data.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            let mut response = vec![0u8; test_data.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, test_data.as_bytes());
        });
        handles.push(handle);
    }

    // Wait for all clients
    for handle in handles {
        handle.await.unwrap();
    }

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_websocket_server_config() {
    let config = WebSocketServerConfig::default();
    assert_eq!(config.path, "/");
    assert_eq!(config.max_message_size, Some(64 * 1024 * 1024));
    assert_eq!(config.max_frame_size, Some(16 * 1024 * 1024));
    assert!(!config.require_path_match);
}

#[tokio::test]
async fn test_websocket_large_message() {
    // Start WebSocket server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let ws_listener = WebSocketListener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = ws_listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create WebSocket client
    let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
    let ws_dialer = WebSocketDialer::new(WebSocketConfig::default(), tcp_dialer);

    let mut client_stream = ws_dialer
        .connect("127.0.0.1", server_addr.port())
        .await
        .unwrap();

    // Send large message (100KB)
    let test_data = vec![0xAB; 100 * 1024];
    client_stream.write_all(&test_data).await.unwrap();
    client_stream.flush().await.unwrap();

    // Read echo response
    let mut response = vec![0u8; test_data.len()];
    client_stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response, test_data);

    drop(client_stream);
    server_handle.await.unwrap();
}
