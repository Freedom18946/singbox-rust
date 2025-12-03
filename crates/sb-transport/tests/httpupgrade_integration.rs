//! HTTPUpgrade server/client integration tests

#![cfg(feature = "transport_httpupgrade")]

use sb_transport::httpupgrade::{
    HttpUpgradeConfig, HttpUpgradeDialer, HttpUpgradeListener, HttpUpgradeServerConfig,
};
use sb_transport::{Dialer, TcpDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_httpupgrade_server_client_echo() {
    // Start HTTPUpgrade server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let listener = HttpUpgradeListener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();

        // Echo server: read and write back
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create HTTPUpgrade client
    let config = HttpUpgradeConfig {
        path: "/".to_string(),
        host: "".to_string(),
        headers: vec![],
    };
    let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
    let dialer = HttpUpgradeDialer::new(config, tcp_dialer);

    // Connect to server
    let mut client_stream = dialer
        .connect("127.0.0.1", server_addr.port())
        .await
        .unwrap();

    // Send test data
    let test_data = b"Hello HTTPUpgrade!";
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
async fn test_httpupgrade_server_config() {
    let config = HttpUpgradeServerConfig::default();
    assert_eq!(config.upgrade_protocol, "websocket");
    assert_eq!(config.path, "/");
    assert!(!config.require_path_match);
}

#[tokio::test]
async fn test_httpupgrade_large_message() {
    // Start HTTPUpgrade server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let listener = HttpUpgradeListener::with_default_config(tcp_listener);

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 100 * 1024]; // Match exact test data size

        // Read exactly the amount we expect
        match tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf).await {
            Ok(_) => {
                stream.write_all(&buf).await.unwrap();
                stream.flush().await.unwrap();
            }
            Err(e) => {
                eprintln!("Server read error: {}", e);
            }
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create HTTPUpgrade client
    let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
    let dialer = HttpUpgradeDialer::new(HttpUpgradeConfig::default(), tcp_dialer);

    let mut client_stream = dialer
        .connect("127.0.0.1", server_addr.port())
        .await
        .unwrap();

    // Send large message (100KB)
    let test_data = vec![0xEF; 100 * 1024];
    client_stream.write_all(&test_data).await.unwrap();
    client_stream.flush().await.unwrap();

    // Read echo response
    let mut response = vec![0u8; test_data.len()];
    client_stream.read_exact(&mut response).await.unwrap();

    assert_eq!(response, test_data);

    drop(client_stream);
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_httpupgrade_multiple_clients() {
    // Start HTTPUpgrade server
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let listener = HttpUpgradeListener::with_default_config(tcp_listener);

    // Spawn server task that handles multiple connections
    let server_handle = tokio::spawn(async move {
        for _ in 0..3 {
            let mut stream = listener.accept().await.unwrap();
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
        let dialer = HttpUpgradeDialer::new(HttpUpgradeConfig::default(), tcp_dialer);
        let port = server_addr.port();

        let handle = tokio::spawn(async move {
            let mut stream = dialer.connect("127.0.0.1", port).await.unwrap();
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
