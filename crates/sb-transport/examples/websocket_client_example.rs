//! WebSocket Client Example
//!
//! This example demonstrates how to use WebSocketDialer to connect to a WebSocket server.
//!
//! Run the server first: cargo run --example websocket_server_example --all-features
//! Then run this client: cargo run --example websocket_client_example --all-features

use sb_transport::websocket::{WebSocketDialer, WebSocketConfig};
use sb_transport::{Dialer, TcpDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("Connecting to WebSocket server at ws://127.0.0.1:8080/");

    // Create WebSocket dialer with custom config
    let ws_config = WebSocketConfig {
        path: "/".to_string(),
        headers: vec![
            ("User-Agent".to_string(), "singbox-rust-example/1.0".to_string()),
        ],
        max_message_size: Some(64 * 1024 * 1024),
        max_frame_size: Some(16 * 1024 * 1024),
        early_data: false,
    };

    let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
    let ws_dialer = WebSocketDialer::new(ws_config, tcp_dialer);

    // Connect to server
    let mut stream = ws_dialer.connect("127.0.0.1", 8080).await?;
    println!("Connected to WebSocket server!");

    // Send test messages
    for i in 1..=5 {
        let message = format!("Hello from client, message #{}", i);
        println!("\nSending: {}", message);

        stream.write_all(message.as_bytes()).await?;
        stream.flush().await?;

        // Read echo response
        let mut buffer = vec![0u8; message.len()];
        stream.read_exact(&mut buffer).await?;

        let response = String::from_utf8_lossy(&buffer);
        println!("Received: {}", response);

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    println!("\n✅ All messages sent and echoed successfully!");
    Ok(())
}
