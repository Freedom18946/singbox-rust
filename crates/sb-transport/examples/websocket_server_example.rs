//! WebSocket Server Example
//!
//! This example demonstrates how to use WebSocketListener to build a simple
//! proxy server that accepts WebSocket connections. This pattern can be used
//! for protocols like VMess, VLESS, and Trojan that support WebSocket transport.
//!
//! Run with: cargo run --example websocket_server_example --all-features

use sb_transport::websocket::{WebSocketListener, WebSocketServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Create TCP listener
    let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
    let local_addr = tcp_listener.local_addr()?;
    println!("WebSocket server listening on {}", local_addr);
    println!("Connect with: ws://127.0.0.1:8080/");

    // Create WebSocket listener with custom config
    let ws_config = WebSocketServerConfig {
        path: "/".to_string(),
        max_message_size: Some(64 * 1024 * 1024),
        max_frame_size: Some(16 * 1024 * 1024),
        require_path_match: false,
    };
    let ws_listener = WebSocketListener::new(tcp_listener, ws_config);

    println!("\nWaiting for WebSocket connections...");

    // Accept connections in a loop
    loop {
        match ws_listener.accept().await {
            Ok(mut stream) => {
                println!("New WebSocket connection accepted");

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    // Example: Echo server
                    let mut buffer = [0u8; 4096];

                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) => {
                                println!("Client disconnected");
                                break;
                            }
                            Ok(n) => {
                                println!("Received {} bytes", n);

                                // Echo back
                                if let Err(e) = stream.write_all(&buffer[..n]).await {
                                    eprintln!("Write error: {}", e);
                                    break;
                                }

                                if let Err(e) = stream.flush().await {
                                    eprintln!("Flush error: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("Read error: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("Accept error: {}", e);
            }
        }
    }
}
