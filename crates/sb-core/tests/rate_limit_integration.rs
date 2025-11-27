use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;

use sb_core::adapter::InboundService;
use sb_core::inbound::socks5::Socks5;

#[tokio::test]
async fn test_socks5_rate_limiting() {
    // Set environment variables for rate limiting
    // Limit to 2 connections per IP per 10 seconds
    std::env::set_var("SB_INBOUND_RATE_LIMIT_PER_IP", "2");
    std::env::set_var("SB_INBOUND_RATE_LIMIT_WINDOW_SEC", "10");

    // Start SOCKS5 server on a random port
    let port = 10000 + (fastrand::u16(0..10000));
    let listen = "127.0.0.1".to_string();
    
    let server = Socks5::new(listen.clone(), port);
    // Use std::thread::spawn to avoid "Cannot start a runtime from within a runtime"
    // because Socks5::serve calls block_on.
    std::thread::spawn(move || {
        if let Err(e) = server.serve() {
            eprintln!("Server error: {}", e);
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    let addr = format!("{}:{}", listen, port);

    // Connection 1: Should succeed
    let result1 = TcpStream::connect(&addr).await;
    assert!(result1.is_ok(), "Connection 1 should succeed");
    let _conn1 = result1.unwrap();

    // Connection 2: Should succeed
    let result2 = TcpStream::connect(&addr).await;
    assert!(result2.is_ok(), "Connection 2 should succeed");
    let _conn2 = result2.unwrap();

    // Connection 3: Should fail (dropped by server immediately after accept)
    // Note: TCP accept might succeed, but the connection should be closed immediately or dropped.
    // In our implementation, we `continue` the loop, which drops the stream.
    // The client might see a successful connect, but then immediate EOF or reset.
    // However, since we drop the stream without writing anything, the client `connect` usually returns OK,
    // but subsequent read/write will fail.
    // BUT, `TcpRateLimiter` logic is checked *after* accept.
    // So `TcpStream::connect` will likely succeed.
    // We need to verify that the server *closes* it.
    
    let result3 = TcpStream::connect(&addr).await;
    assert!(result3.is_ok(), "Connection 3 connect syscall usually succeeds even if dropped immediately");
    let mut conn3 = result3.unwrap();

    // Try to read from conn3. It should be closed.
    // SOCKS5 greeting is the first thing server sends.
    // If rate limited, server sends nothing and closes.
    let mut buf = [0u8; 10];
    let read_result = tokio::time::timeout(Duration::from_millis(500), conn3.peek(&mut buf)).await;
    
    match read_result {
        Ok(Ok(0)) => {
            // EOF, which is expected if server dropped connection
            println!("Connection 3 closed by server (EOF) as expected");
        }
        Ok(Ok(_)) => {
            panic!("Connection 3 received data, should have been dropped");
        }
        Ok(Err(e)) => {
             println!("Connection 3 read error: {}, likely reset", e);
        }
        Err(_) => {
            // Timeout implies connection is open but silent? 
            // If we dropped the stream, it should close.
            panic!("Connection 3 timed out, should have been closed");
        }
    }

    // Clean up
    // server thread will be killed when test process exits
    std::env::remove_var("SB_INBOUND_RATE_LIMIT_PER_IP");
    std::env::remove_var("SB_INBOUND_RATE_LIMIT_WINDOW_SEC");
}
