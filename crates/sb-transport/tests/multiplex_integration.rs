//! Multiplex (yamux) server/client integration tests

use sb_transport::multiplex::{MultiplexListener, MultiplexServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
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

#[tokio::test]
async fn test_multiplex_server_config() {
    let config = MultiplexServerConfig::default();
    assert_eq!(config.max_num_streams, 256);
    assert_eq!(config.initial_stream_window, 256 * 1024);
    assert_eq!(config.max_stream_window, 1024 * 1024);
    assert!(config.enable_keepalive);
}
