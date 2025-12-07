#![cfg(feature = "transport_mux")]
use sb_transport::multiplex::padding::PaddingStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test_padding_stream() {
    let (client, server) = tokio::io::duplex(1024);

    let client_handle = tokio::spawn(async move {
        let mut stream = PaddingStream::new(client, true);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
    });

    let server_handle = tokio::spawn(async move {
        let mut stream = PaddingStream::new(server, false);
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    });

    let _ = tokio::join!(client_handle, server_handle);
}

#[tokio::test]
async fn test_padding_stream_bidirectional() {
    let (client, server) = tokio::io::duplex(1024);

    let client_handle = tokio::spawn(async move {
        let mut stream = PaddingStream::new(client, true);
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    });

    let server_handle = tokio::spawn(async move {
        let mut stream = PaddingStream::new(server, false);
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let _ = tokio::join!(client_handle, server_handle);
}
