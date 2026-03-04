use sb_transport::{webpki_roots_config, Dialer as _, TcpDialer, TlsDialer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".into());
    let port: u16 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "443".into())
        .parse()
        .unwrap_or(443);
    let addr = format!("{host}:{port}");
    let tls = TlsDialer {
        inner: TcpDialer::default(),
        config: webpki_roots_config(),
        sni_override: Some(host.clone()),
        alpn: None,
    };

    println!("Connecting to {addr}...");
    println!("Starting TLS handshake with {}...", host);
    let mut s = tls
        .connect(&host, port)
        .await
        .map_err(|err| anyhow::anyhow!("tls connect failed: {err}"))?;

    // 可选：发一个最小 HTTP/1.1 请求验证往返
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;

    // 读取一些响应数据
    let mut buf = vec![0u8; 1024];
    let n = s.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    println!("TLS handshake successful -> {host}:{port}");
    println!("HTTP response preview ({} bytes):", n);
    println!(
        "{}",
        response.lines().take(5).collect::<Vec<_>>().join("\n")
    );

    Ok(())
}
