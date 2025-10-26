#![cfg(feature = "adapter-http")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("Usage: http_connect_probe <host:port>");
        std::process::exit(2);
    }
    let authority = args.remove(0);
    // Router（可选）
    let decision = sb_core::router::decide_http(&authority);
    eprintln!("[router] decision={:?}", decision);
    // 选择直连/代理
    let mut stream = match sb_core::outbound::tcp::connect_auto(&authority, decision.as_str()).await
    {
        Ok(s) => s,
        Err(_) => sb_core::outbound::tcp::connect_direct(&authority).await?,
    };
    // 发一行 TLS ClientHello 前的探测（可选），这里只展示 CONNECT 已经 200 成功
    let host = authority
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or_else(|| authority.as_str());
    let req = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
    // 很多站会 400；我们只想看到通路是否 OK
    if let Err(e) = stream.write_all(req.as_bytes()).await {
        eprintln!("write failed: {}", e);
        return Ok(());
    }
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await?;
    println!("ok: read {} bytes", n);
    Ok(())
}
