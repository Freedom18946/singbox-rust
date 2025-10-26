use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 直连上游
pub async fn connect_direct(authority: &str) -> anyhow::Result<TcpStream> {
    let (host, port) = split_authority(authority);
    let addr = format!("{host}:{port}");
    let s = TcpStream::connect(addr).await?;
    #[cfg(feature = "metrics")]
    metrics::counter!("outbound_connect_total", "kind"=>"tcp", "mode"=>"direct", "result"=>"ok")
        .increment(1);
    Ok(s)
}

/// 通过 HTTP 代理建立 CONNECT 隧道
pub async fn connect_via_http_proxy(authority: &str) -> anyhow::Result<TcpStream> {
    let proxy = std::env::var("SB_TCP_PROXY_HTTP")
        .map_err(|_| anyhow::anyhow!("SB_TCP_PROXY_HTTP not set"))?;
    let timeout_ms = std::env::var("SB_TCP_PROXY_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(8000);
    let req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    let mut s = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&proxy),
    )
    .await??;
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(512);
    read_until_double_crlf(&mut s, &mut buf).await?;
    let code = parse_http_status(&buf).ok_or_else(|| anyhow::anyhow!("bad proxy response"))?;
    if code != 200 {
        #[cfg(feature = "metrics")]
        metrics::counter!(
            "outbound_connect_total",
            "kind"=>"tcp",
            "mode"=>"http_proxy",
            "result"=>"fail",
            "code"=>code.to_string()   // 传 String，别取引用
        )
        .increment(1);
        return Err(anyhow::anyhow!("proxy connect failed: {code}"));
    }
    #[cfg(feature="metrics")]
    metrics::counter!("outbound_connect_total", "kind"=>"tcp", "mode"=>"http_proxy", "result"=>"ok").increment(1);
    Ok(s)
}

/// 选择：当 router 决策为 "proxy" 且设置了 `SB_TCP_PROXY_MODE=http` 时走代理，否则直连。
pub async fn connect_auto(authority: &str, decision: &str) -> anyhow::Result<TcpStream> {
    let mode = std::env::var("SB_TCP_PROXY_MODE").unwrap_or_default();
    if decision == "proxy" && mode.eq_ignore_ascii_case("http") {
        connect_via_http_proxy(authority).await
    } else {
        connect_direct(authority).await
    }
}

fn split_authority(authority: &str) -> (&str, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => (h, p.parse::<u16>().unwrap_or(443)),
        _ => (authority, 443),
    }
}

async fn read_until_double_crlf<S: AsyncReadExt + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    let mut tmp = [0u8; 256];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            break;
        }
    }
    Ok(())
}

fn parse_http_status(buf: &[u8]) -> Option<u16> {
    // 只看首行：HTTP/1.1 200 ...
    let line_end = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = &buf[..line_end];
    if !line.starts_with(b"HTTP/") {
        return None;
    }
    let mut it = line.split(|&b| b == b' ');
    it.next()?; // HTTP/1.1
    let code = it.next()?;
    let s = std::str::from_utf8(code).ok()?;
    s.parse::<u16>().ok()
}
