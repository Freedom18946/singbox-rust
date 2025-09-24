#![cfg(all(feature = "dns_dot", feature = "tls_rustls"))]
use crate::transport::tls::TlsClient;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub async fn query_dot_once(
    addr: SocketAddr,
    host: &str,
    qtype: u16,
    timeout_ms: u64,
) -> Result<(Vec<IpAddr>, Option<u32>)> {
    let req = crate::dns::udp::build_query(host, qtype)?;
    let tcp =
        tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??;
    let tls = TlsClient::from_env();
    let mut s = tls.connect(host.to_string(), tcp).await?;
    // DoT: 2 bytes length prefix
    let mut buf = Vec::with_capacity(2 + req.len());
    buf.extend_from_slice(&(req.len() as u16).to_be_bytes());
    buf.extend_from_slice(&req);
    tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        use tokio::io::AsyncWriteExt;
        s.write_all(&buf).await?;
        s.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    // read length
    let mut lenb = [0u8; 2];
    tokio::time::timeout(Duration::from_millis(timeout_ms), s.read_exact(&mut lenb)).await??;
    let n = u16::from_be_bytes(lenb) as usize;
    let mut resp = vec![0u8; n];
    tokio::time::timeout(Duration::from_millis(timeout_ms), s.read_exact(&mut resp)).await??;
    let (ips, ttl) = crate::dns::udp::parse_answers(&resp, qtype)?;
    Ok((ips, ttl))
}
