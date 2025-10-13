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
    let req = build_query(host, qtype)?;
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
    let (ips, ttl) = parse_answers(&resp, qtype)?;
    Ok((ips, ttl))
}

fn build_query(host: &str, qtype: u16) -> Result<Vec<u8>> {
    // 12B header + qname + QTYPE/QCLASS
    let id = (std::time::Instant::now().elapsed().as_nanos() as u16).to_be_bytes();
    // header
    let mut out = vec![
        id[0], id[1], // ID
        0x01, 0x00, // RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    // QNAME
    for label in host.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return Err(anyhow::anyhow!("bad label"));
        }
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0); // root
                 // QTYPE / QCLASS=IN(1)
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn parse_answers(mut buf: &[u8], want: u16) -> Result<(Vec<IpAddr>, Option<u32>)> {
    if buf.len() < 12 {
        return Err(anyhow::anyhow!("short dns header"));
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    // 跳过 header
    buf = &buf[12..];
    // 跳过 Question
    for _ in 0..qd {
        let mut i = 0;
        loop {
            if i >= buf.len() {
                return Err(anyhow::anyhow!("bad question section"));
            }
            let len = buf[i];
            if len == 0 {
                break;
            }
            if (len & 0xc0) == 0xc0 {
                i += 2;
                break;
            }
            i += 1 + (len as usize);
        }
        buf = &buf[i + 1 + 4..]; // name terminator + QTYPE + QCLASS
    }
    let mut ips = Vec::new();
    let mut ttl_min: Option<u32> = None;
    // 解析答案
    for _ in 0..an {
        let mut i = 0;
        // 跳过 NAME
        loop {
            if i >= buf.len() {
                break;
            }
            let len = buf[i];
            if len == 0 {
                i += 1;
                break;
            }
            if (len & 0xc0) == 0xc0 {
                i += 2;
                break;
            }
            i += 1 + (len as usize);
        }
        if i + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let ttl = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if i + rdlen > buf.len() {
            break;
        }
        if rtype == want {
            ttl_min = ttl_min.min(Some(ttl)).or(Some(ttl));
            match want {
                1 if rdlen == 4 => {
                    // A
                    let ip = std::net::Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
                    ips.push(IpAddr::V4(ip));
                }
                28 if rdlen == 16 => {
                    // AAAA
                    let mut ip6 = [0u8; 16];
                    ip6.copy_from_slice(&buf[i..i + 16]);
                    ips.push(IpAddr::V6(std::net::Ipv6Addr::from(ip6)));
                }
                _ => {}
            }
        }
        buf = &buf[i + rdlen..];
    }
    Ok((ips, ttl_min))
}
