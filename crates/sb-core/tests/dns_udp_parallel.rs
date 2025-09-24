use sb_core::dns::client::DnsClient;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

// 简易 DNS 响应构造：复用 client.rs 的 wire 规则（同构）
fn build_dns_resp(id: u16, qname: &[u8], qtype: u16, ttl: u32) -> Vec<u8> {
    let mut out = Vec::new();
    // header: ID, flags=0x8180 (standard response, no error), QD=1, AN=1, NS=0, AR=0
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    // Question (copy)
    out.extend_from_slice(qname);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
                                                // Answer: NAME as pointer to 0x0c (first label), TYPE, CLASS, TTL, RDLEN, RDATA
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to offset 12
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&ttl.to_be_bytes());
    match qtype {
        1 => {
            // A
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&[127, 0, 0, 42]);
        }
        28 => {
            // AAAA
            out.extend_from_slice(&16u16.to_be_bytes());
            let mut a = [0u8; 16];
            a[15] = 42;
            out.extend_from_slice(&a);
        }
        _ => unreachable!(),
    }
    out
}

fn parse_qname_and_qtype(pkt: &[u8]) -> Option<(usize, Vec<u8>, u16, u16)> {
    if pkt.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let mut i = 12usize;
    let mut qname = Vec::new();
    loop {
        if i >= pkt.len() {
            return None;
        }
        let l = pkt[i] as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if i + l > pkt.len() {
            return None;
        }
        qname.extend_from_slice(&pkt[i - 1..i + l]); // 包含长度字节，便于复用
        i += l;
    }
    qname.push(0); // root
    if i + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[i], pkt[i + 1]]);
    let qclass = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
    Some((id as usize, qname, qtype, qclass))
}

async fn start_mock_dns() -> anyhow::Result<SocketAddr> {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let addr = sock.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if n < 12 {
                continue;
            }
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            if let Some((_id, qname, qtype, _qclass)) = parse_qname_and_qtype(&buf[..n]) {
                // 控制返回延迟：A 先回，AAAA 晚点回（或反之），便于观察并发行为
                let (delay_ms, ttl) = match qtype {
                    1 => (20u64, 60u32),
                    28 => (5u64, 30u32),
                    _ => (0, 0),
                };
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let resp = build_dns_resp(id, &qname, qtype, ttl);
                let _ = sock.send_to(&resp, from).await;
            }
        }
    });
    Ok(addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_parallel_a_aaaa() -> anyhow::Result<()> {
    let upstream = start_mock_dns().await?;
    // 开启并发 UDP DNS
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_DNS_MODE", "udp");
    std::env::set_var("SB_DNS_UPSTREAM", upstream.to_string());
    std::env::set_var("SB_DNS_PARALLEL", "1");
    let c = DnsClient::new(Duration::from_secs(5));
    let addrs = c.resolve("example.test", 853).await?;
    assert!(addrs.iter().any(|sa| sa.ip().is_ipv4()));
    assert!(addrs.iter().any(|sa| sa.ip().is_ipv6()));
    Ok(())
}
