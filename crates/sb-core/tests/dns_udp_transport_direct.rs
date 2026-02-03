use sb_core::dns::transport::{DnsTransport, UdpTransport, UdpUpstream};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

fn is_permission_denied(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    if msg.contains("operation not permitted") || msg.contains("permission denied") {
        return true;
    }
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    })
}

fn build_dns_resp(id: u16, qname: &[u8], qtype: u16) -> Vec<u8> {
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
                                                // Answer
    out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to offset 12
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out.extend_from_slice(&60u32.to_be_bytes()); // TTL
    out.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
    out.extend_from_slice(&[127, 0, 0, 1]); // RDATA (127.0.0.1)
    out
}

fn parse_query(pkt: &[u8]) -> Option<(u16, Vec<u8>, u16)> {
    if pkt.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);

    // Find end of qname
    let mut i = 12;
    while i < pkt.len() {
        let len = pkt[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        i += len;
    }

    // Check if we have enough bytes for qtype and qclass
    if i + 4 > pkt.len() {
        return None;
    }

    let qname = pkt[12..i].to_vec(); // Include root null
    let qtype = u16::from_be_bytes([pkt[i], pkt[i + 1]]);

    Some((id, qname, qtype))
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
            if let Some((id, qname, qtype)) = parse_query(&buf[..n]) {
                let resp = build_dns_resp(id, &qname, qtype);
                let _ = sock.send_to(&resp, from).await;
            }
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn test_udp_transport_query() -> anyhow::Result<()> {
    let server_addr = match start_mock_dns().await {
        Ok(addr) => addr,
        Err(err) => {
            if is_permission_denied(&err) {
                eprintln!("skip: permission denied starting udp dns mock: {err}");
                return Ok(());
            }
            return Err(err);
        }
    };
    let upstream = UdpUpstream {
        addr: server_addr,
        timeout: Duration::from_secs(1),
    };
    let transport = UdpTransport::new(upstream);

    // Build a simple query (A record for example.com)
    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let response = match transport.query(&query).await {
        Ok(response) => response,
        Err(err) => {
            if is_permission_denied(&err) {
                eprintln!("skip: permission denied querying udp transport: {err}");
                return Ok(());
            }
            return Err(err);
        }
    };

    // Verify response ID matches original query ID
    assert_eq!(response[0], 0x12);
    assert_eq!(response[1], 0x34);

    // Verify response flags (Standard response, No error)
    // 0x8180 -> 1000 0001 1000 0000
    // QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
    assert_eq!(response[2], 0x81);
    assert_eq!(response[3], 0x80);

    Ok(())
}

#[tokio::test]
async fn test_udp_transport_timeout() -> anyhow::Result<()> {
    // Bind a socket but don't respond
    let sock = match UdpSocket::bind(("127.0.0.1", 0)).await {
        Ok(sock) => sock,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("skip: permission denied binding udp socket: {err}");
                return Ok(());
            }
            return Err(err.into());
        }
    };
    let addr = sock.local_addr()?;

    let upstream = UdpUpstream {
        addr,
        timeout: Duration::from_millis(200),
    };
    let transport = UdpTransport::new(upstream);

    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let result = transport.query(&query).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    if is_permission_denied(&err) {
        eprintln!("skip: permission denied on udp transport timeout: {err}");
        return Ok(());
    }
    assert!(err.to_string().contains("timeout"));

    Ok(())
}
