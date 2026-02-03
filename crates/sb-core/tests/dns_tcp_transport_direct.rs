use sb_core::dns::transport::{DnsTransport, TcpTransport};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn is_permission_denied(err: &anyhow::Error) -> bool {
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

async fn start_mock_tcp_dns() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                // Read length prefix (2 bytes)
                let mut len_buf = [0u8; 2];
                if socket.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;

                // Read query
                let mut buf = vec![0u8; len];
                if socket.read_exact(&mut buf).await.is_err() {
                    return;
                }

                if let Some((id, qname, qtype)) = parse_query(&buf) {
                    let resp = build_dns_resp(id, &qname, qtype);

                    // Write length prefix
                    let resp_len = resp.len() as u16;
                    if socket.write_all(&resp_len.to_be_bytes()).await.is_err() {
                        return;
                    }

                    // Write response
                    let _ = socket.write_all(&resp).await;
                }
            });
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn test_tcp_transport_query() -> anyhow::Result<()> {
    let server_addr = match start_mock_tcp_dns().await {
        Ok(addr) => addr,
        Err(err) => {
            if is_permission_denied(&err) {
                eprintln!("skip: permission denied starting mock tcp dns: {err}");
                return Ok(());
            }
            return Err(err);
        }
    };
    let transport = TcpTransport::new(server_addr).with_timeout(Duration::from_secs(1));

    // Build a simple query (A record for example.com)
    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let response = match transport.query(&query).await {
        Ok(resp) => resp,
        Err(err) => {
            if is_permission_denied(&err) {
                eprintln!("skip: permission denied on tcp dns query: {err}");
                return Ok(());
            }
            return Err(err);
        }
    };

    // Verify response ID matches original query ID
    assert_eq!(response[0], 0x12);
    assert_eq!(response[1], 0x34);

    // Verify response flags
    assert_eq!(response[2], 0x81);
    assert_eq!(response[3], 0x80);

    Ok(())
}

#[tokio::test]
async fn test_tcp_transport_timeout() -> anyhow::Result<()> {
    // Bind a listener but never accept/respond
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("skip: permission denied binding mock tcp dns: {err}");
                return Ok(());
            }
            return Err(err.into());
        }
    };
    let addr = listener.local_addr()?;

    // Don't spawn accept loop, so connect might succeed (backlog) but write/read will hang or fail
    // Or if we accept but don't read/write:
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                continue;
            };
            // Just hold the connection open without sending anything
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(socket);
        }
    });

    let transport = TcpTransport::new(addr).with_timeout(Duration::from_millis(200));

    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let result = transport.query(&query).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    if is_permission_denied(&err) {
        eprintln!("skip: permission denied on tcp dns timeout test: {err}");
        return Ok(());
    }
    // Error could be "timeout" or "connection closed" depending on timing, but mostly timeout
    // TcpTransport wraps errors with context, so we check string representation
    println!("Error: {:?}", err);
    assert!(err.to_string().to_lowercase().contains("timeout"));

    Ok(())
}
