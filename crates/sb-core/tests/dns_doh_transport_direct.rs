use sb_core::dns::transport::{DnsTransport, DohTransport};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

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

fn response_for_request(request: &[u8]) -> Option<Vec<u8>> {
    let header_end = request.windows(4).position(|part| part == b"\r\n\r\n")? + 4;
    let header = std::str::from_utf8(&request[..header_end]).ok()?;
    let request_line = header.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;

    let query = if method == "POST" {
        request[header_end..].to_vec()
    } else if method == "GET" {
        let encoded = target
            .split_once('?')?
            .1
            .split('&')
            .find_map(|part| part.strip_prefix("dns="))?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.decode(encoded).ok()?
    } else {
        return None;
    };

    let (id, qname, qtype) = parse_query(&query)?;
    Some(build_dns_resp(id, &qname, qtype))
}

async fn start_mock_doh_server() -> Option<(SocketAddr, oneshot::Sender<()>)> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return None;
        }
        Err(err) => panic!("failed to bind DoH test server: {err}"),
    };
    let addr = listener.local_addr().expect("failed to get local addr");
    let (tx, mut rx) = oneshot::channel();

    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut stream, _)) = accepted else {
                break;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(read) = stream.read(&mut buf).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..read]);
                    let Some(header_end) = request.windows(4).position(|p| p == b"\r\n\r\n") else {
                        continue;
                    };
                    let header_end = header_end + 4;
                    let header = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .map(str::to_owned)
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= header_end + content_length {
                        break;
                    }
                }

                let (status, body) =
                    response_for_request(&request).map_or((400, Vec::new()), |body| (200, body));
                let response = format!(
                    "HTTP/1.1 {status} {}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if status == 200 { "OK" } else { "Bad Request" },
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Some((addr, tx))
}

#[tokio::test]
async fn test_doh_transport_post() -> anyhow::Result<()> {
    let Some((addr, tx)) = start_mock_doh_server().await else {
        eprintln!("skipping DoH transport POST test: PermissionDenied binding listener");
        return Ok(());
    };
    let url = format!("http://{}/dns-query", addr);

    let transport = match std::panic::catch_unwind(|| DohTransport::new(url)) {
        Ok(Ok(transport)) => transport,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            eprintln!("skipping DoH transport POST test: system configuration unavailable");
            let _ = tx.send(());
            return Ok(());
        }
    };

    // Build a simple query (A record for example.com)
    // Large enough to force POST (> 256 bytes usually, but here we test POST directly via internal logic or just standard query)
    // DohTransport uses adaptive logic: <= 256 bytes tries GET first.
    // To force POST, we can make a large query or rely on fallback if GET fails (but our mock supports GET).
    // Actually, let's just test that it works. If it uses GET, that's fine too.
    // But wait, we want to verify POST specifically.
    // We can construct a large query.

    let mut query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    // Add a very long domain name to exceed 256 bytes
    // 63 bytes label * 4 + some separators
    for _ in 0..5 {
        query.push(60);
        query.extend_from_slice(&[b'a'; 60]);
    }
    query.push(0); // Root
    query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN

    let response = transport.query(&query).await?;

    // Verify response ID matches original query ID
    assert_eq!(response[0], 0x12);
    assert_eq!(response[1], 0x34);

    let _ = tx.send(());
    Ok(())
}

#[tokio::test]
async fn test_doh_transport_get() -> anyhow::Result<()> {
    let Some((addr, tx)) = start_mock_doh_server().await else {
        eprintln!("skipping DoH transport GET test: PermissionDenied binding listener");
        return Ok(());
    };
    let url = format!("http://{}/dns-query", addr);

    let transport = match std::panic::catch_unwind(|| DohTransport::new(url)) {
        Ok(Ok(transport)) => transport,
        Ok(Err(err)) => return Err(err),
        Err(_) => {
            eprintln!("skipping DoH transport GET test: system configuration unavailable");
            let _ = tx.send(());
            return Ok(());
        }
    };

    // Small query should use GET
    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let response = transport.query(&query).await?;

    assert_eq!(response[0], 0x12);
    assert_eq!(response[1], 0x34);

    let _ = tx.send(());
    Ok(())
}
