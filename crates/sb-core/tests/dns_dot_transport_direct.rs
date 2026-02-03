use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sb_core::dns::transport::{DnsTransport, DotTransport};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

// Generate self-signed cert for testing
fn generate_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = cert.key_pair.serialize_der();
    let cert = cert.cert.der().to_vec();
    (
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::try_from(key).unwrap(),
    )
}

async fn start_mock_dot_server(
) -> anyhow::Result<Option<(SocketAddr, Vec<CertificateDer<'static>>)>> {
    let (certs, key) = generate_cert();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                    return;
                };

                // Read length prefix (2 bytes)
                let mut len_buf = [0u8; 2];
                if tls_stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;

                // Read query
                let mut buf = vec![0u8; len];
                if tls_stream.read_exact(&mut buf).await.is_err() {
                    return;
                }

                if let Some((id, qname, qtype)) = parse_query(&buf) {
                    let resp = build_dns_resp(id, &qname, qtype);

                    // Write length prefix
                    let resp_len = resp.len() as u16;
                    if tls_stream.write_all(&resp_len.to_be_bytes()).await.is_err() {
                        return;
                    }

                    // Write response
                    let _ = tls_stream.write_all(&resp).await;
                }
            });
        }
    });

    Ok(Some((addr, certs)))
}

#[tokio::test]
async fn test_dot_transport_query() -> anyhow::Result<()> {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    let Some((server_addr, _certs)) = start_mock_dot_server().await? else {
        eprintln!("skipping DoT transport test: PermissionDenied binding listener");
        return Ok(());
    };

    // Use skip_verify=true for self-signed cert
    let transport = DotTransport::new_with_tls(
        server_addr,
        "localhost".to_string(),
        Vec::new(),
        Vec::new(),
        true, // skip_verify
    )?;

    // Build a simple query (A record for example.com)
    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let response = transport.query(&query).await?;

    // Verify response ID matches original query ID
    assert_eq!(response[0], 0x12);
    assert_eq!(response[1], 0x34);

    // Verify response flags
    assert_eq!(response[2], 0x81);
    assert_eq!(response[3], 0x80);

    Ok(())
}
