use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sb_core::dns::transport::{DnsTransport, DoqTransport};
use std::net::SocketAddr;
use std::sync::Arc;



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

async fn start_mock_doq_server() -> anyhow::Result<(SocketAddr, Vec<CertificateDer<'static>>)> {
    let (certs, key) = generate_cert();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)?;
    server_crypto.alpn_protocols = vec![b"doq".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    // Configure transport parameters if needed, defaults are usually fine
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_bidi_streams(100u8.into());

    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;

    tokio::spawn(async move {
        while let Some(conn) = endpoint.accept().await {
            tokio::spawn(async move {
                let connection = match conn.await {
                    Ok(c) => c,
                    Err(_) => return,
                };

                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        // Read length prefix (2 bytes)
                        let mut len_buf = [0u8; 2];
                        if recv.read_exact(&mut len_buf).await.is_err() {
                            return;
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;

                        // Read query
                        let mut buf = vec![0u8; len];
                        if recv.read_exact(&mut buf).await.is_err() {
                            return;
                        }

                        if let Some((id, qname, qtype)) = parse_query(&buf) {
                            let resp = build_dns_resp(id, &qname, qtype);

                            // Write length prefix
                            let resp_len = resp.len() as u16;
                            if send.write_all(&resp_len.to_be_bytes()).await.is_err() {
                                return;
                            }

                            // Write response
                            let _ = send.write_all(&resp).await;
                            let _ = send.finish();
                        }
                    });
                }
            });
        }
    });

    Ok((addr, certs))
}

#[tokio::test]
async fn test_doq_transport_query() -> anyhow::Result<()> {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server_addr, _certs) = start_mock_doq_server().await?;

    // Use skip_verify=true for self-signed cert
    let transport = DoqTransport::new_with_tls(
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
