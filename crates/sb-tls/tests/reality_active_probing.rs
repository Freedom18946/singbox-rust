//! REALITY server active-probing resistance harness.
//!
//! Locally decidable evidence that the canonical Rust REALITY server
//! (`RealityAcceptor`) is indistinguishable from its decoy target under active
//! probing: every connection that does not authenticate is transparently relayed
//! to the real target, so a prober observes the target's genuine TLS handshake
//! and certificate — never a dropped/reset connection.
//!
//! Topology (all on 127.0.0.1, no external network):
//! - a rustls "decoy" TLS server with a known self-signed certificate;
//! - a `RealityAcceptor` whose `target` points at the decoy;
//! - probe clients connecting to the REALITY port.
//!
//! Oracle: a client connecting directly to the decoy records the decoy leaf
//! certificate. Each non-authenticated probe against the REALITY port must
//! observe the identical certificate (relay) rather than an error.
//! First-flight timing is checked independently: the decoy must be connected
//! before client input, receive partial input immediately, and return data before
//! the first TLS record is complete.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

use sb_tls::reality::generate_keypair;
use sb_tls::{RealityAcceptor, RealityClientConfig, RealityConnector, RealityServerConfig};

const DECOY_BANNER: &[u8] = b"decoy-hello";
const PROXY_PAYLOAD: &[u8] = b"reality-proxy-payload";
const ACCEPTED_SNI: &str = "auth.example";

#[derive(Clone, Copy)]
enum TargetFlightShape {
    Combined(usize),
    Separate([usize; 4]),
}

struct RecordingStream {
    inner: TcpStream,
    writes: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                self.writes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..written]);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A cert verifier that accepts any certificate; used by probe/oracle clients so
/// we can capture the peer certificate without a trust anchor.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Spawn a rustls decoy TLS server; returns its address and leaf certificate DER.
async fn spawn_decoy() -> (SocketAddr, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["decoy.example".to_string()]).unwrap();
    let cert_bytes = certified.cert.der().to_vec();
    let cert_der = rustls::pki_types::CertificateDer::from(cert_bytes.clone());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(certified.key_pair.serialize_der()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let _ = tls.write_all(DECOY_BANNER).await;
                    let _ = tls.flush().await;
                    let mut buf = [0u8; 64];
                    let _ = tls.read(&mut buf).await;
                }
            });
        }
    });

    (addr, cert_bytes)
}

async fn spawn_partial_timing_decoy() -> (SocketAddr, mpsc::UnboundedReceiver<&'static str>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (events_tx, events_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let _ = events_tx.send("accepted");
        let mut first = [0u8; 1];
        tcp.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], 0x16);
        let _ = events_tx.send("first_byte");
        tcp.write_all(b"partial-decoy-response").await.unwrap();
        tcp.flush().await.unwrap();
    });

    (addr, events_rx)
}

fn tls_record(content_type: u8, total_len: usize, payload_prefix: &[u8]) -> Vec<u8> {
    assert!(total_len >= 5 + payload_prefix.len());
    let payload_len = total_len - 5;
    let mut record = Vec::with_capacity(total_len);
    record.extend_from_slice(&[
        content_type,
        0x03,
        0x03,
        (payload_len >> 8) as u8,
        payload_len as u8,
    ]);
    record.extend_from_slice(payload_prefix);
    record.resize(total_len, 0);
    record
}

fn fake_server_hello(client_hello_record: &[u8]) -> Vec<u8> {
    let client_hello = &client_hello_record[5..];
    let session_id_len = usize::from(client_hello[38]);
    let session_id = &client_hello[39..39 + session_id_len];

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    extensions.extend_from_slice(&[0x42; 32]);

    let mut handshake = vec![2, 0, 0, 0, 0x03, 0x03];
    handshake.extend_from_slice(&[0x24; 32]);
    handshake.push(session_id_len as u8);
    handshake.extend_from_slice(session_id);
    handshake.extend_from_slice(&[0x13, 0x02, 0x00]);
    handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&extensions);
    let body_len = handshake.len() - 4;
    handshake[1] = (body_len >> 16) as u8;
    handshake[2] = (body_len >> 8) as u8;
    handshake[3] = body_len as u8;

    tls_record(22, 5 + handshake.len(), &handshake)
}

async fn spawn_profile_target(shape: TargetFlightShape) -> (SocketAddr, usize) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Chrome-current REALITY always uses a 32-byte legacy session ID, so this
    // standard TLS 1.3 ServerHello shape has a deterministic record length.
    let expected_server_hello_len = 127;
    tokio::spawn(async move {
        loop {
            let Ok((mut tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut header = [0u8; 5];
                if tcp.read_exact(&mut header).await.is_err() {
                    return;
                }
                let payload_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
                let mut client_hello = Vec::with_capacity(5 + payload_len);
                client_hello.extend_from_slice(&header);
                client_hello.resize(5 + payload_len, 0);
                if tcp.read_exact(&mut client_hello[5..]).await.is_err() {
                    return;
                }

                let mut flight = fake_server_hello(&client_hello);
                flight.extend_from_slice(&[20, 0x03, 0x03, 0, 1, 1]);
                match shape {
                    TargetFlightShape::Combined(length) => {
                        flight.extend_from_slice(&tls_record(23, length, &[]));
                    }
                    TargetFlightShape::Separate(lengths) => {
                        for length in lengths {
                            flight.extend_from_slice(&tls_record(23, length, &[]));
                        }
                    }
                }
                let _ = tcp.write_all(&flight).await;
                let _ = tcp.flush().await;
            });
        }
    });

    (addr, expected_server_hello_len)
}

/// Spawn the REALITY server; authenticated connections receive `PROXY_PAYLOAD`,
/// non-authenticated connections are relayed to the decoy target.
async fn spawn_reality(config: RealityServerConfig) -> SocketAddr {
    let acceptor = Arc::new(RealityAcceptor::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(conn) = acceptor.accept(tcp).await
                    && let Ok(Some(mut proxy)) = conn.handle().await
                {
                    // Authenticated tunnel: emit a payload distinct from
                    // the decoy banner so the client can prove it is the
                    // proxy and not a relay.
                    let _ = proxy.write_all(PROXY_PAYLOAD).await;
                    let _ = proxy.flush().await;
                    let mut buf = [0u8; 64];
                    let _ = proxy.read(&mut buf).await;
                }
            });
        }
    });

    addr
}

async fn spawn_recording_reality(config: RealityServerConfig) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
    let acceptor = Arc::new(RealityAcceptor::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let writes = Arc::new(Mutex::new(Vec::new()));
    let writes_for_task = writes.clone();

    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = RecordingStream {
            inner: tcp,
            writes: writes_for_task,
        };
        if let Ok(conn) = acceptor.accept(stream).await
            && let Ok(Some(mut proxy)) = conn.handle().await
        {
            let _ = proxy.write_all(PROXY_PAYLOAD).await;
            let _ = proxy.flush().await;
        }
    });

    (addr, writes)
}

fn parsed_record_lengths(wire: &[u8], count: usize) -> Vec<usize> {
    let mut lengths = Vec::with_capacity(count);
    let mut offset = 0usize;
    while lengths.len() < count {
        assert!(wire.len() >= offset + 5, "truncated TLS record header");
        let payload_len = usize::from(u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]));
        let record_len = 5 + payload_len;
        assert!(wire.len() >= offset + record_len, "truncated TLS record");
        lengths.push(record_len);
        offset += record_len;
    }
    lengths
}

fn server_hello_choices(wire: &[u8]) -> (u16, u16) {
    assert_eq!(wire[0], 22);
    let payload = &wire[5..5 + usize::from(u16::from_be_bytes([wire[3], wire[4]]))];
    let session_id_len = usize::from(payload[38]);
    let cipher_offset = 39 + session_id_len;
    let cipher_suite = u16::from_be_bytes([payload[cipher_offset], payload[cipher_offset + 1]]);
    let mut cursor = cipher_offset + 3;
    let extensions_block_len =
        usize::from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]));
    cursor += 2;
    let extensions_block_end = cursor + extensions_block_len;
    while cursor < extensions_block_end {
        let extension_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
        let entry_len = usize::from(u16::from_be_bytes([
            payload[cursor + 2],
            payload[cursor + 3],
        ]));
        cursor += 4;
        if extension_type == 51 {
            return (
                cipher_suite,
                u16::from_be_bytes([payload[cursor], payload[cursor + 1]]),
            );
        }
        cursor += entry_len;
    }
    panic!("ServerHello did not contain key_share");
}

/// Complete a plain TLS handshake to `addr` with the given SNI and return the
/// peer leaf certificate DER.
async fn tls_probe_peer_cert(addr: SocketAddr, sni: &str) -> Result<Vec<u8>, String> {
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| format!("bad server name: {e:?}"))?;
    let tls = timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .map_err(|_| "probe TLS handshake timed out".to_string())?
        .map_err(|e| e.to_string())?;

    let (_, conn) = tls.get_ref();
    conn.peer_certificates()
        .and_then(<[_]>::first)
        .map(|c| c.as_ref().to_vec())
        .ok_or_else(|| "no peer certificate".to_string())
}

fn server_config(target: SocketAddr, priv_hex: &str) -> RealityServerConfig {
    RealityServerConfig {
        target: target.to_string(),
        server_names: vec![ACCEPTED_SNI.to_string()],
        private_key: priv_hex.to_string(),
        short_ids: vec!["01ab".to_string()],
        handshake_timeout: 5,
        max_time_difference: None,
        enable_fallback: true,
    }
}

#[tokio::test]
async fn target_preconnects_and_mirrors_partial_input() {
    init_crypto();
    let (decoy_addr, mut events) = spawn_partial_timing_decoy().await;
    let (priv_hex, _pub_hex) = generate_keypair();
    let reality_addr = spawn_reality(server_config(decoy_addr, &priv_hex)).await;

    let mut client = TcpStream::connect(reality_addr).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("decoy was not preconnected before client data"),
        Some("accepted")
    );

    client.write_all(&[0x16]).await.unwrap();
    client.flush().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("first byte was not mirrored before record completion"),
        Some("first_byte")
    );

    let mut response = vec![0u8; b"partial-decoy-response".len()];
    timeout(Duration::from_secs(1), client.read_exact(&mut response))
        .await
        .expect("decoy response was not relayed before record completion")
        .expect("partial-input decoy response failed");
    assert_eq!(response, b"partial-decoy-response");
}

/// A plain-TLS probe whose SNI is NOT in the server's accepted list must be
/// transparently relayed to the decoy — the prober sees the decoy certificate.
#[tokio::test]
async fn plain_tls_probe_wrong_sni_is_relayed_to_decoy() {
    init_crypto();
    let (decoy_addr, decoy_cert) = spawn_decoy().await;
    let (priv_hex, _pub_hex) = generate_keypair();
    let reality_addr = spawn_reality(server_config(decoy_addr, &priv_hex)).await;

    let oracle = tls_probe_peer_cert(decoy_addr, "decoy.example")
        .await
        .expect("oracle direct-to-decoy handshake failed");
    assert_eq!(
        oracle, decoy_cert,
        "oracle must observe the decoy certificate"
    );

    let relayed = tls_probe_peer_cert(reality_addr, "not-in-list.example")
        .await
        .expect("wrong-SNI probe must complete via relay, not drop");
    assert_eq!(
        relayed, decoy_cert,
        "wrong-SNI probe must be indistinguishable from talking to the decoy"
    );
}

/// A plain-TLS probe whose SNI IS accepted but which carries no valid REALITY
/// session_id must fail authentication and be relayed to the decoy.
#[tokio::test]
async fn plain_tls_probe_accepted_sni_no_auth_is_relayed() {
    init_crypto();
    let (decoy_addr, decoy_cert) = spawn_decoy().await;
    let (priv_hex, _pub_hex) = generate_keypair();
    let reality_addr = spawn_reality(server_config(decoy_addr, &priv_hex)).await;

    let relayed = tls_probe_peer_cert(reality_addr, ACCEPTED_SNI)
        .await
        .expect("accepted-SNI unauthenticated probe must complete via relay");
    assert_eq!(
        relayed, decoy_cert,
        "unauthenticated probe must observe the decoy certificate"
    );
}

/// A malformed / non-REALITY handshake record must still be relayed to the decoy
/// (which responds), not dropped. This is the regression guard against the old
/// behaviour where an unparsable ClientHello produced a hard error + socket drop.
#[tokio::test]
async fn malformed_handshake_record_is_relayed_not_dropped() {
    init_crypto();
    let (decoy_addr, _decoy_cert) = spawn_decoy().await;
    let (priv_hex, _pub_hex) = generate_keypair();
    let reality_addr = spawn_reality(server_config(decoy_addr, &priv_hex)).await;

    // A TLS handshake record (content_type=22) whose body is a truncated
    // ClientHello: unparsable by the REALITY server, rejected by the decoy with a
    // TLS alert. Either way, the decoy must receive it and respond.
    let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];
    let mut tcp = TcpStream::connect(reality_addr).await.unwrap();
    tcp.write_all(&record).await.unwrap();
    tcp.flush().await.unwrap();
    record.clear();

    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .expect("relay response timed out")
        .expect("read failed");
    assert!(
        n > 0,
        "non-REALITY probe must be relayed to the decoy (which responds), not dropped"
    );
    // A relayed TLS response begins with a TLS record content type (handshake=22
    // or alert=21); a dropped connection would yield 0 bytes.
    assert!(
        buf[0] == 0x16 || buf[0] == 0x15,
        "expected a relayed TLS record from the decoy, got first byte 0x{:02x}",
        buf[0]
    );
}

/// Positive control + Rust-server <-> Rust-client interop: a REALITY client with
/// the matching public key authenticates via the session_id and reaches the
/// authenticated proxy path (receiving `PROXY_PAYLOAD`, not the decoy banner).
#[tokio::test]
async fn authenticated_reality_client_reaches_proxy() {
    init_crypto();
    let (decoy_addr, _decoy_cert) = spawn_decoy().await;
    let (priv_hex, pub_hex) = generate_keypair();
    let reality_addr = spawn_reality(server_config(decoy_addr, &priv_hex)).await;

    let client_config = RealityClientConfig {
        target: ACCEPTED_SNI.to_string(),
        server_name: ACCEPTED_SNI.to_string(),
        public_key: pub_hex,
        short_id: Some("01ab".to_string()),
        fingerprint: "chrome".to_string(),
        alpn: vec![],
    };
    let connector = RealityConnector::new(client_config).unwrap();

    let tcp = TcpStream::connect(reality_addr).await.unwrap();
    let mut stream = timeout(
        Duration::from_secs(5),
        connector.connect_stream(tcp, ACCEPTED_SNI),
    )
    .await
    .expect("REALITY client handshake timed out")
    .expect("REALITY client handshake failed (Rust server <-> Rust client)");

    let mut buf = vec![0u8; PROXY_PAYLOAD.len()];
    let n = timeout(Duration::from_secs(5), stream.read_tls(&mut buf))
        .await
        .expect("proxy payload read timed out")
        .expect("proxy payload read failed");
    assert_eq!(
        &buf[..n],
        PROXY_PAYLOAD,
        "authenticated client must receive the proxy payload, not the decoy banner"
    );
}

async fn assert_target_profile_borrowed(
    shape: TargetFlightShape,
    expected_encrypted_lengths: &[usize],
) {
    init_crypto();
    let (target_addr, server_hello_len) = spawn_profile_target(shape).await;
    let (priv_hex, pub_hex) = generate_keypair();
    let mut config = server_config(target_addr, &priv_hex);
    config.handshake_timeout = 10;
    let (reality_addr, writes) = spawn_recording_reality(config).await;

    let client_config = RealityClientConfig {
        target: ACCEPTED_SNI.to_string(),
        server_name: ACCEPTED_SNI.to_string(),
        public_key: pub_hex,
        short_id: Some("01ab".to_string()),
        fingerprint: "chrome".to_string(),
        alpn: vec![],
    };
    let connector = RealityConnector::new(client_config).unwrap();
    let tcp = TcpStream::connect(reality_addr).await.unwrap();
    let mut stream = timeout(
        Duration::from_secs(10),
        connector.connect_stream(tcp, ACCEPTED_SNI),
    )
    .await
    .expect("REALITY profile-borrow handshake timed out")
    .expect("REALITY profile-borrow handshake failed");

    let mut payload = vec![0u8; PROXY_PAYLOAD.len()];
    let read = timeout(Duration::from_secs(5), stream.read_tls(&mut payload))
        .await
        .expect("profile-borrow proxy payload timed out")
        .expect("profile-borrow proxy payload failed");
    assert_eq!(&payload[..read], PROXY_PAYLOAD);

    let wire = writes.lock().unwrap().clone();
    let mut expected = vec![server_hello_len, 6];
    expected.extend_from_slice(expected_encrypted_lengths);
    assert_eq!(parsed_record_lengths(&wire, expected.len()), expected);
    assert_eq!(
        server_hello_choices(&wire),
        (0x1302, 0x001d),
        "Rust must borrow target AES-256-GCM and X25519 choices"
    );
}

/// Target emits one combined encrypted server flight. Rust must keep it
/// combined and pad its generated flight to the exact target record length.
#[tokio::test]
async fn authenticated_server_borrows_combined_target_record_shape() {
    assert_target_profile_borrowed(TargetFlightShape::Combined(777), &[777]).await;
}

/// Target emits EE, Certificate, CertificateVerify, and Finished separately.
/// Rust must split its normal combined rustls flight and match every record.
#[tokio::test]
async fn authenticated_server_borrows_separate_target_record_shape() {
    let target_lengths = [120, 1024, 180, 150];
    assert_target_profile_borrowed(TargetFlightShape::Separate(target_lengths), &target_lengths)
        .await;
}
