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

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sb_tls::reality::generate_keypair;
use sb_tls::{RealityAcceptor, RealityClientConfig, RealityConnector, RealityServerConfig};

const DECOY_BANNER: &[u8] = b"decoy-hello";
const PROXY_PAYLOAD: &[u8] = b"reality-proxy-payload";
const ACCEPTED_SNI: &str = "auth.example";

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
                match acceptor.accept(tcp).await {
                    Ok(conn) => match conn.handle().await {
                        Ok(Some(mut proxy)) => {
                            // Authenticated tunnel: emit a payload distinct from
                            // the decoy banner so the client can prove it is the
                            // proxy and not a relay.
                            let _ = proxy.write_all(PROXY_PAYLOAD).await;
                            let _ = proxy.flush().await;
                            let mut buf = [0u8; 64];
                            let _ = proxy.read(&mut buf).await;
                        }
                        Ok(None) => {} // relayed to target
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
            });
        }
    });

    addr
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
        enable_fallback: true,
    }
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
