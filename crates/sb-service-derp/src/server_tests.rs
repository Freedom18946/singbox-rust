#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use rustls::RootCertStore;
use sb_config::ir::{
    DerpStunOptionsIR, DerpVerifyClientUrlIR, EndpointIR, InboundTlsOptionsIR, Listable,
    ServiceType, StringOrObj,
};
use std::future::pending;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

fn install_rustls_crypto_provider() {
    sb_tls::ensure_crypto_provider();
}

struct TestTls {
    cert_file: tempfile::NamedTempFile,
    key_file: tempfile::NamedTempFile,
    client_config: Arc<ClientConfig>,
    connector: tokio_rustls::TlsConnector,
}

impl TestTls {
    fn new() -> Self {
        install_rustls_crypto_provider();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_file = tempfile::NamedTempFile::new().unwrap();
        let key_file = tempfile::NamedTempFile::new().unwrap();
        fs::write(cert_file.path(), cert_pem).unwrap();
        fs::write(key_file.path(), key_pem).unwrap();

        let mut roots = RootCertStore::empty();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        roots.add(cert_der).expect("add root");
        let client_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let connector = tokio_rustls::TlsConnector::from(client_config.clone());

        Self {
            cert_file,
            key_file,
            client_config,
            connector,
        }
    }

    fn tls_ir(&self) -> InboundTlsOptionsIR {
        InboundTlsOptionsIR {
            enabled: true,
            certificate_path: Some(self.cert_file.path().to_string_lossy().to_string()),
            key_path: Some(self.key_file.path().to_string_lossy().to_string()),
            ..Default::default()
        }
    }

    async fn connect(&self, port: u16) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        use rustls::pki_types::ServerName;

        let server_name = ServerName::try_from("localhost").unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect tls");
        self.connector
            .connect(server_name, tcp)
            .await
            .expect("tls handshake")
    }
}

struct AbortFlag {
    flag: Arc<AtomicBool>,
}

impl Drop for AbortFlag {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

async fn abort_observable_task(flag: Arc<AtomicBool>, ready: tokio::sync::oneshot::Sender<()>) {
    let _flag = AbortFlag { flag };
    let _ = ready.send(());
    pending::<()>().await;
}

#[test]
fn test_stun_packet_parsing() {
    // Binding Request
    let packet = vec![
        0x00, 0x01, // Type: Binding Request
        0x00, 0x00, // Length: 0
        0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, // Transaction ID
    ];

    let peer = "127.0.0.1:12345".parse().unwrap();
    let response =
        DerpService::handle_stun_packet(&packet, peer).expect("Should handle valid STUN packet");

    // Verify response header
    assert_eq!(response[0], 0x01); // Binding Response
    assert_eq!(response[1], 0x01);
    assert_eq!(response[4], 0x21); // Magic Cookie

    // Verify XOR-MAPPED-ADDRESS
    // Attribute Type 0x0020
    // Find attribute in response
    let mut idx = 20;
    let mut found = false;
    while idx < response.len() {
        let attr_type = u16::from_be_bytes([response[idx], response[idx + 1]]);
        let attr_len = u16::from_be_bytes([response[idx + 2], response[idx + 3]]);

        if attr_type == 0x0020 {
            found = true;
            // Check port
            let xor_port = u16::from_be_bytes([response[idx + 6], response[idx + 7]]);
            let port = xor_port ^ 0x2112;
            assert_eq!(port, 12345);
            break;
        }
        idx += 4 + attr_len as usize;
    }
    assert!(found, "XOR-MAPPED-ADDRESS not found");
}

#[test]
fn test_derp_requires_tls_and_config_path() {
    let ctx = ServiceContext::default();

    // Missing config_path should error.
    let ir_missing_config = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-missing-config".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(0),
        tls: Some(InboundTlsOptionsIR {
            enabled: true,
            certificate_path: Some("cert.pem".to_string()),
            key_path: Some("key.pem".to_string()),
            ..Default::default()
        }),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = DerpService::from_ir(&ir_missing_config, &ctx)
        .err()
        .expect("expected missing config_path error");
    assert!(
        err.to_string().contains("missing config_path"),
        "unexpected error: {err}"
    );

    // Missing TLS should error.
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();
    let ir_missing_tls = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-missing-tls".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(0),
        config_path: Some(config_path),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = DerpService::from_ir(&ir_missing_tls, &ctx)
        .err()
        .expect("expected TLS required error");
    assert!(
        err.to_string().contains("TLS is required for DERP server"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_http_stub_over_tls() {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping tls http stub test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    install_rustls_crypto_provider();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let cert_file = tempfile::NamedTempFile::new().unwrap();
    let key_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(cert_file.path(), cert_pem).unwrap();
    fs::write(key_file.path(), key_pem).unwrap();

    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-http-tls".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        stun: Some(DerpStunOptionsIR {
            enabled: false, // isolate HTTP for the test
            ..Default::default()
        }),
        tls: Some(InboundTlsOptionsIR {
            enabled: true,
            certificate_path: Some(cert_file.path().to_string_lossy().to_string()),
            key_path: Some(key_file.path().to_string_lossy().to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = build_derp_service(&ir, &ctx).expect("service should build");

    service.start(StartStage::Initialize).unwrap();
    if let Err(e) = service.start(StartStage::Start) {
        if let Some(io_err) = e.downcast_ref::<io::Error>() {
            if io_err.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("skipping tls http stub test during start: {io_err}");
                return;
            }
        }
        panic!("start failed: {e}");
    }

    sleep(Duration::from_millis(50)).await;

    let mut roots = RootCertStore::empty();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    roots.add(cert_der).expect("add root");
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name = ServerName::try_from("localhost").unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect tls");
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");

    tls_stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut buf = Vec::new();
    tls_stream
        .read_to_end(&mut buf)
        .await
        .expect("read response");
    let response = String::from_utf8_lossy(&buf);
    assert!(
        response.contains("200 OK"),
        "expected 200 OK over TLS, got: {response}"
    );
    assert!(
        response.contains("<h1>DERP</h1>"),
        "expected home page over TLS, got: {response}"
    );

    service.close().unwrap();
}

#[tokio::test]
async fn test_mock_relay_pairs_two_clients() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping relay test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };
    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-relay".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = build_derp_service(&ir, &ctx).expect("service should build");

    service.start(StartStage::Initialize).unwrap();
    if let Err(e) = service.start(StartStage::Start) {
        if let Some(io_err) = e.downcast_ref::<io::Error>() {
            if io_err.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("skipping relay test during start: {io_err}");
                return;
            }
        }
        panic!("start failed: {e}");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut c1 = tls.connect(port).await;
    let mut c2 = tls.connect(port).await;

    c1.write_all(b"DERP session test\n")
        .await
        .expect("handshake c1");
    c2.write_all(b"DERP session test\n")
        .await
        .expect("handshake c2");

    // Small pause to ensure pairing.
    tokio::time::sleep(Duration::from_millis(20)).await;

    c1.write_all(b"hello").await.expect("c1 write");
    let mut buf = [0u8; 5];
    c2.read_exact(&mut buf).await.expect("c2 read");
    assert_eq!(&buf, b"hello");

    c2.write_all(b"world").await.expect("c2 write");
    let mut buf2 = [0u8; 5];
    c1.read_exact(&mut buf2).await.expect("c1 read");
    assert_eq!(&buf2, b"world");

    service.close().unwrap();
}

#[tokio::test]
async fn test_mock_relay_requires_token() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping relay auth test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let psk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-auth".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        mesh_psk: Some(psk.to_string()),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = build_derp_service(&ir, &ctx).expect("service should build");

    service.start(StartStage::Initialize).unwrap();
    if let Err(e) = service.start(StartStage::Start) {
        if let Some(io_err) = e.downcast_ref::<io::Error>() {
            if io_err.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("skipping relay auth test during start: {io_err}");
                return;
            }
        }
        panic!("start failed: {e}");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Missing token should be rejected.
    let mut unauth = tls.connect(port).await;
    unauth
        .write_all(b"DERP session auth-test\n")
        .await
        .expect("handshake unauth");
    let mut unauth_buf = Vec::new();
    let _ = unauth.read_to_end(&mut unauth_buf).await;
    let unauth_str = String::from_utf8_lossy(&unauth_buf);
    assert!(
        unauth_str.contains("ERR unauthorized"),
        "expected unauthorized response, got: {unauth_str}"
    );

    // With token, relay should pair.
    let mut a = tls.connect(port).await;
    let mut b = tls.connect(port).await;
    let handshake_a = format!("DERP session auth-ok token={psk}\n");
    a.write_all(handshake_a.as_bytes())
        .await
        .expect("handshake a");
    let handshake_b = format!("DERP session auth-ok token={psk}\n");
    b.write_all(handshake_b.as_bytes())
        .await
        .expect("handshake b");

    tokio::time::sleep(Duration::from_millis(20)).await;
    a.write_all(b"ping").await.expect("a write");
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await.expect("b read");
    assert_eq!(&buf, b"ping");

    service.close().unwrap();
}

async fn send_https_request(tls: &TestTls, port: u16, request: &str) -> String {
    let mut stream = tls.connect(port).await;
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    String::from_utf8_lossy(&buf).to_string()
}

fn alloc_port() -> io::Result<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
}

type TestTlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

fn test_client_keypair(seed: u8) -> (PrivateKey, PublicKey) {
    let mut private = [seed; 32];
    clamp_private_key(&mut private);
    let public = derive_public_key(&private);
    (private, public)
}

async fn derp_handshake_v2<S>(
    stream: &mut S,
    client_private_key: PrivateKey,
    mesh_key: Option<String>,
    expect_server_info: bool,
) -> PublicKey
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let client_public_key = derive_public_key(&client_private_key);

    let server_key_frame = DerpFrame::read_from_async(stream)
        .await
        .expect("server key");
    let server_public_key = match server_key_frame {
        DerpFrame::ServerKey { key } => key,
        other => panic!("expected ServerKey, got {:?}", other.frame_type()),
    };

    let mut info = ClientInfoPayload::new(PROTOCOL_VERSION as u32).with_can_ack_pings(true);
    if let Some(mesh_key) = mesh_key {
        info = info.with_mesh_key(mesh_key);
    }
    let msgbox =
        seal_to(&client_private_key, &server_public_key, &info.to_json()).expect("seal clientinfo");
    DerpFrame::ClientInfo {
        key: client_public_key,
        encrypted_info: msgbox,
    }
    .write_to_async(stream)
    .await
    .expect("clientinfo");
    stream.flush().await.expect("flush clientinfo");

    if expect_server_info {
        let server_info_frame = DerpFrame::read_from_async(stream)
            .await
            .expect("server info");
        match server_info_frame {
            DerpFrame::ServerInfo { encrypted_info } => {
                let clear = open_from(&client_private_key, &server_public_key, &encrypted_info)
                    .expect("open server info");
                let clear = String::from_utf8_lossy(&clear);
                assert!(
                    clear.contains(&format!("\"version\":{}", PROTOCOL_VERSION)),
                    "unexpected ServerInfo payload: {clear}"
                );
            }
            other => panic!("expected ServerInfo, got {:?}", other.frame_type()),
        }
    }

    client_public_key
}

async fn connect_derp_upgrade(
    tls: &TestTls,
    port: u16,
    client_private_key: PrivateKey,
    fast_start: bool,
) -> (PrefixedStream<TestTlsStream>, PublicKey) {
    let mut stream = tls.connect(port).await;

    let mut req = String::from(
        "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n",
    );
    if fast_start {
        req.push_str("Derp-Fast-Start: 1\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush request");

    let mut prefix = Vec::new();
    if !fast_start {
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).await.expect("read response");
            assert!(n > 0, "connection closed before response");
            prefix.extend_from_slice(&tmp[..n]);
            if let Some(idx) = prefix.windows(4).position(|w| w == b"\r\n\r\n") {
                let end = idx + 4;
                let head = String::from_utf8_lossy(&prefix[..end]);
                assert!(
                    head.contains("101 Switching Protocols"),
                    "expected 101 response, got: {head}"
                );
                prefix = prefix[end..].to_vec();
                break;
            }
            assert!(prefix.len() <= 16 * 1024, "response headers too large");
        }
    }

    let mut derp = PrefixedStream::new(stream, prefix);
    let client_public_key = derp_handshake_v2(&mut derp, client_private_key, None, true).await;
    (derp, client_public_key)
}

#[tokio::test]
async fn test_derp_over_websocket_ping_pong() {
    use sb_transport::tls::TlsDialer;
    use sb_transport::websocket::{WebSocketConfig, WebSocketDialer};
    use sb_transport::Dialer;

    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp ws test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-ws".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");
    service.start(StartStage::Start).expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let ws_cfg = WebSocketConfig {
        path: "/derp".to_string(),
        headers: vec![("Sec-WebSocket-Protocol".to_string(), "derp".to_string())],
        ..Default::default()
    };
    let tls_dialer = TlsDialer {
        inner: sb_transport::TcpDialer::default(),
        config: tls.client_config.clone(),
        sni_override: Some("localhost".to_string()),
        alpn: Some(vec![b"http/1.1".to_vec()]),
    };
    let dialer = WebSocketDialer::new(ws_cfg, Box::new(tls_dialer));
    let mut stream = dialer.connect("127.0.0.1", port).await.expect("ws connect");

    let (client_private_key, _) = test_client_keypair(9);
    derp_handshake_v2(&mut stream, client_private_key, None, true).await;

    let ping_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    DerpFrame::Ping { data: ping_data }
        .write_to_async(&mut stream)
        .await
        .expect("ping");
    stream.flush().await.expect("flush ping");

    let pong = tokio::time::timeout(
        Duration::from_secs(2),
        DerpFrame::read_from_async(&mut stream),
    )
    .await
    .expect("timeout")
    .expect("read pong");
    assert!(matches!(pong, DerpFrame::Pong { data } if data == ping_data));

    service.close().unwrap();
}

#[tokio::test]
async fn test_derp_over_http_upgrade_end_to_end() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp http upgrade test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-h1-upgrade".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");
    service.start(StartStage::Start).expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (client1_private_key, client1_key) = test_client_keypair(1);
    let (client2_private_key, client2_key) = test_client_keypair(2);
    let (mut c1, client1_key2) = connect_derp_upgrade(&tls, port, client1_private_key, false).await;
    let (mut c2, client2_key2) = connect_derp_upgrade(&tls, port, client2_private_key, false).await;
    assert_eq!(client1_key2, client1_key);
    assert_eq!(client2_key2, client2_key);

    // Client1 -> Client2
    let packet = vec![0xAA, 0xBB, 0xCC, 0xDD];
    DerpFrame::SendPacket {
        dst_key: client2_key,
        packet: packet.clone(),
    }
    .write_to_async(&mut c1)
    .await
    .expect("send packet");
    c1.flush().await.expect("flush send packet");

    let recv = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut c2))
        .await
        .expect("timeout waiting for packet")
        .expect("read frame");
    match recv {
        DerpFrame::RecvPacket {
            src_key,
            packet: got,
        } => {
            assert_eq!(src_key, client1_key);
            assert_eq!(got, packet);
        }
        other => panic!("expected RecvPacket, got {:?}", other.frame_type()),
    }

    // Drive a simple ping/pong on the other direction too.
    let ping_data = [9u8, 8, 7, 6, 5, 4, 3, 2];
    DerpFrame::Ping { data: ping_data }
        .write_to_async(&mut c2)
        .await
        .expect("send ping");
    c2.flush().await.expect("flush ping");
    let pong = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut c2))
        .await
        .expect("timeout")
        .expect("read pong");
    assert!(matches!(pong, DerpFrame::Pong { data } if data == ping_data));

    service.close().unwrap();
}

#[tokio::test]
async fn test_derp_http_fast_start_end_to_end() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp fast-start test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-fast-start".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");
    service.start(StartStage::Start).expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (client_private_key, _) = test_client_keypair(3);
    let (mut c, _) = connect_derp_upgrade(&tls, port, client_private_key, true).await;

    let ping_data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    DerpFrame::Ping { data: ping_data }
        .write_to_async(&mut c)
        .await
        .expect("send ping");
    c.flush().await.expect("flush ping");

    let pong = tokio::time::timeout(Duration::from_secs(2), DerpFrame::read_from_async(&mut c))
        .await
        .expect("timeout")
        .expect("read pong");
    assert!(matches!(pong, DerpFrame::Pong { data } if data == ping_data));

    service.close().unwrap();
}

#[tokio::test]
async fn test_close_aborts_owned_background_tasks() {
    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp-close.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-close".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(0),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let service = DerpService::from_ir(&ir, &ServiceContext::default()).expect("build service");

    let http_aborted = Arc::new(AtomicBool::new(false));
    let stun_aborted = Arc::new(AtomicBool::new(false));
    let mesh_aborted = Arc::new(AtomicBool::new(false));
    let (http_ready_tx, http_ready_rx) = tokio::sync::oneshot::channel();
    let (stun_ready_tx, stun_ready_rx) = tokio::sync::oneshot::channel();
    let (mesh_ready_tx, mesh_ready_rx) = tokio::sync::oneshot::channel();

    *service.http_task.lock() = Some(tokio::spawn(abort_observable_task(
        http_aborted.clone(),
        http_ready_tx,
    )));
    *service.stun_task.lock() = Some(tokio::spawn(abort_observable_task(
        stun_aborted.clone(),
        stun_ready_tx,
    )));
    service
        .mesh_tasks
        .lock()
        .push(tokio::spawn(abort_observable_task(
            mesh_aborted.clone(),
            mesh_ready_tx,
        )));

    http_ready_rx.await.expect("http task started");
    stun_ready_rx.await.expect("stun task started");
    mesh_ready_rx.await.expect("mesh task started");

    service.close().expect("close service");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if http_aborted.load(Ordering::SeqCst)
                && stun_aborted.load(Ordering::SeqCst)
                && mesh_aborted.load(Ordering::SeqCst)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("background tasks should be aborted");
}

#[tokio::test]
async fn test_derp_requires_http_upgrade() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp upgrade-required test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-upgrade-required".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");
    service.start(StartStage::Start).expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = send_https_request(
        &tls,
        port,
        "GET /derp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("426") || resp.contains("Upgrade Required"),
        "expected 426 upgrade required, got: {resp}"
    );
    assert!(
        resp.contains("DERP requires connection upgrade"),
        "expected upgrade-required body, got: {resp}"
    );

    service.close().unwrap();
}

#[tokio::test]
async fn test_derp_probe_handler() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp probe test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-probe".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");
    service.start(StartStage::Start).expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let probe_get = send_https_request(
        &tls,
        port,
        "GET /derp/probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    let probe_get_lower = probe_get.to_ascii_lowercase();
    assert!(
        probe_get_lower.contains("200 ok"),
        "expected 200 probe response, got: {probe_get}"
    );
    assert!(
        probe_get_lower.contains("access-control-allow-origin: *"),
        "expected CORS header on probe response, got: {probe_get}"
    );
    assert!(
        !probe_get_lower.contains("strict-transport-security:"),
        "probe should not include browser headers, got: {probe_get}"
    );

    let probe_post = send_https_request(
            &tls,
            port,
            "POST /derp/probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
    let probe_post_lower = probe_post.to_ascii_lowercase();
    assert!(
        probe_post_lower.contains("405"),
        "expected 405 probe response, got: {probe_post}"
    );
    assert!(
        probe_post.contains("bogus probe method"),
        "expected probe body, got: {probe_post}"
    );

    service.close().unwrap();
}

#[tokio::test]
async fn test_generate_204_challenge_response() {
    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping generate_204 challenge test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-204".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");
    service.start(StartStage::Start).expect("start");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let challenge = "abcDEF0123.-_";
    let req = format!(
            "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Tailscale-Challenge: {challenge}\r\n\r\n"
        );
    let resp = send_https_request(&tls, port, &req).await;
    assert!(resp.contains("204"), "expected 204 response, got: {resp}");
    assert!(
        resp.contains(&format!("response {challenge}")),
        "expected challenge response header, got: {resp}"
    );
    let resp_lower = resp.to_ascii_lowercase();
    assert!(
        resp_lower.contains("x-tailscale-response:"),
        "expected x-tailscale-response header, got: {resp}"
    );
    assert!(
        !resp_lower.contains("strict-transport-security:"),
        "generate_204 should not include browser headers, got: {resp}"
    );

    let bad_req = "GET /generate_204 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Tailscale-Challenge: bad!\r\n\r\n";
    let bad_resp = send_https_request(&tls, port, bad_req).await;
    assert!(
        !bad_resp
            .to_ascii_lowercase()
            .contains("x-tailscale-response:"),
        "expected no response header for invalid challenge, got: {bad_resp}"
    );

    service.close().unwrap();
}

#[tokio::test]
async fn test_verify_client_url_enforced() {
    use hyper::service::{make_service_fn, service_fn};
    use tokio::sync::oneshot;

    // Start a local verify server: POST /ok => 204, POST /deny => 403.
    let std_listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping verify_client_url test: {e}");
            return;
        }
        Err(e) => panic!("bind verify server: {e}"),
    };
    std_listener.set_nonblocking(true).expect("nonblocking");
    let verify_addr = std_listener.local_addr().expect("verify addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|req: HyperRequest<Body>| async move {
            let status = match (req.method(), req.uri().path()) {
                (&hyper::Method::POST, "/ok") => StatusCode::NO_CONTENT,
                (&hyper::Method::POST, "/deny") => StatusCode::FORBIDDEN,
                _ => StatusCode::NOT_FOUND,
            };
            Ok::<_, Infallible>({
                let mut resp = HyperResponse::new(Body::empty());
                *resp.status_mut() = status;
                resp
            })
        }))
    });

    let server = hyper::Server::from_tcp(std_listener)
        .unwrap()
        .serve(make_svc)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
    let verify_handle = tokio::spawn(async move {
        let _ = server.await;
    });

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();

    // Start DERP service with verify_client_url=/ok (should accept).
    let port_ok = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping verify_client_url test: {e}");
            let _ = shutdown_tx.send(());
            verify_handle.abort();
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };
    let config_path_ok = tempdir
        .path()
        .join("derp-ok.key")
        .to_string_lossy()
        .to_string();
    let ir_ok = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-verify-ok".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port_ok),
        config_path: Some(config_path_ok),
        tls: Some(tls.tls_ir()),
        verify_client_url: Some(Listable {
            items: vec![StringOrObj(DerpVerifyClientUrlIR::from(format!(
                "http://{verify_addr}/ok"
            )))],
        }),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    let ctx = ServiceContext::default();
    let derp_ok = DerpService::from_ir(&ir_ok, &ctx).expect("derp ok service");
    derp_ok.start(StartStage::Start).expect("start derp ok");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut ok_stream = tls.connect(port_ok).await;
    let (client_private_key, _) = test_client_keypair(7);
    derp_handshake_v2(&mut ok_stream, client_private_key, None, true).await;
    DerpFrame::Ping {
        data: [1, 1, 2, 3, 5, 8, 13, 21],
    }
    .write_to_async(&mut ok_stream)
    .await
    .expect("ping");
    let pong = tokio::time::timeout(
        Duration::from_secs(2),
        DerpFrame::read_from_async(&mut ok_stream),
    )
    .await
    .expect("timeout")
    .expect("pong");
    assert!(matches!(pong, DerpFrame::Pong { .. }));
    derp_ok.close().unwrap();

    // Start DERP service with verify_client_url=/deny (should reject).
    let port_deny = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping verify_client_url deny test: {e}");
            derp_ok.close().ok();
            let _ = shutdown_tx.send(());
            verify_handle.abort();
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };
    let config_path_deny = tempdir
        .path()
        .join("derp-deny.key")
        .to_string_lossy()
        .to_string();
    let ir_deny = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp-verify-deny".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port_deny),
        config_path: Some(config_path_deny),
        tls: Some(tls.tls_ir()),
        verify_client_url: Some(Listable {
            items: vec![StringOrObj(DerpVerifyClientUrlIR::from(format!(
                "http://{verify_addr}/deny"
            )))],
        }),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        ..Default::default()
    };
    let derp_deny = DerpService::from_ir(&ir_deny, &ctx).expect("derp deny service");
    derp_deny.start(StartStage::Start).expect("start derp deny");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut deny_stream = tls.connect(port_deny).await;
    let (client_private_key, _) = test_client_keypair(8);
    derp_handshake_v2(&mut deny_stream, client_private_key, None, false).await;

    // The server should close after verification fails; expect read error/EOF quickly.
    let denied = tokio::time::timeout(
        Duration::from_secs(2),
        DerpFrame::read_from_async(&mut deny_stream),
    )
    .await;
    assert!(
        denied.is_err() || denied.unwrap().is_err(),
        "expected deny to close connection"
    );
    derp_deny.close().unwrap();

    // Shutdown verify server.
    let _ = shutdown_tx.send(());
    verify_handle.abort();
}

#[tokio::test]
async fn test_derp_protocol_over_tls_end_to_end() {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use sb_config::ir::ServiceType;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    let port = match alloc_port() {
        Ok(port) => port,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping derp tls test: {e}");
            return;
        }
        Err(e) => panic!("failed to allocate port: {e}"),
    };

    install_rustls_crypto_provider();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let cert_file = tempfile::NamedTempFile::new().unwrap();
    let key_file = tempfile::NamedTempFile::new().unwrap();
    fs::write(cert_file.path(), cert_pem).unwrap();
    fs::write(key_file.path(), key_pem).unwrap();

    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("test-derp-tls".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(port),
        config_path: Some(config_path),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        tls: Some(InboundTlsOptionsIR {
            enabled: true,
            certificate_path: Some(cert_file.path().to_string_lossy().to_string()),
            key_path: Some(key_file.path().to_string_lossy().to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let ctx = ServiceContext::default();
    let service = DerpService::from_ir(&ir, &ctx).expect("Failed to create service");

    if let Err(e) = service.start(StartStage::Start) {
        if let Some(io_err) = e.downcast_ref::<io::Error>() {
            if io_err.kind() == io::ErrorKind::PermissionDenied {
                eprintln!("skipping derp tls test during start: {io_err}");
                return;
            }
        }
        panic!("start failed: {e}");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut roots = RootCertStore::empty();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    roots.add(cert_der).expect("add root");
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("localhost").unwrap();

    let mut stream1 = connector
        .connect(
            server_name.clone(),
            TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect client1"),
        )
        .await
        .expect("tls handshake client1");

    let mut stream2 = connector
        .connect(
            server_name,
            TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect client2"),
        )
        .await
        .expect("tls handshake client2");

    let (client1_private_key, client1_key) = test_client_keypair(1);
    let (client2_private_key, client2_key) = test_client_keypair(2);
    derp_handshake_v2(&mut stream1, client1_private_key, None, true).await;
    derp_handshake_v2(&mut stream2, client2_private_key, None, true).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send packet from client1 to client2
    let packet = vec![9, 8, 7, 6];
    let send_frame = DerpFrame::SendPacket {
        dst_key: client2_key,
        packet: packet.clone(),
    };
    send_frame
        .write_to_async(&mut stream1)
        .await
        .expect("send packet from client1");

    // Client2 should receive packet
    tokio::time::timeout(Duration::from_secs(2), async {
        let recv_frame = DerpFrame::read_from_async(&mut stream2)
            .await
            .expect("recv frame on client2");
        match recv_frame {
            DerpFrame::RecvPacket {
                src_key,
                packet: recv,
            } => {
                assert_eq!(src_key, client1_key, "wrong source key");
                assert_eq!(recv, packet, "packet content mismatch");
            }
            other => panic!("expected RecvPacket, got {:?}", other.frame_type()),
        }
    })
    .await
    .expect("timeout waiting for TLS packet");

    service.close().expect("Failed to close service");
}

// ────────────────────────────────────────────────────────────────────────────
// Persistent Key Storage Tests
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn test_generate_secure_key_uniqueness() {
    let key1 = generate_secure_server_private_key().unwrap();
    let key2 = generate_secure_server_private_key().unwrap();
    // Keys should be different (cryptographically secure)
    assert_ne!(key1, key2);
    assert_eq!(key1.len(), 32);
    assert_eq!(key2.len(), 32);
}

#[test]
fn test_key_save_load_roundtrip() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("derp.key");
    let path = key_path.to_str().unwrap();

    let original_key = generate_secure_server_private_key().unwrap();
    save_private_key_to_config(path, &original_key).unwrap();
    let loaded_key = load_private_key_from_config(path).unwrap();

    assert_eq!(original_key, loaded_key);
}

#[test]
fn test_load_or_generate_creates_new_key() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("derp_server.key");
    let path_str = key_path.to_str().unwrap();

    // Key file shouldn't exist yet
    assert!(!key_path.exists());

    // First call should generate and save key
    let key1 = load_or_generate_server_private_key(Some(path_str)).unwrap();

    // File should now exist
    assert!(key_path.exists());

    // Second call should load same key
    let key2 = load_or_generate_server_private_key(Some(path_str)).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_ephemeral_key_without_path() {
    // Should generate ephemeral key without error
    let key = load_or_generate_server_private_key(None).unwrap();
    assert_eq!(key.len(), 32);

    // Each call should generate different key
    let key2 = load_or_generate_server_private_key(None).unwrap();
    assert_ne!(key, key2);
}

#[cfg(unix)]
#[test]
fn test_key_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("derp.key");
    let path = key_path.to_str().unwrap();

    let key = generate_secure_server_private_key().unwrap();
    save_private_key_to_config(path, &key).unwrap();

    let metadata = fs::metadata(path).unwrap();
    let mode = metadata.permissions().mode();
    // Go writes `0644` (writeNewDERPConfig).
    assert_eq!(mode & 0o777, 0o644);
}

#[test]
fn test_save_key_creates_parent_directories() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("subdir/deep/derp_server.key");
    let path_str = key_path.to_str().unwrap();

    let key = generate_secure_server_private_key().unwrap();
    save_private_key_to_config(path_str, &key).unwrap();

    // Parent directories and file should exist
    assert!(key_path.exists());
    assert!(key_path.parent().unwrap().exists());
}

#[test]
fn test_load_key_with_wrong_size_fails() {
    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("derp.key");
    let path = key_path.to_str().unwrap();

    // Invalid JSON / invalid private key should fail.
    fs::write(path, br#"{"PrivateKey":"privkey:deadbeef"}"#).unwrap();
    let result = load_private_key_from_config(path);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_bootstrap_dns_uses_injected_dns_router() {
    #[derive(Clone, Debug)]
    struct FakeRouter;

    #[async_trait::async_trait]
    impl DnsRouter for FakeRouter {
        async fn exchange(
            &self,
            _ctx: &DnsQueryContext,
            _message: &[u8],
        ) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("not implemented"))
        }

        async fn lookup(
            &self,
            _ctx: &DnsQueryContext,
            domain: &str,
        ) -> anyhow::Result<Vec<std::net::IpAddr>> {
            if domain == "example.com" {
                Ok(vec!["1.2.3.4".parse().unwrap()])
            } else {
                Ok(vec![])
            }
        }

        async fn lookup_default(&self, _domain: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
            Err(anyhow::anyhow!("not implemented"))
        }

        async fn resolve(
            &self,
            _ctx: &DnsQueryContext,
            _domain: &str,
        ) -> anyhow::Result<sb_core::dns::DnsAnswer> {
            Err(anyhow::anyhow!("not implemented"))
        }

        fn clear_cache(&self) {}
    }

    let runtime = DerpRuntimeCtx {
        dns_router: Some(Arc::new(FakeRouter)),
        outbounds: None,
    };

    let state = DerpHttpState {
        tag: Arc::from("derp-test"),
        peer: "127.0.0.1:0".parse().unwrap(),
        client_registry: Arc::new(ClientRegistry::new(Arc::from("derp-test"))),
        server_private_key: [0u8; 32],
        server_public_key: [0u8; 32],
        mesh_psk: None,
        home: Arc::from(""),
        runtime,
        verify_client_urls: Arc::from(Vec::<DerpVerifyClientUrlCfg>::new().into_boxed_slice()),
        verify_client_endpoints: Arc::new(parking_lot::RwLock::new(Vec::new())),
    };

    let req = HyperRequest::builder()
        .method(Method::GET)
        .uri("/bootstrap-dns?q=example.com")
        .body(Body::empty())
        .unwrap();
    let resp = state.clone().handle(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v, serde_json::json!({ "example.com": ["1.2.3.4"] }));
}

#[tokio::test]
async fn test_domain_resolver_dialer_uses_injected_dns_router() {
    #[derive(Clone, Debug)]
    struct FakeRouter {
        ip: IpAddr,
        lookups: Arc<std::sync::atomic::AtomicUsize>,
        last_transport: Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl DnsRouter for FakeRouter {
        async fn exchange(
            &self,
            _ctx: &DnsQueryContext,
            _message: &[u8],
        ) -> anyhow::Result<Vec<u8>> {
            Err(anyhow::anyhow!("not implemented"))
        }

        async fn lookup(
            &self,
            ctx: &DnsQueryContext,
            domain: &str,
        ) -> anyhow::Result<Vec<std::net::IpAddr>> {
            assert_eq!(domain, "derp.test");
            self.lookups.fetch_add(1, Ordering::Relaxed);
            *self.last_transport.lock().unwrap() = ctx.transport.clone();
            Ok(vec![self.ip])
        }

        async fn lookup_default(&self, _domain: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
            Err(anyhow::anyhow!("not implemented"))
        }

        async fn resolve(
            &self,
            _ctx: &DnsQueryContext,
            _domain: &str,
        ) -> anyhow::Result<sb_core::dns::DnsAnswer> {
            Err(anyhow::anyhow!("not implemented"))
        }

        fn clear_cache(&self) {}
    }

    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping DERP domain_resolver test: {e}");
            return;
        }
        Err(e) => panic!("failed to bind DERP domain_resolver test listener: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let last_transport = Arc::new(std::sync::Mutex::new(None));
    let runtime = DerpRuntimeCtx {
        dns_router: Some(Arc::new(FakeRouter {
            ip: addr.ip(),
            lookups: lookups.clone(),
            last_transport: last_transport.clone(),
        })),
        outbounds: None,
    };
    let dial = DerpDialOptionsIR {
        domain_resolver: Some(StringOrObj(sb_config::ir::DerpDomainResolverIR {
            server: Some("dns-a".to_string()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let dialer = DerpService::build_derp_dialer(&runtime, &dial, None, None)
        .expect("domain_resolver dialer");

    let mut stream = dialer
        .connect("derp.test", addr.port())
        .await
        .expect("dial through domain_resolver");
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");

    server.await.unwrap();
    assert_eq!(lookups.load(Ordering::Relaxed), 1);
    assert_eq!(
        last_transport.lock().unwrap().as_deref(),
        Some("dns-a"),
        "domain_resolver.server should be passed as DNS lookup transport"
    );
}

#[tokio::test]
async fn test_verify_client_url_detour_uses_outbound_connector() {
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};

    #[derive(Debug)]
    struct TestConnector {
        calls: Arc<tokio::sync::Mutex<Vec<(String, u16)>>>,
    }

    impl sb_types::Outbound for TestConnector {
        fn r#type(&self) -> &str {
            "test"
        }
        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new("test")
        }
        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp]
        }
        fn dial<'a>(
            &'a self,
            session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async move {
                use tokio_util::compat::TokioAsyncReadCompatExt;
                let (host, port) = match &session.target {
                    sb_types::TargetAddr::Socket(address) => {
                        (address.ip().to_string(), address.port())
                    }
                    sb_types::TargetAddr::Domain(host, port) => (host.clone(), *port),
                };
                self.calls.lock().await.push((host.to_string(), port));
                let stream = tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
                Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
            })
        }
        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            Box::pin(async {
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "test",
                ))
            })
        }
    }

    // Minimal HTTP server: accept one request, respond 204.
    let listener = match tokio::net::TcpListener::bind(("127.0.0.1", 0)).await {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping verify_client_url detour test: {e}");
            return;
        }
        Err(e) => panic!("bind: {e}"),
    };
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf).await;
        let _ = s
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    });

    let calls = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut reg = OutboundRegistry::default();
    reg.insert(
        "d1".to_string(),
        OutboundImpl::Connector(Arc::new(TestConnector {
            calls: calls.clone(),
        })),
    );
    let outbounds = Arc::new(OutboundRegistryHandle::new(reg));

    let runtime = DerpRuntimeCtx {
        dns_router: None,
        outbounds: Some(outbounds),
    };

    let url = Url::parse(&format!("http://127.0.0.1:{port}/verify")).unwrap();
    let cfg = DerpVerifyClientUrlCfg {
        url,
        dial: DerpDialOptionsIR {
            detour: Some("d1".to_string()),
            ..Default::default()
        },
    };
    let key: PublicKey = [7u8; 32];
    let ok = DerpService::verify_client_via_urls(&runtime, &[cfg], &key)
        .await
        .unwrap();
    assert!(ok);

    let got = calls.lock().await.clone();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, "127.0.0.1");
    assert_eq!(got[0].1, port);
}

#[test]
fn test_verify_client_endpoint_tags_resolved_at_poststart() {
    use sb_core::endpoint::tailscale::{
        DaemonControlPlane, TailscaleEndpoint, TailscaleEndpointConfig,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;

    let tls = TestTls::new();
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir
        .path()
        .join("derp.key")
        .to_string_lossy()
        .to_string();

    let endpoint_ir: EndpointIR =
        serde_json::from_value(serde_json::json!({"type":"tailscale","tag":"ts0"})).unwrap();
    let ts_cfg = TailscaleEndpointConfig::from_ir(&endpoint_ir);
    let ts = TailscaleEndpoint::with_config(ts_cfg.clone(), None);
    let sock = PathBuf::from("/tmp/test-tailscaled.sock");
    ts.set_control_plane(Arc::new(DaemonControlPlane::with_socket(
        sock.clone(),
        ts_cfg,
    )));

    let mut map: HashMap<String, Arc<dyn sb_core::endpoint::Endpoint>> = HashMap::new();
    map.insert("ts0".to_string(), Arc::new(ts));

    let ctx = ServiceContext::new().with_endpoints(Arc::new(map));
    let ir = ServiceIR {
        ty: ServiceType::Derp,
        tag: Some("derp".to_string()),
        listen: Some("127.0.0.1".to_string()),
        listen_port: Some(0),
        config_path: Some(config_path),
        tls: Some(tls.tls_ir()),
        stun: Some(DerpStunOptionsIR {
            enabled: false,
            ..Default::default()
        }),
        verify_client_endpoint: Some(Listable {
            items: vec!["ts0".to_string()],
        }),
        ..Default::default()
    };

    let svc = DerpService::from_ir(&ir, &ctx).unwrap();
    svc.start(StartStage::PostStart).unwrap();

    let sockets = svc.verify_client_endpoint_sockets.read().clone();
    assert_eq!(sockets, vec![sock.to_string_lossy().to_string()]);
}
