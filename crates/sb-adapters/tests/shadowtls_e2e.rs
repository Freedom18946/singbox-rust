#![cfg(feature = "adapter-shadowtls")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use futures::future::abortable;
use hmac::{Hmac, Mac};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sb_adapters::build_default_registry;
#[cfg(feature = "adapter-shadowsocks")]
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::registry as core_registry;
use sb_core::adapter::OutboundParam;
#[cfg(feature = "adapter-shadowsocks")]
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use serial_test::serial;
use sha1::Sha1;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsAcceptor;

fn test_connector() -> ShadowTlsConnector {
    ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 443,
        version: 1,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    })
}

fn generate_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = cert.key_pair.serialize_der();
    let cert = cert.cert.der().to_vec();
    (
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::try_from(key).unwrap(),
    )
}

async fn start_tls_echo_server() -> std::io::Result<TcpListener> {
    TcpListener::bind("127.0.0.1:0").await
}

async fn start_tcp_echo_server() -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 256];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    Ok((addr, task))
}

fn tls_acceptor(tls12_only: bool) -> TlsAcceptor {
    let (certs, key) = generate_cert();
    let builder = if tls12_only {
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
    } else {
        rustls::ServerConfig::builder()
    };
    let server_config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    TlsAcceptor::from(Arc::new(server_config))
}

async fn start_tls12_handshake_server() -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>)> {
    let listener = start_tls_echo_server().await?;
    let addr = listener.local_addr()?;
    let acceptor = tls_acceptor(true);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let mut buf = [0u8; 1];
        let _ = tls_stream.read(&mut buf).await;
    });
    Ok((addr, task))
}

async fn start_tls_handshake_server() -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>)> {
    let listener = start_tls_echo_server().await?;
    let addr = listener.local_addr()?;
    let acceptor = tls_acceptor(false);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let mut buf = [0u8; 1];
        let _ = tls_stream.read(&mut buf).await;
    });
    Ok((addr, task))
}

async fn copy_until_handshake_finished<R, W>(dst: &mut W, src: &mut R) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const TLS_HEADER_SIZE: usize = 5;
    const HANDSHAKE: u8 = 22;
    const CHANGE_CIPHER_SPEC: u8 = 20;

    let mut seen_change_cipher_spec = false;
    let mut header = [0u8; TLS_HEADER_SIZE];
    loop {
        src.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        dst.write_all(&header).await?;
        let mut payload = vec![0u8; length];
        src.read_exact(&mut payload).await?;
        dst.write_all(&payload).await?;
        if header[0] != HANDSHAKE {
            if header[0] != CHANGE_CIPHER_SPEC {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected tls frame type: {}", header[0]),
                ));
            }
            if !seen_change_cipher_spec {
                seen_change_cipher_spec = true;
                continue;
            }
        }
        if seen_change_cipher_spec {
            dst.flush().await?;
            return Ok(());
        }
    }
}

async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "early eof",
            ));
        }
        filled += n;
    }
    Ok(true)
}

async fn read_shadowtls_payload<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    if header[0] != 23 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected tls frame type: {}", header[0]),
        ));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; length];
    read_exact_or_eof(reader, &mut payload).await?;
    Ok(Some(payload))
}

async fn write_shadowtls_payload<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 5];
    header[0] = 23;
    header[1] = 0x03;
    header[2] = 0x03;
    header[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await
}

type HmacSha1 = Hmac<Sha1>;

struct V2HashState {
    hmac: HmacSha1,
    has_content: bool,
    last_sum: Option<[u8; 8]>,
}

impl V2HashState {
    fn new(password: &str) -> Self {
        Self {
            hmac: HmacSha1::new_from_slice(password.as_bytes())
                .expect("hmac accepts any key length"),
            has_content: false,
            last_sum: None,
        }
    }

    fn current_sum(&self) -> [u8; 8] {
        let mut sum = [0u8; 8];
        let digest = self.hmac.clone().finalize().into_bytes();
        sum.copy_from_slice(&digest[..8]);
        sum
    }

    fn note_write(&mut self, bytes: &[u8]) {
        if self.has_content {
            self.last_sum = Some(self.current_sum());
        }
        self.hmac.update(bytes);
        self.has_content = true;
    }
}

async fn copy_and_hash<R, W>(
    dst: &mut W,
    src: &mut R,
    state: Arc<tokio::sync::Mutex<V2HashState>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        {
            let mut guard = state.lock().await;
            guard.note_write(&buf[..n]);
        }
        dst.write_all(&buf[..n]).await?;
    }
}

async fn copy_until_handshake_finished_v2<R, W>(
    dst: &mut W,
    src: &mut R,
    state: Arc<tokio::sync::Mutex<V2HashState>>,
    fallback_after: usize,
) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 5];
    let mut application_data_count = 0usize;
    loop {
        read_exact_or_eof(src, &mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut payload = vec![0u8; length];
        read_exact_or_eof(src, &mut payload).await?;

        if header[0] == 23 {
            let snapshot = {
                let guard = state.lock().await;
                (guard.has_content, guard.current_sum(), guard.last_sum)
            };
            if snapshot.0 && payload.len() >= 8 {
                let candidate = &payload[..8];
                if candidate == snapshot.1.as_slice()
                    || snapshot
                        .2
                        .as_ref()
                        .map(|last| candidate == last.as_slice())
                        .unwrap_or(false)
                {
                    payload.drain(..8);
                    return Ok(payload);
                }
            }
            application_data_count += 1;
        }

        dst.write_all(&header).await?;
        dst.write_all(&payload).await?;

        if application_data_count > fallback_after {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "shadowtls v2 fallback triggered",
            ));
        }
    }
}

async fn start_shadowtls_v1_relay(
    target: std::net::SocketAddr,
) -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>, JoinHandle<()>)> {
    let (handshake_addr, handshake_task) = start_tls12_handshake_server().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = listener.local_addr()?;
    let relay_task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut handshake = TcpStream::connect(handshake_addr).await.unwrap();
        {
            let (mut client_read, mut client_write) = client.split();
            let (mut handshake_read, mut handshake_write) = handshake.split();
            tokio::try_join!(
                copy_until_handshake_finished(&mut handshake_write, &mut client_read),
                copy_until_handshake_finished(&mut client_write, &mut handshake_read),
            )
            .unwrap();
        }
        drop(handshake);

        let mut upstream = TcpStream::connect(target).await.unwrap();
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .unwrap();
    });
    Ok((relay_addr, relay_task, handshake_task))
}

async fn start_shadowtls_v2_relay(
    target: std::net::SocketAddr,
    password: &str,
) -> std::io::Result<(std::net::SocketAddr, JoinHandle<()>, JoinHandle<()>)> {
    let (handshake_addr, handshake_task) = start_tls_handshake_server().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_addr = listener.local_addr()?;
    let password = password.to_string();
    let relay_task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut handshake = TcpStream::connect(handshake_addr).await.unwrap();

        let request = {
            let hash_state = Arc::new(tokio::sync::Mutex::new(V2HashState::new(&password)));
            let (mut client_read, mut client_write) = client.split();
            let (mut handshake_read, mut handshake_write) = handshake.split();
            let (server_copy, abort_handle) = abortable(copy_and_hash(
                &mut client_write,
                &mut handshake_read,
                hash_state.clone(),
            ));
            tokio::pin!(server_copy);
            let request = tokio::select! {
                request = copy_until_handshake_finished_v2(
                    &mut handshake_write,
                    &mut client_read,
                    hash_state.clone(),
                    2,
                ) => {
                    abort_handle.abort();
                    request.unwrap()
                }
                result = &mut server_copy => {
                    match result {
                        Ok(Ok(())) => panic!("shadowtls v2 server copy ended before request"),
                        Ok(Err(err)) => panic!("shadowtls v2 server copy failed: {err}"),
                        Err(_) => panic!("shadowtls v2 server copy aborted before request"),
                    }
                }
            };
            let _ = server_copy.await;
            request
        };
        drop(handshake);

        let mut upstream = TcpStream::connect(target).await.unwrap();
        if !request.is_empty() {
            upstream.write_all(&request).await.unwrap();
        }
        let (mut client_read, mut client_write) = client.into_split();
        let (mut upstream_read, mut upstream_write) = upstream.into_split();

        let client_to_upstream = async {
            while let Some(payload) = read_shadowtls_payload(&mut client_read).await? {
                if !payload.is_empty() {
                    upstream_write.write_all(&payload).await?;
                }
            }
            upstream_write.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };

        let upstream_to_client = async {
            let mut buf = [0u8; 16 * 1024];
            loop {
                let n = upstream_read.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<(), std::io::Error>(());
                }
                write_shadowtls_payload(&mut client_write, &buf[..n]).await?;
            }
        };

        tokio::try_join!(client_to_upstream, upstream_to_client).unwrap();
    });
    Ok((relay_addr, relay_task, handshake_task))
}

#[tokio::test]
async fn shadowtls_rejects_standalone_leaf_dialing() {
    let connector = test_connector();
    let err = timeout(
        Duration::from_secs(2),
        connector.dial(Target::tcp("127.0.0.1", 18080), DialOpts::default()),
    )
    .await
    .expect("shadowtls guardrail dial timed out");
    let err = match err {
        Ok(_) => panic!("shadowtls standalone leaf dial should be rejected"),
        Err(err) => err,
    };

    assert!(
        err.to_string()
            .contains("standalone leaf dialing is disabled"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("transport-wrapper/detour model"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn shadowtls_standalone_rejection_happens_before_network_io() {
    let connector = ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 1,
        version: 1,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: false,
        utls_fingerprint: None,
    });

    let err = timeout(
        Duration::from_secs(2),
        connector.dial(Target::tcp("198.51.100.10", 443), DialOpts::default()),
    )
    .await
    .expect("shadowtls guardrail dial timed out");
    let err = match err {
        Ok(_) => panic!("shadowtls standalone leaf dial should be rejected before connect"),
        Err(err) => err,
    };

    assert!(
        err.to_string()
            .contains("standalone leaf dialing is disabled"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn shadowtls_detour_wrapper_connects_for_configured_server() {
    let (echo_addr, echo_task) = start_tcp_echo_server()
        .await
        .expect("failed to bind tcp echo listener");
    let (relay_addr, relay_task, handshake_task) = start_shadowtls_v1_relay(echo_addr)
        .await
        .expect("failed to start shadowtls v1 relay");

    let connector = ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: relay_addr.port(),
        version: 1,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    });

    let mut stream = connector
        .connect_detour_stream("127.0.0.1", echo_addr.port())
        .await
        .expect("shadowtls detour wrapper should connect");
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    drop(stream);
    relay_task.await.unwrap();
    echo_task.await.unwrap();
    handshake_task.abort();
}

#[tokio::test]
async fn shadowtls_detour_wrapper_ignores_requested_target() {
    let (echo_addr, echo_task) = start_tcp_echo_server()
        .await
        .expect("failed to bind tcp echo listener");
    let (relay_addr, relay_task, handshake_task) = start_shadowtls_v1_relay(echo_addr)
        .await
        .expect("failed to start shadowtls v1 relay");

    let connector = ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: relay_addr.port(),
        version: 1,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    });

    let mut stream = connector
        .connect_detour_stream("198.51.100.10", 8443)
        .await
        .expect("wrapper should ignore requested target");
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    drop(stream);
    relay_task.await.unwrap();
    echo_task.await.unwrap();
    handshake_task.abort();
}

#[tokio::test]
async fn shadowtls_v2_detour_wrapper_connects_for_configured_server() {
    let (echo_addr, echo_task) = start_tcp_echo_server()
        .await
        .expect("failed to bind tcp echo listener");
    let (relay_addr, relay_task, handshake_task) =
        start_shadowtls_v2_relay(echo_addr, "interop-password")
            .await
            .expect("failed to start shadowtls v2 relay");

    let connector = ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: relay_addr.port(),
        version: 2,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    });

    let mut stream = connector
        .connect_detour_stream("127.0.0.1", echo_addr.port())
        .await
        .expect("shadowtls v2 detour wrapper should connect");
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    drop(stream);
    relay_task.await.unwrap();
    echo_task.await.unwrap();
    handshake_task.abort();
}

#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_registry_builder_exposes_detour_only_connect_io() {
    let (echo_addr, echo_task) = start_tcp_echo_server()
        .await
        .expect("failed to bind tcp echo listener");
    let (relay_addr, relay_task, handshake_task) = start_shadowtls_v1_relay(echo_addr)
        .await
        .expect("failed to start shadowtls v1 relay");

    let snapshot = build_default_registry();
    core_registry::install_snapshot(&snapshot);
    let builder = core_registry::get_outbound("shadowtls")
        .expect("shadowtls outbound builder should be registered");

    let context = sb_core::context::Context::new();
    let bridge = Arc::new(sb_core::adapter::Bridge::new(context));
    let ctx = core_registry::AdapterOutboundContext {
        context: sb_core::context::ContextRegistry::from(&bridge.context),
        bridge,
    };
    let param = OutboundParam {
        kind: "shadowtls".into(),
        name: Some("shadowtls-registry-test".into()),
        ..Default::default()
    };
    let ir = OutboundIR {
        ty: OutboundType::Shadowtls,
        server: Some("127.0.0.1".to_string()),
        port: Some(relay_addr.port()),
        password: Some("interop-password".to_string()),
        version: Some(1),
        tls_sni: Some("localhost".to_string()),
        tls_alpn: Some(vec!["http/1.1".to_string()]),
        skip_cert_verify: Some(true),
        ..Default::default()
    };

    let (connector, udp_factory) = builder(&param, &ir, &ctx).expect("builder should succeed");
    assert!(udp_factory.is_none());

    let mut stream = connector
        .connect_io("198.51.100.10", 443)
        .await
        .expect("wrapper connect_io should ignore requested target");
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    drop(stream);
    relay_task.await.unwrap();
    echo_task.await.unwrap();
    handshake_task.abort();
}

#[tokio::test]
async fn shadowtls_detour_wrapper_rejects_unimplemented_versions() {
    let connector = ShadowTlsConnector::new(ShadowTlsAdapterConfig {
        server: "127.0.0.1".to_string(),
        port: 443,
        version: 3,
        password: "interop-password".to_string(),
        sni: "localhost".to_string(),
        alpn: Some("http/1.1".to_string()),
        skip_cert_verify: true,
        utls_fingerprint: None,
    });

    let err = match connector.connect_detour_stream("127.0.0.1", 443).await {
        Ok(_) => panic!("v3 wrapper path should be rejected for now"),
        Err(err) => err,
    };
    assert!(!err.to_string().is_empty());
}

#[cfg(feature = "adapter-shadowsocks")]
#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_shadowsocks_detour_chain_completes_mock_handshake() {
    let ss_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock shadowsocks listener");
    let ss_addr = ss_listener.local_addr().unwrap();
    let ss_server = tokio::spawn(async move {
        let (mut stream, _) = ss_listener.accept().await.unwrap();
        let mut buf = [0u8; 256];

        let n1 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n1 == 0 {
            return false;
        }

        let server_salt = [7u8; 32];
        if stream.write_all(&server_salt).await.is_err() {
            return false;
        }
        true
    });

    let (relay_addr, relay_task, handshake_task) = start_shadowtls_v1_relay(ss_addr)
        .await
        .expect("failed to bind shadowtls relay listener");

    let snapshot = build_default_registry();
    core_registry::install_snapshot(&snapshot);
    let builder = core_registry::get_outbound("shadowtls")
        .expect("shadowtls outbound builder should be registered");

    let context = sb_core::context::Context::new();
    let bridge = Arc::new(sb_core::adapter::Bridge::new(context));
    let ctx = core_registry::AdapterOutboundContext {
        context: sb_core::context::ContextRegistry::from(&bridge.context),
        bridge,
    };
    let param = OutboundParam {
        kind: "shadowtls".into(),
        name: Some("shadowtls-wrap".into()),
        ..Default::default()
    };
    let ir = OutboundIR {
        ty: OutboundType::Shadowtls,
        server: Some("127.0.0.1".to_string()),
        port: Some(relay_addr.port()),
        password: Some("interop-password".to_string()),
        version: Some(1),
        tls_sni: Some("localhost".to_string()),
        tls_alpn: Some(vec!["http/1.1".to_string()]),
        skip_cert_verify: Some(true),
        ..Default::default()
    };
    let (shadowtls_connector, _) = builder(&param, &ir, &ctx).expect("builder should succeed");

    let mut outbounds = OutboundRegistry::default();
    outbounds.insert(
        "shadowtls-wrap".to_string(),
        OutboundImpl::Connector(shadowtls_connector),
    );
    core_registry::install_runtime_outbounds(Arc::new(OutboundRegistryHandle::new(outbounds)));

    let shadowsocks = ShadowsocksConnector::new(ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: Some("shadowtls-wrap".to_string()),
        multiplex: None,
    })
    .unwrap();

    let result = shadowsocks
        .dial(
            Target::tcp("example.com", 80),
            DialOpts::new().with_connect_timeout(Duration::from_secs(5)),
        )
        .await;
    assert!(
        result.is_ok(),
        "chained shadowsocks over shadowtls should dial"
    );
    drop(result);

    let ss_handshake_ok = ss_server.await.unwrap();
    assert!(
        ss_handshake_ok,
        "mock shadowsocks server should receive handshake over shadowtls detour"
    );
    relay_task.abort();
    handshake_task.abort();
}

#[cfg(feature = "adapter-shadowsocks")]
#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_v2_shadowsocks_detour_chain_completes_mock_handshake() {
    let ss_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock shadowsocks listener");
    let ss_addr = ss_listener.local_addr().unwrap();
    let ss_server = tokio::spawn(async move {
        let (mut stream, _) = ss_listener.accept().await.unwrap();
        let mut buf = [0u8; 256];

        let n1 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        if n1 == 0 {
            return false;
        }

        let server_salt = [7u8; 32];
        if stream.write_all(&server_salt).await.is_err() {
            return false;
        }

        let n2 = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        n2 > 0
    });

    let (relay_addr, relay_task, handshake_task) =
        start_shadowtls_v2_relay(ss_addr, "interop-password")
            .await
            .expect("failed to bind shadowtls v2 relay listener");

    let snapshot = build_default_registry();
    core_registry::install_snapshot(&snapshot);
    let builder = core_registry::get_outbound("shadowtls")
        .expect("shadowtls outbound builder should be registered");

    let context = sb_core::context::Context::new();
    let bridge = Arc::new(sb_core::adapter::Bridge::new(context));
    let ctx = core_registry::AdapterOutboundContext {
        context: sb_core::context::ContextRegistry::from(&bridge.context),
        bridge,
    };
    let param = OutboundParam {
        kind: "shadowtls".into(),
        name: Some("shadowtls-wrap-v2".into()),
        ..Default::default()
    };
    let ir = OutboundIR {
        ty: OutboundType::Shadowtls,
        server: Some("127.0.0.1".to_string()),
        port: Some(relay_addr.port()),
        password: Some("interop-password".to_string()),
        version: Some(2),
        tls_sni: Some("localhost".to_string()),
        tls_alpn: Some(vec!["http/1.1".to_string()]),
        skip_cert_verify: Some(true),
        ..Default::default()
    };
    let (shadowtls_connector, _) = builder(&param, &ir, &ctx).expect("builder should succeed");

    let mut outbounds = OutboundRegistry::default();
    outbounds.insert(
        "shadowtls-wrap-v2".to_string(),
        OutboundImpl::Connector(shadowtls_connector),
    );
    core_registry::install_runtime_outbounds(Arc::new(OutboundRegistryHandle::new(outbounds)));

    let shadowsocks = ShadowsocksConnector::new(ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: Some("shadowtls-wrap-v2".to_string()),
        multiplex: None,
    })
    .unwrap();

    let result = shadowsocks
        .dial(
            Target::tcp("example.com", 80),
            DialOpts::new().with_connect_timeout(Duration::from_secs(5)),
        )
        .await;
    assert!(
        result.is_ok(),
        "chained shadowsocks over shadowtls v2 should dial"
    );
    drop(result);

    ss_server.abort();
    relay_task.abort();
    handshake_task.abort();
}
