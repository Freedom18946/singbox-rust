#![cfg(all(feature = "router", feature = "adapters"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sb_adapters::inbound::shadowsocks::{serve, ShadowsocksInboundConfig, ShadowsocksUser};
use sb_config::ir::{ConfigIR, OutboundIR, OutboundType};
use sb_core::adapter::bridge::build_bridge;
use sb_core::adapter::registry::runtime_outbounds;
use sb_core::outbound::{Endpoint, RouteTarget};
use sb_core::routing::engine::Engine;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn install_direct_rules_engine() {
    let rules = sb_core::router::rules::parse_rules("default=direct");
    let engine = sb_core::router::rules::Engine::build(rules);
    sb_core::router::rules::install_global(engine);
}

fn generate_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der().unwrap();
    (
        vec![CertificateDer::from(cert)],
        PrivateKeyDer::try_from(key).unwrap(),
    )
}

async fn start_echo_server(
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);
        let payload = buf[..n].to_vec();
        if n > 0 {
            stream.write_all(&buf[..n]).await.unwrap();
        }
        payload
    });
    Ok((addr, task))
}

fn tls12_acceptor() -> TlsAcceptor {
    let (certs, key) = generate_cert();
    let server_config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    TlsAcceptor::from(Arc::new(server_config))
}

async fn start_tls12_handshake_server(
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let acceptor = tls12_acceptor();

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

async fn start_shadowtls_v1_relay(
    upstream: std::net::SocketAddr,
) -> std::io::Result<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
)> {
    let (handshake_addr, handshake_task) = start_tls12_handshake_server().await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

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

        let mut upstream_stream = TcpStream::connect(upstream).await.unwrap();
        if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut upstream_stream).await {
            let msg = err.to_string().to_ascii_lowercase();
            let benign_eof = msg.contains("unexpectedeof")
                || msg.contains("unexpected eof")
                || msg.contains("close_notify");
            assert!(
                benign_eof,
                "shadowtls relay copy failed unexpectedly: {err}"
            );
        }
    });

    Ok((addr, relay_task, handshake_task))
}

async fn start_shadowsocks_inbound(
    listen: std::net::SocketAddr,
) -> std::io::Result<(tokio::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>)> {
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let cfg = ShadowsocksInboundConfig {
        listen,
        method: "aes-256-gcm".to_string(),
        #[allow(deprecated)]
        password: None,
        users: vec![ShadowsocksUser::new(
            "test".to_string(),
            "test_password".to_string(),
        )],
        router: Arc::new(sb_core::router::engine::RouterHandle::new_mock()),
        tag: None,
        stats: None,
        multiplex: None,
        transport_layer: None,
    };

    let task = tokio::spawn(async move {
        let _ = serve(cfg, stop_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok((stop_tx, task))
}

#[tokio::test]
async fn config_bridge_builds_shadowtls_detour_chain_for_shadowsocks() {
    install_rustls_provider();
    install_direct_rules_engine();
    sb_adapters::register_all();

    let (echo_addr, echo_task) = start_echo_server()
        .await
        .expect("failed to bind echo server");
    let ss_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind shadowsocks inbound listener");
    let ss_addr = ss_listener.local_addr().unwrap();
    drop(ss_listener);
    let (ss_stop_tx, ss_task) = start_shadowsocks_inbound(ss_addr)
        .await
        .expect("failed to start shadowsocks inbound");
    let (relay_addr, relay_task, handshake_task) = start_shadowtls_v1_relay(ss_addr)
        .await
        .expect("failed to bind shadowtls relay");

    let ir = ConfigIR {
        outbounds: vec![
            OutboundIR {
                ty: OutboundType::Shadowtls,
                name: Some("stl-wrap".into()),
                server: Some("127.0.0.1".into()),
                port: Some(relay_addr.port()),
                password: Some("interop-password".into()),
                version: Some(1),
                tls_sni: Some("localhost".into()),
                tls_alpn: Some(vec!["http/1.1".into()]),
                skip_cert_verify: Some(true),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Shadowsocks,
                name: Some("ss-chain".into()),
                server: Some("127.0.0.1".into()),
                port: Some(ss_addr.port()),
                method: Some("aes-256-gcm".into()),
                password: Some("test_password".into()),
                detour: Some("stl-wrap".into()),
                connect_timeout_sec: Some(5),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let engine = Engine::new(std::sync::Arc::new(ir.clone()));
    let _bridge = build_bridge(&ir, engine, sb_core::context::Context::default());
    let outbounds = runtime_outbounds().expect("runtime outbounds should be installed");

    let mut stream = outbounds
        .connect_io(
            &RouteTarget::Named("ss-chain".to_string()),
            Endpoint::Ip(echo_addr),
        )
        .await
        .expect("config-driven shadowsocks detour chain should connect");
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("echo read timed out")
        .expect("echo read failed");
    assert_eq!(&buf, b"ping");
    drop(stream);

    let echoed = echo_task.await.unwrap();
    assert_eq!(echoed, b"ping");

    let _ = ss_stop_tx.send(()).await;
    ss_task.abort();
    relay_task.abort();
    handshake_task.abort();
}
