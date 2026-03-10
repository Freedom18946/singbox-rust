#![cfg(all(feature = "adapter-shadowtls", feature = "adapter-shadowsocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sb_adapters::build_default_registry;
use sb_adapters::inbound::shadowsocks::{
    ShadowsocksInboundAdapter, ShadowsocksInboundConfig, ShadowsocksUser,
};
use sb_adapters::inbound::shadowtls::{
    serve as serve_shadowtls, ShadowTlsHandshakeConfig, ShadowTlsInboundConfig,
    ShadowTlsWildcardSniMode,
};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::registry as core_registry;
use sb_core::adapter::{InboundService, OutboundParam};
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

fn install_direct_rules_engine() {
    let rules = sb_core::router::rules::parse_rules("default=direct");
    let engine = sb_core::router::rules::Engine::build(rules);
    sb_core::router::rules::install_global(engine);
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

fn tls_acceptor() -> TlsAcceptor {
    let (certs, key) = generate_cert();
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    TlsAcceptor::from(Arc::new(server_config))
}

async fn start_tls_handshake_server() -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let acceptor = tls_acceptor();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let mut buf = [0u8; 1];
        let _ = tls_stream.read(&mut buf).await;
    });
    Ok((addr, task))
}

async fn start_echo_server(
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        buf.truncate(n);
        buf
    });
    Ok((addr, task))
}

#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_v2_inbound_detours_into_shadowsocks_inbound() {
    install_direct_rules_engine();

    let (echo_addr, echo_task) = start_echo_server().await.expect("bind echo");
    let (handshake_addr, handshake_task) = start_tls_handshake_server()
        .await
        .expect("bind handshake server");

    #[allow(deprecated)]
    let ss_adapter = Arc::new(ShadowsocksInboundAdapter::with_tag(
        ShadowsocksInboundConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            method: "aes-256-gcm".to_string(),
            password: None,
            users: vec![ShadowsocksUser::new(
                "default".to_string(),
                "test_password".to_string(),
            )],
            router: Arc::new(sb_core::router::RouterHandle::new_mock()),
            tag: Some("ss-detour".to_string()),
            stats: None,
            multiplex: None,
            transport_layer: None,
        },
        "ss-detour".to_string(),
    ));

    let mut inbounds = HashMap::new();
    inbounds.insert(
        "ss-detour".to_string(),
        ss_adapter.clone() as Arc<dyn InboundService>,
    );
    core_registry::install_runtime_inbounds(Arc::new(core_registry::InboundRegistryHandle::new(
        inbounds,
    )));

    let probe = TcpListener::bind("127.0.0.1:0").await.expect("reserve shadowtls port");
    let shadowtls_addr = probe.local_addr().unwrap();
    drop(probe);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let shadowtls_task = tokio::spawn(serve_shadowtls(
        ShadowTlsInboundConfig {
            listen: shadowtls_addr,
            detour: "ss-detour".to_string(),
            version: 2,
            password: Some("interop-password".to_string()),
            users: Vec::new(),
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "127.0.0.1".to_string(),
                server_port: handshake_addr.port(),
            }),
            handshake_for_server_name: HashMap::new(),
            strict_mode: false,
            wildcard_sni: ShadowTlsWildcardSniMode::Off,
            tag: Some("shadowtls-in".to_string()),
            tls: None,
            router: None,
            stats: None,
        },
        stop_rx,
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let snapshot = build_default_registry();
    core_registry::install_snapshot(&snapshot);
    let builder = core_registry::get_outbound("shadowtls").expect("shadowtls builder");
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
        port: Some(shadowtls_addr.port()),
        password: Some("interop-password".to_string()),
        version: Some(2),
        tls_sni: Some("localhost".to_string()),
        tls_alpn: Some(vec!["http/1.1".to_string()]),
        skip_cert_verify: Some(true),
        ..Default::default()
    };
    let (shadowtls_connector, _) = builder(&param, &ir, &ctx).expect("shadowtls connector");

    let mut outbounds = OutboundRegistry::default();
    outbounds.insert(
        "shadowtls-wrap-v2".to_string(),
        OutboundImpl::Connector(shadowtls_connector),
    );
    core_registry::install_runtime_outbounds(Arc::new(OutboundRegistryHandle::new(outbounds)));

    let shadowsocks = ShadowsocksConnector::new(ShadowsocksConfig {
        server: shadowtls_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: Some("shadowtls-wrap-v2".to_string()),
        multiplex: None,
    })
    .unwrap();

    let mut stream = timeout(
        Duration::from_secs(5),
        shadowsocks.dial(
            Target::tcp("127.0.0.1", echo_addr.port()),
            DialOpts::new().with_connect_timeout(Duration::from_secs(5)),
        ),
    )
    .await
    .expect("shadowsocks dial timeout")
    .expect("shadowtls inbound chain should dial");

    stream.write_all(b"shadowtls-v2-ok").await.unwrap();
    let mut buf = [0u8; 15];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"shadowtls-v2-ok");

    drop(stream);
    let _ = stop_tx.try_send(());
    let echoed = echo_task.await.unwrap();
    assert_eq!(echoed, b"shadowtls-v2-ok");
    handshake_task.abort();
    shadowtls_task.abort();
}
