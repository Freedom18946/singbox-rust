#![cfg(all(feature = "adapter-shadowtls", feature = "adapter-shadowsocks"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hmac::{Hmac, Mac};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sb_adapters::build_default_registry;
use sb_adapters::inbound::shadowsocks::{
    ShadowsocksInboundAdapter, ShadowsocksInboundConfig, ShadowsocksUser,
};
use sb_adapters::inbound::shadowtls::{
    serve as serve_shadowtls, ShadowTlsHandshakeConfig, ShadowTlsInboundConfig, ShadowTlsUser,
    ShadowTlsWildcardSniMode,
};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::traits::{DialOpts, OutboundConnector, Target};
use sb_config::ir::{OutboundIR, OutboundType};
use sb_core::adapter::registry as core_registry;
use sb_core::adapter::{InboundService, OutboundParam};
use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
use serial_test::serial;
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

type HmacSha1 = Hmac<Sha1>;

fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

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

fn tls_acceptor(tls12_only: bool) -> TlsAcceptor {
    init_crypto();
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

async fn start_tls_handshake_server(
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
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

async fn start_tls_echo_server(
    tls12_only: bool,
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let acceptor = tls_acceptor(tls12_only);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tls_stream.read(&mut buf).await.unwrap();
        tls_stream.write_all(&buf[..n]).await.unwrap();
        buf.truncate(n);
        buf
    });
    Ok((addr, task))
}

async fn start_tls_reply_server(
    tls12_only: bool,
    reply: &'static [u8],
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let acceptor = tls_acceptor(tls12_only);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = tls_stream.read(&mut buf).await.unwrap();
        tls_stream.write_all(reply).await.unwrap();
        buf.truncate(n);
        buf
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

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[derive(Debug)]
struct ShadowTlsTestSessionIdGenerator {
    password: String,
}

impl rustls::client::SessionIdGenerator for ShadowTlsTestSessionIdGenerator {
    fn generate(&self, client_hello: &[u8], session_id: &mut [u8]) -> Result<(), rustls::Error> {
        const TLS_RANDOM_SIZE: usize = 32;
        const TLS_SESSION_ID_SIZE: usize = 32;
        const HMAC_SIZE: usize = 4;
        const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

        if session_id.len() != TLS_SESSION_ID_SIZE {
            return Err(rustls::Error::General(format!(
                "unexpected test session_id len {}",
                session_id.len()
            )));
        }
        if client_hello.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
            return Err(rustls::Error::General(
                "client hello too short for shadowtls v3 test auth".to_string(),
            ));
        }

        session_id.fill(0);
        rand::rngs::OsRng.fill_bytes(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);

        let mut hmac = HmacSha1::new_from_slice(self.password.as_bytes())
            .map_err(|_| rustls::Error::General("test hmac init failed".to_string()))?;
        hmac.update(&client_hello[..SESSION_ID_START]);
        hmac.update(session_id);
        hmac.update(&client_hello[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
        let digest = hmac.finalize().into_bytes();
        session_id[TLS_SESSION_ID_SIZE - HMAC_SIZE..].copy_from_slice(&digest[..HMAC_SIZE]);
        Ok(())
    }
}

fn tls_client_config(
    tls12_only: bool,
    session_id_generator: Option<Arc<dyn rustls::client::SessionIdGenerator>>,
) -> Arc<rustls::ClientConfig> {
    init_crypto();
    let builder = if tls12_only {
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
    } else {
        rustls::ClientConfig::builder()
    };
    let mut config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    if let Some(generator) = session_id_generator {
        config.resumption = rustls::client::Resumption::disabled();
        config.session_id_generator = Some(generator);
    }
    Arc::new(config)
}

async fn connect_tls_client(
    addr: std::net::SocketAddr,
    server_name: &str,
    tls12_only: bool,
    session_id_generator: Option<Arc<dyn rustls::client::SessionIdGenerator>>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let stream = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(tls_client_config(tls12_only, session_id_generator));
    let server_name = rustls::pki_types::ServerName::try_from(server_name)
        .unwrap()
        .to_owned();
    connector.connect(server_name, stream).await.unwrap()
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
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
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

    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve shadowtls port");
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

#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_v3_outbound_and_inbound_detour_into_shadowsocks_inbound() {
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
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
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

    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve shadowtls port");
    let shadowtls_addr = probe.local_addr().unwrap();
    drop(probe);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let shadowtls_task = tokio::spawn(serve_shadowtls(
        ShadowTlsInboundConfig {
            listen: shadowtls_addr,
            detour: "ss-detour".to_string(),
            version: 3,
            password: None,
            users: vec![ShadowTlsUser {
                name: Some("interop".to_string()),
                password: "interop-password".to_string(),
            }],
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "127.0.0.1".to_string(),
                server_port: handshake_addr.port(),
            }),
            handshake_for_server_name: HashMap::new(),
            strict_mode: false,
            wildcard_sni: ShadowTlsWildcardSniMode::Off,
            tag: Some("shadowtls-in-v3".to_string()),
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
        name: Some("shadowtls-wrap-v3".into()),
        ..Default::default()
    };
    let ir = OutboundIR {
        ty: OutboundType::Shadowtls,
        server: Some("127.0.0.1".to_string()),
        port: Some(shadowtls_addr.port()),
        password: Some("interop-password".to_string()),
        version: Some(3),
        tls_sni: Some("localhost".to_string()),
        tls_alpn: Some(vec!["http/1.1".to_string()]),
        skip_cert_verify: Some(true),
        ..Default::default()
    };
    let (shadowtls_connector, _) = builder(&param, &ir, &ctx).expect("shadowtls connector");

    let mut outbounds = OutboundRegistry::default();
    outbounds.insert(
        "shadowtls-wrap-v3".to_string(),
        OutboundImpl::Connector(shadowtls_connector),
    );
    core_registry::install_runtime_outbounds(Arc::new(OutboundRegistryHandle::new(outbounds)));

    let shadowsocks = ShadowsocksConnector::new(ShadowsocksConfig {
        server: shadowtls_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test_password".to_string(),
        connect_timeout_sec: Some(5),
        detour: Some("shadowtls-wrap-v3".to_string()),
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
    .expect("shadowtls v3 inbound chain should dial");

    stream.write_all(b"shadowtls-v3-ok").await.unwrap();
    let mut buf = [0u8; 15];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"shadowtls-v3-ok");

    drop(stream);
    let _ = stop_tx.try_send(());
    let echoed = echo_task.await.unwrap();
    assert_eq!(echoed, b"shadowtls-v3-ok");
    handshake_task.abort();
    shadowtls_task.abort();
}

#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_v3_inbound_strict_mode_falls_back_to_tls12_passthrough() {
    let (tls_echo_addr, tls_echo_task) =
        start_tls_echo_server(true).await.expect("bind tls12 echo");

    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve shadowtls port");
    let shadowtls_addr = probe.local_addr().unwrap();
    drop(probe);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let shadowtls_task = tokio::spawn(serve_shadowtls(
        ShadowTlsInboundConfig {
            listen: shadowtls_addr,
            detour: "unused-detour".to_string(),
            version: 3,
            password: None,
            users: vec![ShadowTlsUser {
                name: Some("interop".to_string()),
                password: "interop-password".to_string(),
            }],
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "127.0.0.1".to_string(),
                server_port: tls_echo_addr.port(),
            }),
            handshake_for_server_name: HashMap::new(),
            strict_mode: true,
            wildcard_sni: ShadowTlsWildcardSniMode::Off,
            tag: Some("shadowtls-in-v3-strict".to_string()),
            tls: None,
            router: None,
            stats: None,
        },
        stop_rx,
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let generator = Arc::new(ShadowTlsTestSessionIdGenerator {
        password: "interop-password".to_string(),
    });
    let mut tls_stream = timeout(
        Duration::from_secs(5),
        connect_tls_client(shadowtls_addr, "localhost", false, Some(generator)),
    )
    .await
    .expect("strict-mode tls connect timeout");
    tls_stream.write_all(b"shadowtls-v3-strict").await.unwrap();
    let mut buf = [0u8; 19];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"shadowtls-v3-strict");

    drop(tls_stream);
    let _ = stop_tx.try_send(());
    let echoed = tls_echo_task.await.unwrap();
    assert_eq!(echoed, b"shadowtls-v3-strict");
    shadowtls_task.abort();
}

#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_v3_inbound_wildcard_authed_unauthorized_client_uses_default_handshake() {
    let (tls_echo_addr, tls_echo_task) = start_tls_echo_server(false).await.expect("bind tls echo");

    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve shadowtls port");
    let shadowtls_addr = probe.local_addr().unwrap();
    drop(probe);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let shadowtls_task = tokio::spawn(serve_shadowtls(
        ShadowTlsInboundConfig {
            listen: shadowtls_addr,
            detour: "unused-detour".to_string(),
            version: 3,
            password: None,
            users: vec![ShadowTlsUser {
                name: Some("interop".to_string()),
                password: "interop-password".to_string(),
            }],
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "127.0.0.1".to_string(),
                server_port: tls_echo_addr.port(),
            }),
            handshake_for_server_name: HashMap::new(),
            strict_mode: false,
            wildcard_sni: ShadowTlsWildcardSniMode::Authed,
            tag: Some("shadowtls-in-v3-wildcard-authed".to_string()),
            tls: None,
            router: None,
            stats: None,
        },
        stop_rx,
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut tls_stream = timeout(
        Duration::from_secs(5),
        connect_tls_client(shadowtls_addr, "wild.example", false, None),
    )
    .await
    .expect("wildcard authed tls connect timeout");

    tls_stream.write_all(b"wildcard-authed-ok").await.unwrap();
    let mut buf = [0u8; 18];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"wildcard-authed-ok");

    drop(tls_stream);
    let _ = stop_tx.try_send(());
    let echoed = tls_echo_task.await.unwrap();
    assert_eq!(echoed, b"wildcard-authed-ok");
    shadowtls_task.abort();
}

#[tokio::test]
#[serial(shadowtls_runtime)]
async fn shadowtls_v3_inbound_custom_handshake_for_server_name_handles_unauthorized_client() {
    let (custom_addr, custom_task) = start_tls_reply_server(false, b"custom")
        .await
        .expect("bind custom tls reply");
    let default_probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve unused default tls port");
    let default_addr = default_probe.local_addr().unwrap();
    drop(default_probe);

    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve shadowtls port");
    let shadowtls_addr = probe.local_addr().unwrap();
    drop(probe);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let shadowtls_task = tokio::spawn(serve_shadowtls(
        ShadowTlsInboundConfig {
            listen: shadowtls_addr,
            detour: "unused-detour".to_string(),
            version: 3,
            password: None,
            users: vec![ShadowTlsUser {
                name: Some("interop".to_string()),
                password: "interop-password".to_string(),
            }],
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "127.0.0.1".to_string(),
                server_port: default_addr.port(),
            }),
            handshake_for_server_name: HashMap::from([(
                "custom.example".to_string(),
                ShadowTlsHandshakeConfig {
                    server: "127.0.0.1".to_string(),
                    server_port: custom_addr.port(),
                },
            )]),
            strict_mode: false,
            wildcard_sni: ShadowTlsWildcardSniMode::Off,
            tag: Some("shadowtls-in-v3-custom-fallback".to_string()),
            tls: None,
            router: None,
            stats: None,
        },
        stop_rx,
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut tls_stream = timeout(
        Duration::from_secs(5),
        connect_tls_client(shadowtls_addr, "custom.example", false, None),
    )
    .await
    .expect("custom fallback tls connect timeout");
    tls_stream.write_all(b"custom-route-check").await.unwrap();
    let mut buf = [0u8; 6];
    tls_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"custom");

    drop(tls_stream);
    let _ = stop_tx.try_send(());
    let custom_seen = custom_task.await.unwrap();
    assert_eq!(custom_seen, b"custom-route-check");
    shadowtls_task.abort();
}

#[tokio::test]
#[ignore = "requires outbound internet access to example.com:443"]
#[serial(shadowtls_runtime)]
async fn shadowtls_v3_inbound_wildcard_all_unauthorized_client_reaches_public_https_origin() {
    let probe = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve shadowtls port");
    let shadowtls_addr = probe.local_addr().unwrap();
    drop(probe);

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let shadowtls_task = tokio::spawn(serve_shadowtls(
        ShadowTlsInboundConfig {
            listen: shadowtls_addr,
            detour: "unused-detour".to_string(),
            version: 3,
            password: None,
            users: vec![ShadowTlsUser {
                name: Some("interop".to_string()),
                password: "interop-password".to_string(),
            }],
            handshake: Some(ShadowTlsHandshakeConfig {
                server: "example.com".to_string(),
                server_port: 443,
            }),
            handshake_for_server_name: HashMap::new(),
            strict_mode: false,
            wildcard_sni: ShadowTlsWildcardSniMode::All,
            tag: Some("shadowtls-in-v3-wildcard-all".to_string()),
            tls: None,
            router: None,
            stats: None,
        },
        stop_rx,
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut tls_stream = timeout(
        Duration::from_secs(10),
        connect_tls_client(shadowtls_addr, "example.com", false, None),
    )
    .await
    .expect("wildcard all tls connect timeout");

    tls_stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nUser-Agent: singbox-rust-shadowtls-e2e\r\n\r\n",
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") && response.len() < 4096 {
        let read = timeout(Duration::from_secs(10), tls_stream.read(&mut chunk))
            .await
            .expect("wildcard all response timeout")
            .unwrap();
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
    }

    assert!(
        response.starts_with(b"HTTP/1."),
        "unexpected https response prefix: {:?}",
        String::from_utf8_lossy(&response)
    );

    drop(tls_stream);
    let _ = stop_tx.try_send(());
    shadowtls_task.abort();
}
