#![cfg(feature = "net_e2e")]

//! Deterministic local VMess standard-TLS acceptance.
//!
//! REALITY and ECH are intentionally absent: standard TLS is not a valid
//! substitute for either protocol.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use rustls::pki_types::ServerName;
use sb_adapters::inbound::vmess::VmessInboundConfig;
use sb_adapters::outbound::vmess::{
    Security, VmessAuth, VmessConfig, VmessConnector, VmessTransport,
};
use sb_adapters::transport_config::TransportConfig;
use sb_core::router::engine::RouterHandle;
use sb_transport::multiplex::{MultiplexConfig, MultiplexServerConfig};
use sb_transport::{StandardTlsConfig, TlsConfig, TlsVersion};
use sb_types::{Session, TargetAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsConnector;
use uuid::Uuid;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

struct CertificateSet {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

fn certificate_set(validity: CertificateValidity) -> CertificateSet {
    let mut ca_params = CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = Certificate::from_params(ca_params).expect("generate local CA");

    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()]);
    let now = time::OffsetDateTime::now_utc();
    match validity {
        CertificateValidity::Valid => {
            leaf_params.not_before = now - time::Duration::days(1);
            leaf_params.not_after = now + time::Duration::days(30);
        }
        CertificateValidity::Expired => {
            leaf_params.not_before = now - time::Duration::days(30);
            leaf_params.not_after = now - time::Duration::days(1);
        }
        CertificateValidity::NotYetValid => {
            leaf_params.not_before = now + time::Duration::days(1);
            leaf_params.not_after = now + time::Duration::days(30);
        }
    }
    let leaf = Certificate::from_params(leaf_params).expect("generate localhost certificate");
    CertificateSet {
        ca_pem: ca.serialize_pem().expect("serialize local CA"),
        cert_pem: leaf
            .serialize_pem_with_signer(&ca)
            .expect("sign localhost certificate"),
        key_pem: leaf.serialize_private_key_pem(),
    }
}

#[derive(Clone, Copy)]
enum CertificateValidity {
    Valid,
    Expired,
    NotYetValid,
}

fn server_tls(
    certificate: &CertificateSet,
    alpn: &[&str],
    min_version: TlsVersion,
    max_version: TlsVersion,
) -> StandardTlsConfig {
    StandardTlsConfig {
        alpn: alpn.iter().map(|value| (*value).to_string()).collect(),
        cert_pem: Some(certificate.cert_pem.clone()),
        key_pem: Some(certificate.key_pem.clone()),
        min_version: Some(min_version),
        max_version: Some(max_version),
        ..Default::default()
    }
}

fn client_tls(
    ca_pem: String,
    server_name: &str,
    alpn: &[&str],
    min_version: TlsVersion,
    max_version: TlsVersion,
) -> StandardTlsConfig {
    StandardTlsConfig {
        server_name: Some(server_name.to_string()),
        alpn: alpn.iter().map(|value| (*value).to_string()).collect(),
        ca_pem: vec![ca_pem],
        min_version: Some(min_version),
        max_version: Some(max_version),
        ..Default::default()
    }
}

struct EchoServer {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl EchoServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo server");
        let addr = listener.local_addr().expect("echo server address");
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted.expect("echo accept");
                        connections.spawn(async move {
                            let mut buffer = [0_u8; 8192];
                            loop {
                                let read = stream.read(&mut buffer).await.expect("echo read");
                                if read == 0 {
                                    break;
                                }
                                stream.write_all(&buffer[..read]).await.expect("echo write");
                            }
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            addr,
            stop: Some(stop_tx),
            task: Some(task),
        }
    }

    async fn shutdown(mut self) {
        let _ = self.stop.take().expect("echo stop sender").send(());
        tokio::time::timeout(IO_TIMEOUT, self.task.take().expect("echo task"))
            .await
            .expect("echo shutdown timeout")
            .expect("echo task result");
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct VmessServer {
    addr: SocketAddr,
    stop: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl VmessServer {
    async fn start(
        uuid: Uuid,
        tls: Option<StandardTlsConfig>,
        multiplex: bool,
        handshake_timeout: Duration,
    ) -> Result<Self, String> {
        let acceptor = tls
            .as_ref()
            .map(sb_transport::build_standard_tls_acceptor)
            .transpose()
            .map_err(|error| format!("build VMess TLS server: {error}"))?;
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (bound_tx, bound_rx) = oneshot::channel();
        let config = VmessInboundConfig {
            listen: "127.0.0.1:0".parse().expect("wildcard VMess address"),
            uuid,
            security: "auto".to_string(),
            router: Arc::new(RouterHandle::new_mock()),
            tag: Some("vmess-standard-tls-test".to_string()),
            stats: None,
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
            multiplex: multiplex.then(MultiplexServerConfig::default),
            transport_layer: Some(TransportConfig::Tcp),
            fallback: None,
            fallback_for_alpn: HashMap::new(),
            tls: acceptor,
            tls_handshake_timeout: handshake_timeout,
        };
        let task = tokio::spawn(sb_adapters::inbound::vmess::serve_with_bound(
            config, stop_rx, bound_tx,
        ));
        let addr = tokio::time::timeout(IO_TIMEOUT, bound_rx)
            .await
            .map_err(|_| "VMess readiness timeout".to_string())?
            .map_err(|_| "VMess readiness sender dropped".to_string())?
            .map_err(|error| format!("VMess startup: {error}"))?;
        Ok(Self {
            addr,
            stop: Some(stop_tx),
            task: Some(task),
        })
    }

    async fn shutdown(mut self) {
        self.stop
            .take()
            .expect("VMess stop sender")
            .send(())
            .await
            .expect("VMess stop signal");
        tokio::time::timeout(IO_TIMEOUT, self.task.take().expect("VMess task"))
            .await
            .expect("VMess shutdown timeout")
            .expect("VMess task join")
            .expect("VMess server result");
    }
}

impl Drop for VmessServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn connector(
    server: SocketAddr,
    uuid: Uuid,
    tls: Option<StandardTlsConfig>,
    multiplex: bool,
) -> Result<VmessConnector, String> {
    VmessConnector::try_new(VmessConfig {
        server: server.ip().to_string(),
        port: server.port(),
        auth: VmessAuth {
            uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::Tcp,
        timeout: Some(IO_TIMEOUT),
        packet_encoding: false,
        headers: Default::default(),
        multiplex: multiplex.then(MultiplexConfig::default),
        tls: tls.map(TlsConfig::Standard),
        ..Default::default()
    })
    .map_err(|error| error.to_string())
}

async fn echo_over_vmess(
    connector: &VmessConnector,
    target: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let target = TargetAddr::from_host_port(target.ip().to_string(), target.port());
    let mut stream = tokio::time::timeout(IO_TIMEOUT, connector.dial(&Session::outbound(target)))
        .await
        .map_err(|_| "VMess dial timeout".to_string())?
        .map_err(|error| format!("VMess dial: {error}"))?;
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(payload))
        .await
        .map_err(|_| "VMess write timeout".to_string())?
        .map_err(|error| format!("VMess write: {error}"))?;
    let mut response = vec![0_u8; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| "VMess read timeout".to_string())?
        .map_err(|error| format!("VMess read: {error}"))?;
    if response != payload {
        return Err("VMess echo payload mismatch".to_string());
    }
    Ok(())
}

async fn connect_tcp(addr: SocketAddr, label: &str) -> TcpStream {
    tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_| panic!("{label} TCP connect timeout"))
        .unwrap_or_else(|error| panic!("{label} TCP connect failed: {error}"))
}

type NegotiatedTls = (Option<Vec<u8>>, rustls::ProtocolVersion);

async fn run_tls_pair(
    server_config: &StandardTlsConfig,
    client_config: &StandardTlsConfig,
) -> (Result<NegotiatedTls, String>, Result<NegotiatedTls, String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TLS inspection listener");
    let addr = listener.local_addr().expect("TLS inspection address");
    let acceptor = sb_transport::build_standard_tls_acceptor(server_config)
        .expect("build TLS inspection server");
    let server_task = tokio::spawn(async move {
        let (tcp, _) = tokio::time::timeout(IO_TIMEOUT, listener.accept())
            .await
            .map_err(|_| "inspection server accept timeout".to_string())?
            .map_err(|error| format!("inspection server accept: {error}"))?;
        let mut tls = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(tcp))
            .await
            .map_err(|_| "inspection server TLS timeout".to_string())?
            .map_err(|error| format!("inspection server TLS handshake: {error}"))?;
        let connection = &tls.get_ref().1;
        let negotiated = (
            connection.alpn_protocol().map(ToOwned::to_owned),
            connection
                .protocol_version()
                .ok_or_else(|| "inspection server TLS version missing".to_string())?,
        );
        // Both halves issue close_notify concurrently. One side may observe an
        // OS broken pipe after the peer has already completed its close.
        let _ = tokio::time::timeout(IO_TIMEOUT, tls.shutdown()).await;
        Ok(negotiated)
    });

    let client = sb_transport::build_standard_client_config(client_config)
        .expect("build TLS inspection client");
    let connector = TlsConnector::from(client);
    let client_result = async {
        let tcp = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| "inspection TCP timeout".to_string())?
            .map_err(|error| format!("inspection TCP: {error}"))?;
        let name = ServerName::try_from(
            client_config
                .server_name
                .clone()
                .unwrap_or_else(|| "localhost".to_string()),
        )
        .map_err(|error| format!("inspection server name: {error}"))?;
        let mut tls = tokio::time::timeout(IO_TIMEOUT, connector.connect(name, tcp))
            .await
            .map_err(|_| "inspection TLS timeout".to_string())?
            .map_err(|error| format!("inspection TLS handshake: {error}"))?;
        let connection = &tls.get_ref().1;
        let negotiated = (
            connection.alpn_protocol().map(ToOwned::to_owned),
            connection
                .protocol_version()
                .ok_or_else(|| "inspection TLS version missing".to_string())?,
        );
        let _ = tokio::time::timeout(IO_TIMEOUT, tls.shutdown()).await;
        Ok(negotiated)
    }
    .await;
    let server_result = tokio::time::timeout(IO_TIMEOUT, server_task)
        .await
        .map_err(|_| "inspection server task timeout".to_string())
        .and_then(|result| result.map_err(|error| format!("inspection server task: {error}")))
        .and_then(|result| result);
    (client_result, server_result)
}

async fn inspect_tls_pair(
    server_config: &StandardTlsConfig,
    client_config: &StandardTlsConfig,
) -> Result<NegotiatedTls, String> {
    let (client, server) = run_tls_pair(server_config, client_config).await;
    let client = client?;
    let server = server?;
    if client != server {
        return Err(format!(
            "inspection negotiation differs: client={client:?}, server={server:?}"
        ));
    }
    Ok(client)
}

async fn inspect_tls_pair_error(
    server_config: &StandardTlsConfig,
    client_config: &StandardTlsConfig,
) -> String {
    let (client, _server) = run_tls_pair(server_config, client_config).await;
    match client {
        Ok(negotiated) => panic!("invalid TLS pair unexpectedly negotiated {negotiated:?}"),
        Err(error) => error,
    }
}

async fn assert_tcp_closed(mut stream: TcpStream, payload: &[u8], label: &str) {
    if !payload.is_empty() {
        tokio::time::timeout(IO_TIMEOUT, stream.write_all(payload))
            .await
            .unwrap_or_else(|_| panic!("{label} write timeout"))
            .unwrap_or_else(|error| panic!("{label} write failed before assertion: {error}"));
    }
    let bytes = tokio::time::timeout(Duration::from_secs(3), async {
        let mut received = Vec::new();
        let mut buffer = [0_u8; 64];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break received,
                Ok(read) => {
                    received.extend_from_slice(&buffer[..read]);
                    assert!(received.len() <= 256, "{label} returned excessive data");
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} connection was not closed within timeout"));
    if !bytes.is_empty() {
        assert_eq!(
            bytes[0], 0x15,
            "{label} may return only a TLS alert, never VMess application data"
        );
    }
}

fn assert_tls_error(error: &str, label: &str) {
    let lower = error.to_ascii_lowercase();
    assert!(
        ["tls", "certificate", "handshake", "protocol"]
            .iter()
            .any(|class| lower.contains(class)),
        "{label} must be TLS-classified: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_standard_tls() {
    let certificate = certificate_set(CertificateValidity::Valid);
    let echo = EchoServer::start().await;
    let uuid = Uuid::new_v4();
    let server_config = server_tls(&certificate, &["h2"], TlsVersion::V1_3, TlsVersion::V1_3);
    let client_config = client_tls(
        certificate.ca_pem,
        "localhost",
        &["h2"],
        TlsVersion::V1_3,
        TlsVersion::V1_3,
    );
    let (alpn, version) = inspect_tls_pair(&server_config, &client_config)
        .await
        .expect("inspect standard TLS");
    assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    let server = VmessServer::start(uuid, Some(server_config), false, HANDSHAKE_TIMEOUT)
        .await
        .expect("start standard TLS server");
    let client = connector(server.addr, uuid, Some(client_config), false)
        .expect("build standard TLS connector");
    echo_over_vmess(&client, echo.addr, b"verified VMess standard TLS")
        .await
        .expect("standard TLS echo");
    drop(client);
    server.shutdown().await;
    echo.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_with_alpn() {
    for alpn in [["h2"].as_slice(), ["http/1.1"].as_slice()] {
        let certificate = certificate_set(CertificateValidity::Valid);
        let echo = EchoServer::start().await;
        let uuid = Uuid::new_v4();
        let server_config = server_tls(&certificate, alpn, TlsVersion::V1_3, TlsVersion::V1_3);
        let client_config = client_tls(
            certificate.ca_pem,
            "localhost",
            alpn,
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        );
        let (negotiated, _) = inspect_tls_pair(&server_config, &client_config)
            .await
            .expect("inspect ALPN");
        assert_eq!(negotiated.as_deref(), Some(alpn[0].as_bytes()));
        let server = VmessServer::start(uuid, Some(server_config), false, HANDSHAKE_TIMEOUT)
            .await
            .expect("start ALPN server");
        let client =
            connector(server.addr, uuid, Some(client_config), false).expect("build ALPN connector");
        echo_over_vmess(&client, echo.addr, alpn[0].as_bytes())
            .await
            .expect("ALPN echo");
        drop(client);
        server.shutdown().await;
        echo.shutdown().await;
    }

    // Go crypto/tls and rustls both reject a non-empty ALPN offer when the
    // server has a non-empty list and no protocol overlaps.
    let certificate = certificate_set(CertificateValidity::Valid);
    let uuid = Uuid::new_v4();
    let server_config = server_tls(&certificate, &["h2"], TlsVersion::V1_3, TlsVersion::V1_3);
    let client_config = client_tls(
        certificate.ca_pem,
        "localhost",
        &["http/1.1"],
        TlsVersion::V1_3,
        TlsVersion::V1_3,
    );
    let inspection_error = inspect_tls_pair_error(&server_config, &client_config).await;
    assert!(
        inspection_error
            .to_ascii_lowercase()
            .contains("applicationprotocol"),
        "ALPN mismatch must report no application protocol: {inspection_error}"
    );
    let server = VmessServer::start(uuid, Some(server_config), false, HANDSHAKE_TIMEOUT)
        .await
        .expect("start ALPN mismatch server");
    let client = connector(server.addr, uuid, Some(client_config), false)
        .expect("build ALPN mismatch connector");
    let error = echo_over_vmess(&client, "127.0.0.1:9".parse().unwrap(), b"must fail")
        .await
        .expect_err("ALPN mismatch must fail");
    assert_tls_error(&error, "ALPN mismatch");
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_versions() {
    let cases = [
        (
            TlsVersion::V1_2,
            TlsVersion::V1_2,
            rustls::ProtocolVersion::TLSv1_2,
        ),
        (
            TlsVersion::V1_2,
            TlsVersion::V1_3,
            rustls::ProtocolVersion::TLSv1_3,
        ),
        (
            TlsVersion::V1_3,
            TlsVersion::V1_3,
            rustls::ProtocolVersion::TLSv1_3,
        ),
    ];
    for (min_version, max_version, expected) in cases {
        let certificate = certificate_set(CertificateValidity::Valid);
        let echo = EchoServer::start().await;
        let uuid = Uuid::new_v4();
        let server_config = server_tls(&certificate, &["h2"], min_version, max_version);
        let client_config = client_tls(
            certificate.ca_pem,
            "localhost",
            &["h2"],
            min_version,
            max_version,
        );
        let (_, negotiated) = inspect_tls_pair(&server_config, &client_config)
            .await
            .expect("inspect TLS version");
        assert_eq!(negotiated, expected);
        let server = VmessServer::start(uuid, Some(server_config), false, HANDSHAKE_TIMEOUT)
            .await
            .expect("start TLS version server");
        let client = connector(server.addr, uuid, Some(client_config), false)
            .expect("build TLS version connector");
        echo_over_vmess(&client, echo.addr, format!("{expected:?}").as_bytes())
            .await
            .expect("TLS version echo");
        drop(client);
        server.shutdown().await;
        echo.shutdown().await;
    }

    let certificate = certificate_set(CertificateValidity::Valid);
    let uuid = Uuid::new_v4();
    let server_config = server_tls(&certificate, &["h2"], TlsVersion::V1_2, TlsVersion::V1_2);
    let client_config = client_tls(
        certificate.ca_pem,
        "localhost",
        &["h2"],
        TlsVersion::V1_3,
        TlsVersion::V1_3,
    );
    let inspection_error = inspect_tls_pair_error(&server_config, &client_config).await;
    assert_tls_error(&inspection_error, "TLS version inspection mismatch");
    let server = VmessServer::start(uuid, Some(server_config), false, HANDSHAKE_TIMEOUT)
        .await
        .expect("start TLS 1.2-only server");
    let client = connector(server.addr, uuid, Some(client_config), false)
        .expect("build TLS 1.3-only client");
    let error = echo_over_vmess(&client, "127.0.0.1:9".parse().unwrap(), b"must fail")
        .await
        .expect_err("TLS version without overlap must fail");
    assert_tls_error(&error, "TLS version mismatch");
    drop(client);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_with_multiplex() {
    let certificate = certificate_set(CertificateValidity::Valid);
    let echo = EchoServer::start().await;
    let uuid = Uuid::new_v4();
    let server = VmessServer::start(
        uuid,
        Some(server_tls(
            &certificate,
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        true,
        HANDSHAKE_TIMEOUT,
    )
    .await
    .expect("start TLS multiplex server");
    let client = Arc::new(
        connector(
            server.addr,
            uuid,
            Some(client_tls(
                certificate.ca_pem,
                "localhost",
                &["h2"],
                TlsVersion::V1_3,
                TlsVersion::V1_3,
            )),
            true,
        )
        .expect("build TLS multiplex connector"),
    );

    let mut tasks = JoinSet::new();
    for fill in [0x11_u8, 0x22, 0x33, 0x44] {
        let client = client.clone();
        let target = echo.addr;
        tasks.spawn(
            async move { echo_over_vmess(&client, target, &vec![fill; 12 * 1024 + 37]).await },
        );
    }
    while let Some(result) = tokio::time::timeout(IO_TIMEOUT, tasks.join_next())
        .await
        .expect("multiplex task timeout")
    {
        result
            .expect("multiplex task join")
            .expect("multiplex stream echo");
    }
    drop(client);
    server.shutdown().await;
    echo.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_data_integrity() {
    let certificate = certificate_set(CertificateValidity::Valid);
    let echo = EchoServer::start().await;
    let uuid = Uuid::new_v4();
    let server = VmessServer::start(
        uuid,
        Some(server_tls(
            &certificate,
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
        HANDSHAKE_TIMEOUT,
    )
    .await
    .expect("start integrity server");
    let client = connector(
        server.addr,
        uuid,
        Some(client_tls(
            certificate.ca_pem,
            "localhost",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
    )
    .expect("build integrity connector");
    for (index, size) in [1_usize, 16 * 1024 + 3, 32 * 1024 + 97]
        .into_iter()
        .enumerate()
    {
        let payload: Vec<u8> = (0..size)
            .map(|offset| ((offset * 31 + index * 17) & 0xff) as u8)
            .collect();
        echo_over_vmess(&client, echo.addr, &payload)
            .await
            .expect("integrity echo");
    }
    drop(client);
    server.shutdown().await;
    echo.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_verification_and_auth_negatives() {
    let certificate = certificate_set(CertificateValidity::Valid);
    let untrusted = certificate_set(CertificateValidity::Valid);
    let echo = EchoServer::start().await;
    let uuid = Uuid::new_v4();
    let server = VmessServer::start(
        uuid,
        Some(server_tls(
            &certificate,
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
        HANDSHAKE_TIMEOUT,
    )
    .await
    .expect("start verification server");

    let wrong_ca = connector(
        server.addr,
        uuid,
        Some(client_tls(
            untrusted.ca_pem,
            "localhost",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
    )
    .expect("build untrusted-CA connector");
    let error = echo_over_vmess(&wrong_ca, echo.addr, b"must fail")
        .await
        .expect_err("untrusted CA must fail");
    assert_tls_error(&error, "untrusted CA");

    let wrong_name = connector(
        server.addr,
        uuid,
        Some(client_tls(
            certificate.ca_pem.clone(),
            "wrong.invalid",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
    )
    .expect("build wrong-name connector");
    let error = echo_over_vmess(&wrong_name, echo.addr, b"must fail")
        .await
        .expect_err("wrong server name must fail");
    assert_tls_error(&error, "wrong server name");

    let wrong_uuid = connector(
        server.addr,
        Uuid::new_v4(),
        Some(client_tls(
            certificate.ca_pem,
            "localhost",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
    )
    .expect("build wrong-UUID connector");
    echo_over_vmess(&wrong_uuid, echo.addr, b"must fail")
        .await
        .expect_err("wrong UUID after TLS must not echo");

    drop(wrong_ca);
    drop(wrong_name);
    drop(wrong_uuid);
    server.shutdown().await;
    echo.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_certificate_validity_negatives() {
    for (validity, expected) in [
        (CertificateValidity::Expired, "expired"),
        (CertificateValidity::NotYetValid, "not valid"),
    ] {
        let certificate = certificate_set(validity);
        let echo = EchoServer::start().await;
        let uuid = Uuid::new_v4();
        let server_config = server_tls(&certificate, &["h2"], TlsVersion::V1_3, TlsVersion::V1_3);
        let client_config = client_tls(
            certificate.ca_pem,
            "localhost",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        );
        let inspection_error = inspect_tls_pair_error(&server_config, &client_config).await;
        assert!(
            inspection_error.to_ascii_lowercase().contains(expected),
            "certificate-validity inspection missing {expected}: {inspection_error}"
        );
        let server = VmessServer::start(uuid, Some(server_config), false, HANDSHAKE_TIMEOUT)
            .await
            .expect("start certificate-validity server");
        let client = connector(server.addr, uuid, Some(client_config), false)
            .expect("build certificate-validity connector");
        let error = echo_over_vmess(&client, echo.addr, b"must fail")
            .await
            .expect_err("invalid certificate validity must fail");
        assert_tls_error(&error, "certificate validity");
        drop(client);
        server.shutdown().await;
        echo.shutdown().await;
    }
}

#[test]
fn test_vmess_tls_invalid_server_material_fails_before_bind() {
    let missing_key = StandardTlsConfig {
        cert_pem: Some("not a certificate".to_string()),
        ..Default::default()
    };
    let error = match sb_transport::build_standard_tls_acceptor(&missing_key) {
        Ok(_) => panic!("missing key must fail"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("private key"),
        "missing-key error must be specific: {error}"
    );

    let malformed = StandardTlsConfig {
        cert_pem: Some(
            "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----".to_string(),
        ),
        key_pem: Some(
            "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----".to_string(),
        ),
        ..Default::default()
    };
    let error = match sb_transport::build_standard_tls_acceptor(&malformed) {
        Ok(_) => panic!("malformed PEM must fail"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("certificate") || error.contains("private key"),
        "malformed-PEM error must be specific: {error}"
    );
    assert!(
        !error.contains("invalid\n"),
        "malformed PEM content must not appear in error"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_vmess_tls_protocol_mismatch_and_handshake_lifecycle() {
    let certificate = certificate_set(CertificateValidity::Valid);
    let echo = EchoServer::start().await;
    let uuid = Uuid::new_v4();
    let server = VmessServer::start(
        uuid,
        Some(server_tls(
            &certificate,
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
        Duration::from_millis(150),
    )
    .await
    .expect("start handshake-lifecycle server");

    let plain = connect_tcp(server.addr, "plain-to-TLS").await;
    assert_tcp_closed(plain, b"plain VMess must not pass TLS", "plain-to-TLS").await;

    let stalled = connect_tcp(server.addr, "stalled TLS").await;
    assert_tcp_closed(stalled, &[], "TLS handshake timeout").await;

    let mut partial = connect_tcp(server.addr, "partial TLS").await;
    tokio::time::timeout(
        IO_TIMEOUT,
        partial.write_all(&[0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00]),
    )
    .await
    .expect("partial TLS write timeout")
    .expect("write partial TLS record");
    tokio::time::timeout(IO_TIMEOUT, partial.shutdown())
        .await
        .expect("partial TLS shutdown timeout")
        .expect("close during TLS handshake");
    drop(partial);

    let valid = connector(
        server.addr,
        uuid,
        Some(client_tls(
            certificate.ca_pem.clone(),
            "localhost",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
    )
    .expect("build recovery connector");
    echo_over_vmess(&valid, echo.addr, b"server survives bad TLS clients")
        .await
        .expect("valid TLS after lifecycle negatives");
    drop(valid);
    server.shutdown().await;

    let plain_server = VmessServer::start(uuid, None, false, HANDSHAKE_TIMEOUT)
        .await
        .expect("start plain VMess server");
    let tls_to_plain = connector(
        plain_server.addr,
        uuid,
        Some(client_tls(
            certificate.ca_pem,
            "localhost",
            &["h2"],
            TlsVersion::V1_3,
            TlsVersion::V1_3,
        )),
        false,
    )
    .expect("build TLS-to-plain connector");
    let error = echo_over_vmess(&tls_to_plain, echo.addr, b"must fail")
        .await
        .expect_err("TLS client to plain VMess server must fail");
    assert_tls_error(&error, "TLS-to-plain");
    drop(tls_to_plain);
    plain_server.shutdown().await;
    echo.shutdown().await;
}
