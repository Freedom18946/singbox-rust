#![cfg(feature = "net_e2e")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
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
use tokio::task::JoinHandle;
use uuid::Uuid;

const IO_TIMEOUT: Duration = Duration::from_secs(8);

struct BackgroundTask(JoinHandle<()>);

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct VmessServer {
    stop: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<anyhow::Result<()>>>,
}

impl VmessServer {
    async fn shutdown(mut self) {
        self.stop
            .take()
            .expect("VMess stop sender")
            .send(())
            .await
            .expect("VMess stop signal");
        tokio::time::timeout(IO_TIMEOUT, self.task.take().expect("VMess server task"))
            .await
            .expect("VMess TLS mux shutdown timeout")
            .expect("VMess TLS mux server task")
            .expect("VMess TLS mux server result");
    }
}

impl Drop for VmessServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn start_vmess_server(config: VmessInboundConfig) -> VmessServer {
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(sb_adapters::inbound::vmess::serve_with_ready(
        config, stop_rx, ready_tx,
    ));
    tokio::time::timeout(IO_TIMEOUT, ready_rx)
        .await
        .expect("VMess TLS mux readiness timeout")
        .expect("VMess TLS mux readiness sender")
        .expect("VMess TLS mux startup");
    VmessServer {
        stop: Some(stop_tx),
        task: Some(task),
    }
}

async fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve loopback address");
    listener.local_addr().expect("loopback address")
}

async fn start_echo_server() -> (SocketAddr, BackgroundTask) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo address");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 8192];
                loop {
                    let Ok(read) = stream.read(&mut buffer).await else {
                        break;
                    };
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, BackgroundTask(task))
}

async fn start_counting_proxy(
    upstream: SocketAddr,
) -> (SocketAddr, Arc<AtomicUsize>, BackgroundTask) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting proxy");
    let addr = listener.local_addr().expect("proxy address");
    let connections = Arc::new(AtomicUsize::new(0));
    let task_connections = connections.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                break;
            };
            task_connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(mut outbound) = TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    (addr, connections, BackgroundTask(task))
}

fn local_ca() -> (String, String, String) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = Certificate::from_params(ca_params).expect("generate local CA");
    let leaf = Certificate::from_params(CertificateParams::new(vec!["localhost".to_string()]))
        .expect("generate localhost certificate");
    (
        ca.serialize_pem().expect("serialize local CA"),
        leaf.serialize_pem_with_signer(&ca)
            .expect("sign localhost certificate"),
        leaf.serialize_private_key_pem(),
    )
}

async fn echo_once(
    connector: &VmessConnector,
    target: SocketAddr,
    payload: Vec<u8>,
) -> sb_adapters::outbound::BoxedStream {
    let target = TargetAddr::from_host_port(target.ip().to_string(), target.port());
    let mut stream = tokio::time::timeout(IO_TIMEOUT, connector.dial(&Session::outbound(target)))
        .await
        .expect("VMess mux dial timeout")
        .expect("VMess mux dial");
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&payload))
        .await
        .expect("VMess mux write timeout")
        .expect("VMess mux write");
    let mut response = vec![0_u8; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut response))
        .await
        .expect("VMess mux read timeout")
        .expect("VMess mux read");
    assert_eq!(response, payload);
    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_handshake_wraps_one_physical_yamux_connection() {
    let (ca_pem, cert_pem, key_pem) = local_ca();
    let (echo_addr, _echo_task) = start_echo_server().await;
    let vmess_addr = reserve_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let tls = TlsConfig::Standard(StandardTlsConfig {
        alpn: vec!["h2".to_string()],
        cert_pem: Some(cert_pem),
        key_pem: Some(key_pem),
        min_version: Some(TlsVersion::V1_3),
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    });
    let acceptor = match &tls {
        TlsConfig::Standard(config) => {
            sb_transport::build_standard_tls_acceptor(config).expect("build TLS acceptor")
        }
        #[allow(unreachable_patterns)]
        _ => panic!("test requires standard TLS"),
    };
    let server = start_vmess_server(VmessInboundConfig {
        listen: vmess_addr,
        uuid,
        security: "auto".to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        tag: Some("vmess-tls-mux".to_string()),
        stats: None,
        conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
        multiplex: Some(MultiplexServerConfig::default()),
        transport_layer: Some(TransportConfig::Tcp),
        fallback: None,
        fallback_for_alpn: Default::default(),
        tls: Some(acceptor),
        tls_handshake_timeout: IO_TIMEOUT,
    })
    .await;

    let (proxy_addr, physical_connections, _proxy_task) = start_counting_proxy(vmess_addr).await;
    let connector = Arc::new(VmessConnector::new(VmessConfig {
        server: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
        auth: VmessAuth {
            uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::Tcp,
        timeout: Some(IO_TIMEOUT),
        multiplex: Some(MultiplexConfig::default()),
        tls: Some(TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h2".to_string()],
            ca_pem: vec![ca_pem.clone()],
            min_version: Some(TlsVersion::V1_3),
            max_version: Some(TlsVersion::V1_3),
            ..Default::default()
        })),
        ..Default::default()
    }));

    // Prime pool and keep first logical stream alive. Later VMess handshakes
    // must run inside new yamux substreams, not create new TLS connections.
    let first = echo_once(&connector, echo_addr, vec![0x11; 8 * 1024 + 3]).await;
    let mut tasks = Vec::new();
    for fill in [0x22_u8, 0x33, 0x44] {
        let connector = connector.clone();
        tasks.push(tokio::spawn(async move {
            echo_once(&connector, echo_addr, vec![fill; 12 * 1024 + 17]).await
        }));
    }
    for task in tasks {
        drop(
            tokio::time::timeout(IO_TIMEOUT, task)
                .await
                .expect("concurrent VMess substream timeout")
                .expect("concurrent VMess substream task"),
        );
    }

    assert_eq!(
        physical_connections.load(Ordering::SeqCst),
        1,
        "TLS must wrap one physical connection while VMess runs per yamux substream"
    );

    let plain_over_tls = VmessConnector::new(VmessConfig {
        server: proxy_addr.ip().to_string(),
        port: proxy_addr.port(),
        auth: VmessAuth {
            uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: TransportConfig::Tcp,
        timeout: Some(IO_TIMEOUT),
        multiplex: None,
        tls: Some(TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h2".to_string()],
            ca_pem: vec![ca_pem],
            min_version: Some(TlsVersion::V1_3),
            max_version: Some(TlsVersion::V1_3),
            ..Default::default()
        })),
        ..Default::default()
    });
    let target = TargetAddr::from_host_port(echo_addr.ip().to_string(), echo_addr.port());
    let non_mux_result =
        tokio::time::timeout(IO_TIMEOUT, plain_over_tls.dial(&Session::outbound(target)))
            .await
            .expect("non-mux dial setup timeout");
    if let Ok(mut stream) = non_mux_result {
        stream
            .write_all(b"must-not-echo")
            .await
            .expect("buffer non-mux VMess payload");
        let mut response = [0_u8; 13];
        let echoed =
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response)).await;
        assert!(
            !matches!(echoed, Ok(Ok(_))),
            "mux negotiation failure must not fall back to plain VMess"
        );
    }
    assert_eq!(
        physical_connections.load(Ordering::SeqCst),
        2,
        "failed non-mux attempt must use a distinct verified TLS connection"
    );

    drop(first);
    drop(connector);
    server.shutdown().await;
}
