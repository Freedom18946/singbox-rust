#![cfg(feature = "net_e2e")]

use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use sb_adapters::outbound::vmess::{
    Security, VmessAuth, VmessConfig, VmessConnector, VmessTransport,
};
use sb_adapters::transport_config::{
    HttpUpgradeTransportConfig, TransportConfig, WebSocketTransportConfig,
};
use sb_transport::{StandardTlsConfig, TlsConfig, TlsVersion};
use sb_types::{Session, TargetAddr};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

const IO_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy)]
enum TestTransport {
    WebSocket {
        path: &'static str,
        host: &'static str,
    },
    HttpUpgrade {
        path: &'static str,
        host: &'static str,
    },
}

impl TestTransport {
    fn go_json(self) -> serde_json::Value {
        match self {
            Self::WebSocket { path, host } => serde_json::json!({
                "type": "ws",
                "path": path,
                "headers": {"Host": host}
            }),
            Self::HttpUpgrade { path, host } => serde_json::json!({
                "type": "httpupgrade",
                "path": path,
                "host": host
            }),
        }
    }

    fn rust_config(self) -> TransportConfig {
        match self {
            Self::WebSocket { path, host } => {
                TransportConfig::WebSocket(WebSocketTransportConfig {
                    path: path.to_string(),
                    headers: vec![("Host".to_string(), host.to_string())],
                    ..Default::default()
                })
            }
            Self::HttpUpgrade { path, host } => {
                TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
                    path: path.to_string(),
                    host: Some(host.to_string()),
                    headers: Vec::new(),
                })
            }
        }
    }
}

struct GoServer {
    child: Child,
    log_path: PathBuf,
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct EchoServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn go_binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../go_fork_source/sing-box-1.13.13/sing-box")
}

async fn unused_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve loopback address");
    listener.local_addr().expect("loopback address")
}

async fn start_echo_server() -> EchoServer {
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
                    if read == 0 {
                        break;
                    }
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    EchoServer { addr, task }
}

fn generate_local_ca(temp: &TempDir) -> (String, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = Certificate::from_params(ca_params).expect("generate local CA");

    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]);
    let leaf = Certificate::from_params(leaf_params).expect("generate localhost leaf");
    let ca_pem = ca.serialize_pem().expect("serialize local CA");
    let cert_path = temp.path().join("server.pem");
    let key_path = temp.path().join("server.key");
    std::fs::write(
        &cert_path,
        leaf.serialize_pem_with_signer(&ca)
            .expect("sign localhost leaf"),
    )
    .expect("write server certificate");
    std::fs::write(&key_path, leaf.serialize_private_key_pem()).expect("write server key");
    (ca_pem, cert_path, key_path)
}

async fn start_go_server(
    temp: &TempDir,
    listen: SocketAddr,
    uuid: Uuid,
    cert_path: &Path,
    key_path: &Path,
    min_version: &str,
    max_version: &str,
) -> GoServer {
    start_go_server_with_transport(
        temp,
        listen,
        uuid,
        cert_path,
        key_path,
        min_version,
        max_version,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_go_server_with_transport(
    temp: &TempDir,
    listen: SocketAddr,
    uuid: Uuid,
    cert_path: &Path,
    key_path: &Path,
    min_version: &str,
    max_version: &str,
    transport: Option<TestTransport>,
) -> GoServer {
    start_go_server_config(
        temp,
        listen,
        uuid,
        Some((cert_path, key_path, min_version, max_version)),
        transport,
    )
    .await
}

async fn start_go_plain_server_with_transport(
    temp: &TempDir,
    listen: SocketAddr,
    uuid: Uuid,
    transport: TestTransport,
) -> GoServer {
    start_go_server_config(temp, listen, uuid, None, Some(transport)).await
}

async fn start_go_server_config(
    temp: &TempDir,
    listen: SocketAddr,
    uuid: Uuid,
    tls: Option<(&Path, &Path, &str, &str)>,
    transport: Option<TestTransport>,
) -> GoServer {
    let config_path = temp.path().join("go-server.json");
    let log_path = temp.path().join("go-server.log");
    let alpn = if transport.is_some() {
        "http/1.1"
    } else {
        "h2"
    };
    let mut inbound = serde_json::json!({
        "type": "vmess",
        "tag": "vmess-tls",
        "listen": listen.ip().to_string(),
        "listen_port": listen.port(),
        "users": [{"name": "acceptance", "uuid": uuid.to_string()}]
    });
    if let Some((cert_path, key_path, min_version, max_version)) = tls {
        inbound.as_object_mut().expect("Go inbound object").insert(
            "tls".to_string(),
            serde_json::json!({
                "enabled": true,
                "server_name": "localhost",
                "alpn": [alpn],
                "min_version": min_version,
                "max_version": max_version,
                "certificate_path": cert_path,
                "key_path": key_path
            }),
        );
    }
    if let Some(transport) = transport {
        inbound
            .as_object_mut()
            .expect("Go inbound object")
            .insert("transport".to_string(), transport.go_json());
    }
    let config = serde_json::json!({
        "log": {"level": "debug", "timestamp": false},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize Go config"),
    )
    .expect("write Go config");

    let stdout = File::create(&log_path).expect("create Go log");
    let stderr = stdout.try_clone().expect("clone Go log");
    let child = Command::new(go_binary())
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn Go sing-box 1.13.13");
    let mut server = GoServer { child, log_path };

    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(status) = server.child.try_wait().expect("poll Go server") {
                let log = std::fs::read_to_string(&server.log_path).unwrap_or_default();
                panic!("Go server exited before readiness ({status}): {log}");
            }
            if TcpStream::connect(listen).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Go server readiness timeout");
    server
}

fn connector(
    server: SocketAddr,
    uuid: Uuid,
    security: Security,
    server_name: &str,
    ca_pem: Option<String>,
    insecure: bool,
    min_version: TlsVersion,
    max_version: TlsVersion,
) -> VmessConnector {
    connector_with_transport(
        server,
        uuid,
        security,
        server_name,
        ca_pem,
        insecure,
        min_version,
        max_version,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn connector_with_transport(
    server: SocketAddr,
    uuid: Uuid,
    security: Security,
    server_name: &str,
    ca_pem: Option<String>,
    insecure: bool,
    min_version: TlsVersion,
    max_version: TlsVersion,
    transport: Option<TestTransport>,
) -> VmessConnector {
    let alpn = if transport.is_some() {
        "http/1.1"
    } else {
        "h2"
    };
    VmessConnector::new(VmessConfig {
        server: server.ip().to_string(),
        port: server.port(),
        auth: VmessAuth {
            uuid,
            alter_id: 0,
            security,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: transport
            .map(TestTransport::rust_config)
            .unwrap_or(TransportConfig::Tcp),
        timeout: Some(IO_TIMEOUT),
        tls: Some(TlsConfig::Standard(StandardTlsConfig {
            server_name: Some(server_name.to_string()),
            alpn: vec![alpn.to_string()],
            insecure,
            min_version: Some(min_version),
            max_version: Some(max_version),
            ca_pem: ca_pem.into_iter().collect(),
            ..Default::default()
        })),
        ..Default::default()
    })
}

fn plain_connector_with_transport(
    server: SocketAddr,
    uuid: Uuid,
    transport: TestTransport,
) -> VmessConnector {
    VmessConnector::new(VmessConfig {
        server: server.ip().to_string(),
        port: server.port(),
        auth: VmessAuth {
            uuid,
            alter_id: 0,
            security: Security::Auto,
            additional_data: None,
        },
        transport: VmessTransport::default(),
        transport_layer: transport.rust_config(),
        timeout: Some(IO_TIMEOUT),
        tls: None,
        ..Default::default()
    })
}

async fn assert_echo(
    connector: &VmessConnector,
    target: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let target = TargetAddr::from_host_port(target.ip().to_string(), target.port());
    let mut stream = tokio::time::timeout(IO_TIMEOUT, connector.dial(&Session::outbound(target)))
        .await
        .map_err(|_| "VMess dial timeout".to_string())?
        .map_err(|error| error.to_string())?;
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(payload))
        .await
        .map_err(|_| "VMess write timeout".to_string())?
        .map_err(|error| error.to_string())?;
    let mut response = vec![0_u8; payload.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| "VMess read timeout".to_string())?
        .map_err(|error| error.to_string())?;
    if response != payload {
        return Err("VMess echo payload mismatch".to_string());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_outbound_to_go_tls13_verified_ca_auto_zero_multi_connection() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_pem, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let listen = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let _go = start_go_server(&temp, listen, uuid, &cert_path, &key_path, "1.3", "1.3").await;
    let client = connector(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        Some(ca_pem),
        false,
        TlsVersion::V1_3,
        TlsVersion::V1_3,
    );
    let payload = vec![0x5a; 32 * 1024 + 97];

    for _ in 0..3 {
        assert_echo(&client, echo.addr, &payload)
            .await
            .expect("verified TLS 1.3 VMess echo");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_outbound_to_go_tls12_explicit_aes_and_verification_negatives() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_pem, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let listen = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let _go = start_go_server(&temp, listen, uuid, &cert_path, &key_path, "1.2", "1.2").await;

    let verified = connector(
        listen,
        uuid,
        Security::Aes128Gcm,
        "localhost",
        Some(ca_pem.clone()),
        false,
        TlsVersion::V1_2,
        TlsVersion::V1_2,
    );
    assert_echo(&verified, echo.addr, b"TLS 1.2 explicit AES")
        .await
        .expect("verified TLS 1.2 VMess echo");

    let wrong_sni = connector(
        listen,
        uuid,
        Security::Auto,
        "wrong.example",
        Some(ca_pem),
        false,
        TlsVersion::V1_2,
        TlsVersion::V1_2,
    );
    let error = assert_echo(&wrong_sni, echo.addr, b"must fail")
        .await
        .expect_err("wrong SNI must fail");
    assert!(
        error.contains("certificate") || error.contains("Tls") || error.contains("tls"),
        "wrong-SNI failure must be TLS-classified: {error}"
    );

    let untrusted = connector(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        None,
        false,
        TlsVersion::V1_2,
        TlsVersion::V1_2,
    );
    let error = assert_echo(&untrusted, echo.addr, b"must fail")
        .await
        .expect_err("untrusted CA must fail");
    assert!(
        error.contains("certificate") || error.contains("Tls") || error.contains("tls"),
        "untrusted-CA failure must be TLS-classified: {error}"
    );

    let insecure = connector(
        listen,
        uuid,
        Security::Zero,
        "wrong.example",
        None,
        true,
        TlsVersion::V1_2,
        TlsVersion::V1_2,
    );
    assert_echo(&insecure, echo.addr, b"insecure explicit zero")
        .await
        .expect("insecure VMess TLS must connect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_outbound_rejects_tls_version_without_overlap() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_pem, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let listen = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let _go = start_go_server(&temp, listen, uuid, &cert_path, &key_path, "1.3", "1.3").await;
    let client = connector(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        Some(ca_pem),
        false,
        TlsVersion::V1_2,
        TlsVersion::V1_2,
    );

    let error = assert_echo(&client, echo.addr, b"must fail")
        .await
        .expect_err("TLS version mismatch must fail");
    assert!(
        error.contains("Tls") || error.contains("tls") || error.contains("protocol"),
        "version failure must be TLS-classified: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_outbound_to_go_plain_v2ray_transports() {
    let echo = start_echo_server().await;
    let cases = [
        TestTransport::WebSocket {
            path: "/plain-ws",
            host: "ws.plain.test",
        },
        TestTransport::HttpUpgrade {
            path: "/plain-upgrade",
            host: "http.plain.test",
        },
    ];

    for transport in cases {
        let temp = TempDir::new().expect("temp dir");
        let listen = unused_loopback_addr().await;
        let uuid = Uuid::new_v4();
        let _go = start_go_plain_server_with_transport(&temp, listen, uuid, transport).await;
        let client = plain_connector_with_transport(listen, uuid, transport);
        assert_echo(&client, echo.addr, &vec![0x35; 20 * 1024 + 13])
            .await
            .expect("Rust plain V2Ray transport outbound -> Go echo");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_outbound_to_go_websocket_tls_with_distinct_host_and_sni() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_pem, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let listen = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let transport = TestTransport::WebSocket {
        path: "/vmess-ws",
        host: "ws.virtual.test",
    };
    let _go = start_go_server_with_transport(
        &temp,
        listen,
        uuid,
        &cert_path,
        &key_path,
        "1.3",
        "1.3",
        Some(transport),
    )
    .await;
    let client = connector_with_transport(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        Some(ca_pem.clone()),
        false,
        TlsVersion::V1_3,
        TlsVersion::V1_3,
        Some(transport),
    );
    let payload = vec![0x57; 24 * 1024 + 73];
    for _ in 0..3 {
        assert_echo(&client, echo.addr, &payload)
            .await
            .expect("Rust WS+TLS outbound -> Go echo");
    }

    let wrong_path = connector_with_transport(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        Some(ca_pem),
        false,
        TlsVersion::V1_3,
        TlsVersion::V1_3,
        Some(TestTransport::WebSocket {
            path: "/wrong",
            host: "ws.virtual.test",
        }),
    );
    let error = assert_echo(&wrong_path, echo.addr, b"must fail")
        .await
        .expect_err("wrong WebSocket path must fail");
    assert!(
        error.contains("WebSocket") || error.contains("HTTP error"),
        "wrong-path failure must be transport-classified: {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_outbound_to_go_httpupgrade_tls() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_pem, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let listen = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let transport = TestTransport::HttpUpgrade {
        path: "/vmess-upgrade",
        host: "http.virtual.test",
    };
    let _go = start_go_server_with_transport(
        &temp,
        listen,
        uuid,
        &cert_path,
        &key_path,
        "1.3",
        "1.3",
        Some(transport),
    )
    .await;
    let client = connector_with_transport(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        Some(ca_pem.clone()),
        false,
        TlsVersion::V1_3,
        TlsVersion::V1_3,
        Some(transport),
    );
    assert_echo(&client, echo.addr, &vec![0x48; 20 * 1024 + 19])
        .await
        .expect("Rust HTTPUpgrade+TLS outbound -> Go echo");

    let wrong_host = connector_with_transport(
        listen,
        uuid,
        Security::Auto,
        "localhost",
        Some(ca_pem),
        false,
        TlsVersion::V1_3,
        TlsVersion::V1_3,
        Some(TestTransport::HttpUpgrade {
            path: "/vmess-upgrade",
            host: "wrong.virtual.test",
        }),
    );
    let error = assert_echo(&wrong_host, echo.addr, b"must fail")
        .await
        .expect_err("wrong HTTPUpgrade Host must fail");
    assert!(
        error.contains("upgrade") || error.contains("400"),
        "wrong-host failure must be transport-classified: {error}"
    );
}
