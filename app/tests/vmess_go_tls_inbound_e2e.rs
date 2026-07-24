#![cfg(all(feature = "net_e2e", feature = "adapters"))]
#![cfg(unix)]

use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

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
    fn json(self) -> serde_json::Value {
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
}

struct ManagedChild {
    child: Child,
    log_path: PathBuf,
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl ManagedChild {
    async fn stop_gracefully(&mut self, label: &str) {
        let result = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) };
        assert_eq!(result, 0, "send SIGTERM to {label}");
        let status = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(status) = self.child.try_wait().expect("poll child shutdown") {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            let log = std::fs::read_to_string(&self.log_path).unwrap_or_default();
            panic!("{label} graceful shutdown timeout: {log}");
        });
        assert!(status.success(), "{label} shutdown status: {status}");
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

fn app_binary() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_app")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug/app")
                .to_path_buf()
        })
}

fn go_binary() -> PathBuf {
    std::env::var_os("INTEROP_GO_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../go_fork_source/sing-box-1.13.13/sing-box")
        })
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
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    EchoServer { addr, task }
}

fn generate_local_ca(temp: &TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = Certificate::from_params(ca_params).expect("generate local CA");
    let leaf = Certificate::from_params(CertificateParams::new(vec!["localhost".to_string()]))
        .expect("generate localhost leaf");

    let ca_path = temp.path().join("ca.pem");
    let cert_path = temp.path().join("server.pem");
    let key_path = temp.path().join("server.key");
    std::fs::write(&ca_path, ca.serialize_pem().expect("serialize CA")).expect("write CA");
    std::fs::write(
        &cert_path,
        leaf.serialize_pem_with_signer(&ca)
            .expect("sign localhost leaf"),
    )
    .expect("write server certificate");
    std::fs::write(&key_path, leaf.serialize_private_key_pem()).expect("write server key");
    (ca_path, cert_path, key_path)
}

async fn wait_for_listener(child: &mut ManagedChild, addr: SocketAddr, label: &str) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.child.try_wait().expect("poll child") {
                let log = std::fs::read_to_string(&child.log_path).unwrap_or_default();
                panic!("{label} exited before readiness ({status}): {log}");
            }
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        let log = std::fs::read_to_string(&child.log_path).unwrap_or_default();
        panic!("{label} readiness timeout: {log}");
    });
}

async fn start_rust_app(
    temp: &TempDir,
    listen: SocketAddr,
    uuid: Uuid,
    tls: Option<(&Path, &Path, &str)>,
) -> ManagedChild {
    start_rust_app_with_transport(temp, listen, uuid, tls, None).await
}

async fn start_rust_app_with_transport(
    temp: &TempDir,
    listen: SocketAddr,
    uuid: Uuid,
    tls: Option<(&Path, &Path, &str)>,
    transport: Option<TestTransport>,
) -> ManagedChild {
    let config_path = temp.path().join(format!("rust-{}.json", listen.port()));
    let log_path = temp.path().join(format!("rust-{}.log", listen.port()));
    let alpn = if transport.is_some() {
        "http/1.1"
    } else {
        "h2"
    };
    let tls = tls.map(|(certificate, key, version)| {
        serde_json::json!({
            "enabled": true,
            "server_name": "localhost",
            "alpn": [alpn],
            "min_version": version,
            "max_version": version,
            "certificate_path": certificate,
            "key_path": key
        })
    });
    let mut inbound = serde_json::json!({
        "type": "vmess",
        "tag": "vmess-in",
        "listen": listen.ip().to_string(),
        "listen_port": listen.port(),
        "uuid": uuid.to_string(),
        "security": "auto"
    });
    if let Some(tls) = tls {
        inbound
            .as_object_mut()
            .expect("inbound object")
            .insert("tls".to_string(), tls);
    }
    if let Some(transport) = transport {
        inbound
            .as_object_mut()
            .expect("inbound object")
            .insert("transport".to_string(), transport.json());
    }
    let config = serde_json::json!({
        "log": {"level": "debug", "timestamp": false},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize Rust config"),
    )
    .expect("write Rust config");

    let stdout = File::create(&log_path).expect("create Rust log");
    let stderr = stdout.try_clone().expect("clone Rust log");
    let child = Command::new(app_binary())
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn production Rust app");
    let mut child = ManagedChild { child, log_path };
    wait_for_listener(&mut child, listen, "Rust app").await;
    child
}

async fn start_go_client(
    temp: &TempDir,
    index: &str,
    socks: SocketAddr,
    server: SocketAddr,
    uuid: Uuid,
    tls: Option<(&Path, &str)>,
) -> ManagedChild {
    start_go_client_with_transport(temp, index, socks, server, uuid, tls, None).await
}

async fn start_go_client_with_transport(
    temp: &TempDir,
    index: &str,
    socks: SocketAddr,
    server: SocketAddr,
    uuid: Uuid,
    tls: Option<(&Path, &str)>,
    transport: Option<TestTransport>,
) -> ManagedChild {
    let config_path = temp.path().join(format!("go-client-{index}.json"));
    let log_path = temp.path().join(format!("go-client-{index}.log"));
    let alpn = if transport.is_some() {
        "http/1.1"
    } else {
        "h2"
    };
    let tls = tls.map(|(ca_path, server_name)| {
        serde_json::json!({
            "enabled": true,
            "server_name": server_name,
            "alpn": [alpn],
            "certificate_path": ca_path
        })
    });
    let mut outbound = serde_json::json!({
        "type": "vmess",
        "tag": "vmess-out",
        "server": server.ip().to_string(),
        "server_port": server.port(),
        "uuid": uuid.to_string(),
        "security": "auto"
    });
    if let Some(tls) = tls {
        outbound
            .as_object_mut()
            .expect("outbound object")
            .insert("tls".to_string(), tls);
    }
    if let Some(transport) = transport {
        outbound
            .as_object_mut()
            .expect("outbound object")
            .insert("transport".to_string(), transport.json());
    }
    let config = serde_json::json!({
        "log": {"level": "debug", "timestamp": false},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": socks.ip().to_string(),
            "listen_port": socks.port()
        }],
        "outbounds": [outbound],
        "route": {"final": "vmess-out"}
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
        .expect("spawn Go sing-box 1.13.13 client");
    let mut child = ManagedChild { child, log_path };
    wait_for_listener(&mut child, socks, "Go client").await;
    child
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::other("SOCKS authentication rejected"));
    }

    let SocketAddr::V4(target) = target else {
        return Err(io::Error::other("test target must be IPv4"));
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS connect rejected with code {}",
            reply[1]
        )));
    }
    let address_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        other => return Err(io::Error::other(format!("invalid SOCKS atyp {other}"))),
    };
    let mut bound = vec![0_u8; address_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

async fn assert_socks_echo(
    socks: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut stream = socks_connect(socks, target).await?;
        stream.write_all(payload).await?;
        let mut response = vec![0_u8; payload.len()];
        stream.read_exact(&mut response).await?;
        if response != payload {
            return Err(io::Error::other("echo payload mismatch"));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS VMess timeout"))?
}

async fn wait_for_log(path: &Path, needles: &[&str]) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let log = std::fs::read_to_string(path).unwrap_or_default();
            if needles.iter().all(|needle| log.contains(needle)) {
                return log;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| std::fs::read_to_string(path).unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_tls13_client_to_production_rust_app_with_negatives() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_path, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let rust_addr = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let mut rust =
        start_rust_app(&temp, rust_addr, uuid, Some((&cert_path, &key_path, "1.3"))).await;
    let socks = unused_loopback_addr().await;
    let _go = start_go_client(
        &temp,
        "valid13",
        socks,
        rust_addr,
        uuid,
        Some((&ca_path, "localhost")),
    )
    .await;
    let payload = vec![0x6b; 32 * 1024 + 113];
    for _ in 0..3 {
        assert_socks_echo(socks, echo.addr, &payload)
            .await
            .expect("Go TLS 1.3 client -> Rust app echo");
    }

    let log = wait_for_log(
        &rust.log_path,
        &["vmess: TLS handshake complete", "h2", "TLSv1_3"],
    )
    .await;
    assert!(
        log.contains("h2"),
        "negotiated ALPN missing from log: {log}"
    );
    assert!(
        log.contains("TLSv1_3"),
        "negotiated TLS version missing from log: {log}"
    );

    let wrong_sni_addr = unused_loopback_addr().await;
    let _wrong_sni = start_go_client(
        &temp,
        "wrong-sni",
        wrong_sni_addr,
        rust_addr,
        uuid,
        Some((&ca_path, "wrong.example")),
    )
    .await;
    assert!(
        assert_socks_echo(wrong_sni_addr, echo.addr, b"must fail")
            .await
            .is_err(),
        "wrong SNI must fail"
    );

    let wrong_uuid_addr = unused_loopback_addr().await;
    let _wrong_uuid = start_go_client(
        &temp,
        "wrong-uuid",
        wrong_uuid_addr,
        rust_addr,
        Uuid::new_v4(),
        Some((&ca_path, "localhost")),
    )
    .await;
    assert!(
        assert_socks_echo(wrong_uuid_addr, echo.addr, b"must fail")
            .await
            .is_err(),
        "wrong UUID must fail after TLS"
    );

    let untrusted_ca = temp.path().join("untrusted-ca.pem");
    let other_temp = TempDir::new().expect("other CA temp");
    let (other_ca, _, _) = generate_local_ca(&other_temp);
    std::fs::copy(other_ca, &untrusted_ca).expect("copy untrusted CA");
    let untrusted_addr = unused_loopback_addr().await;
    let _untrusted = start_go_client(
        &temp,
        "untrusted",
        untrusted_addr,
        rust_addr,
        uuid,
        Some((&untrusted_ca, "localhost")),
    )
    .await;
    assert!(
        assert_socks_echo(untrusted_addr, echo.addr, b"must fail")
            .await
            .is_err(),
        "untrusted CA must fail"
    );
    rust.stop_gracefully("Rust TLS 1.3 app").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_tls12_client_to_production_rust_app() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_path, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let rust_addr = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let mut rust =
        start_rust_app(&temp, rust_addr, uuid, Some((&cert_path, &key_path, "1.2"))).await;
    let socks = unused_loopback_addr().await;
    let _go = start_go_client(
        &temp,
        "valid12",
        socks,
        rust_addr,
        uuid,
        Some((&ca_path, "localhost")),
    )
    .await;
    assert_socks_echo(socks, echo.addr, &vec![0x12; 20 * 1024 + 29])
        .await
        .expect("Go TLS 1.2 client -> Rust app echo");

    let log = wait_for_log(
        &rust.log_path,
        &["vmess: TLS handshake complete", "h2", "TLSv1_2"],
    )
    .await;
    assert!(
        log.contains("h2"),
        "negotiated ALPN missing from log: {log}"
    );
    assert!(
        log.contains("TLSv1_2"),
        "negotiated TLS version missing from log: {log}"
    );
    rust.stop_gracefully("Rust TLS 1.2 app").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_plain_client_to_production_rust_app_regression() {
    let temp = TempDir::new().expect("temp dir");
    let echo = start_echo_server().await;
    let rust_addr = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let mut rust = start_rust_app(&temp, rust_addr, uuid, None).await;
    let socks = unused_loopback_addr().await;
    let _go = start_go_client(&temp, "plain", socks, rust_addr, uuid, None).await;

    assert_socks_echo(socks, echo.addr, b"plain VMess remains compatible")
        .await
        .expect("Go plain client -> Rust app echo");
    rust.stop_gracefully("Rust plain VMess app").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_plain_v2ray_transports_to_production_rust_app() {
    let temp = TempDir::new().expect("temp dir");
    let echo = start_echo_server().await;
    let cases = [
        (
            "plain-ws",
            TestTransport::WebSocket {
                path: "/plain-ws",
                host: "ws.plain.test",
            },
        ),
        (
            "plain-httpupgrade",
            TestTransport::HttpUpgrade {
                path: "/plain-upgrade",
                host: "http.plain.test",
            },
        ),
    ];

    for (label, transport) in cases {
        let rust_addr = unused_loopback_addr().await;
        let uuid = Uuid::new_v4();
        let mut rust =
            start_rust_app_with_transport(&temp, rust_addr, uuid, None, Some(transport)).await;
        let socks = unused_loopback_addr().await;
        let _go = start_go_client_with_transport(
            &temp,
            label,
            socks,
            rust_addr,
            uuid,
            None,
            Some(transport),
        )
        .await;
        assert_socks_echo(socks, echo.addr, &vec![0x5c; 20 * 1024 + 11])
            .await
            .unwrap_or_else(|error| panic!("{label} Go client -> Rust app failed: {error}"));
        rust.stop_gracefully(label).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_websocket_tls_client_to_production_rust_app() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_path, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let rust_addr = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let transport = TestTransport::WebSocket {
        path: "/vmess-ws",
        host: "ws.virtual.test",
    };
    let mut rust = start_rust_app_with_transport(
        &temp,
        rust_addr,
        uuid,
        Some((&cert_path, &key_path, "1.3")),
        Some(transport),
    )
    .await;
    let socks = unused_loopback_addr().await;
    let _go = start_go_client_with_transport(
        &temp,
        "ws-valid",
        socks,
        rust_addr,
        uuid,
        Some((&ca_path, "localhost")),
        Some(transport),
    )
    .await;
    let payload = vec![0x77; 24 * 1024 + 41];
    for _ in 0..3 {
        assert_socks_echo(socks, echo.addr, &payload)
            .await
            .expect("Go WS+TLS client -> Rust app echo");
    }

    let bad_path_socks = unused_loopback_addr().await;
    let _bad_path = start_go_client_with_transport(
        &temp,
        "ws-bad-path",
        bad_path_socks,
        rust_addr,
        uuid,
        Some((&ca_path, "localhost")),
        Some(TestTransport::WebSocket {
            path: "/wrong",
            host: "ws.virtual.test",
        }),
    )
    .await;
    assert!(
        assert_socks_echo(bad_path_socks, echo.addr, b"must fail")
            .await
            .is_err(),
        "wrong WebSocket path must fail"
    );

    let log = wait_for_log(
        &rust.log_path,
        &[
            "inbound transport TLS handshake complete",
            "http/1.1",
            "transport=\"ws\"",
        ],
    )
    .await;
    assert!(log.contains("http/1.1"), "WS ALPN missing: {log}");
    assert!(
        log.contains("transport=\"ws\""),
        "WS transport ownership missing: {log}"
    );
    rust.stop_gracefully("Rust WS+TLS app").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_httpupgrade_tls_client_to_production_rust_app() {
    let temp = TempDir::new().expect("temp dir");
    let (ca_path, cert_path, key_path) = generate_local_ca(&temp);
    let echo = start_echo_server().await;
    let rust_addr = unused_loopback_addr().await;
    let uuid = Uuid::new_v4();
    let transport = TestTransport::HttpUpgrade {
        path: "/vmess-upgrade",
        host: "http.virtual.test",
    };
    let mut rust = start_rust_app_with_transport(
        &temp,
        rust_addr,
        uuid,
        Some((&cert_path, &key_path, "1.3")),
        Some(transport),
    )
    .await;
    let socks = unused_loopback_addr().await;
    let _go = start_go_client_with_transport(
        &temp,
        "httpupgrade-valid",
        socks,
        rust_addr,
        uuid,
        Some((&ca_path, "localhost")),
        Some(transport),
    )
    .await;
    assert_socks_echo(socks, echo.addr, &vec![0x48; 20 * 1024 + 17])
        .await
        .expect("Go HTTPUpgrade+TLS client -> Rust app echo");

    let wrong_host_socks = unused_loopback_addr().await;
    let _wrong_host = start_go_client_with_transport(
        &temp,
        "httpupgrade-wrong-host",
        wrong_host_socks,
        rust_addr,
        uuid,
        Some((&ca_path, "localhost")),
        Some(TestTransport::HttpUpgrade {
            path: "/vmess-upgrade",
            host: "wrong.virtual.test",
        }),
    )
    .await;
    assert!(
        assert_socks_echo(wrong_host_socks, echo.addr, b"must fail")
            .await
            .is_err(),
        "wrong HTTPUpgrade Host must fail"
    );
    rust.stop_gracefully("Rust HTTPUpgrade+TLS app").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_rust_app_rejects_malformed_tls_key_before_readiness() {
    let temp = TempDir::new().expect("temp dir");
    let (_, cert_path, key_path) = generate_local_ca(&temp);
    std::fs::write(&key_path, "not a private key").expect("replace test key");
    let listen = unused_loopback_addr().await;
    let config_path = temp.path().join("rust-invalid-key.json");
    let log_path = temp.path().join("rust-invalid-key.log");
    let config = serde_json::json!({
        "log": {"level": "debug", "timestamp": false},
        "inbounds": [{
            "type": "vmess",
            "tag": "vmess-in",
            "listen": listen.ip().to_string(),
            "listen_port": listen.port(),
            "uuid": Uuid::new_v4().to_string(),
            "tls": {
                "enabled": true,
                "certificate_path": cert_path,
                "key_path": key_path
            }
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).expect("serialize invalid config"),
    )
    .expect("write invalid config");
    let stdout = File::create(&log_path).expect("create invalid-config log");
    let stderr = stdout.try_clone().expect("clone invalid-config log");
    let child = Command::new(app_binary())
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn Rust app with invalid key");
    let mut child = ManagedChild { child, log_path };
    let status = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(status) = child.child.try_wait().expect("poll invalid app") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("invalid TLS app must exit");
    assert!(!status.success(), "malformed key must fail startup");
    assert!(
        TcpStream::connect(listen).await.is_err(),
        "invalid TLS listener must never become ready"
    );
    let log = std::fs::read_to_string(&child.log_path).unwrap_or_default();
    assert!(
        log.contains("private key") && (log.contains("invalid") || log.contains("no private key")),
        "startup error must identify invalid key without content: {log}"
    );
    assert!(
        !log.contains("not a private key"),
        "TLS error must not leak key content"
    );
}
