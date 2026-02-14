#![cfg(all(feature = "net_e2e", feature = "tls_reality"))]

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use sb_adapters::inbound::trojan::{TrojanInboundConfig, TrojanUser};
use sb_adapters::outbound::trojan::{TrojanConfig, TrojanConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::transport_config::TransportConfig;
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;

fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct TrojanServerHandle {
    stop_tx: mpsc::Sender<()>,
    _cert_file: NamedTempFile,
    _key_file: NamedTempFile,
}

impl TrojanServerHandle {
    async fn stop(self) {
        let _ = self.stop_tx.send(()).await;
    }
}

async fn start_echo_server() -> Option<SocketAddr> {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping trojan restart test: cannot bind echo server ({err})");
                return None;
            }
            panic!("Failed to bind echo server: {err}");
        }
    };
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("echo local_addr: {err}"));

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    Some(addr)
}

fn generate_test_certs(cn: &str) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    let cert = rcgen::Certificate::from_params(params).unwrap_or_else(|err| panic!("rcgen: {err}"));
    (
        cert.serialize_pem()
            .unwrap_or_else(|err| panic!("serialize cert pem: {err}")),
        cert.serialize_private_key_pem(),
    )
}

fn allocate_tcp_addr() -> Option<SocketAddr> {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            let addr = listener
                .local_addr()
                .unwrap_or_else(|err| panic!("alloc local_addr: {err}"));
            drop(listener);
            Some(addr)
        }
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) {
                eprintln!("Skipping trojan restart test: cannot allocate listen addr ({err})");
                None
            } else {
                panic!("allocate listen addr failed: {err}");
            }
        }
    }
}

async fn start_trojan_server_on(
    listen: SocketAddr,
    password: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Option<TrojanServerHandle> {
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(err) => {
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied
                    | io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::AddrInUse
            ) {
                return None;
            }
            panic!("Failed to bind trojan server {listen}: {err}");
        }
    };
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("trojan local_addr: {err}"));
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    let mut cert_file = NamedTempFile::new().unwrap_or_else(|err| panic!("temp cert file: {err}"));
    cert_file
        .write_all(cert_pem.as_bytes())
        .unwrap_or_else(|err| panic!("write cert file: {err}"));
    let mut key_file = NamedTempFile::new().unwrap_or_else(|err| panic!("temp key file: {err}"));
    key_file
        .write_all(key_pem.as_bytes())
        .unwrap_or_else(|err| panic!("write key file: {err}"));

    let config = TrojanInboundConfig {
        listen: addr,
        #[allow(deprecated)]
        password: None,
        users: vec![TrojanUser::new("test".to_string(), password.to_string())],
        cert_path: cert_file.path().to_string_lossy().to_string(),
        key_path: key_file.path().to_string_lossy().to_string(),
        router: Arc::new(RouterHandle::new_mock()),
        tag: None,
        stats: None,
        transport_layer: None,
        multiplex: None,
        reality: None,
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::trojan::serve(config, stop_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    Some(TrojanServerHandle {
        stop_tx,
        _cert_file: cert_file,
        _key_file: key_file,
    })
}

async fn start_trojan_with_retry(
    listen: SocketAddr,
    password: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Option<TrojanServerHandle> {
    for _ in 0..20 {
        if let Some(handle) = start_trojan_server_on(listen, password, cert_pem, key_pem).await {
            return Some(handle);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn dial_echo_once(
    connector: &TrojanConnector,
    echo_addr: SocketAddr,
    payload: &[u8],
) -> bool {
    let target = Target {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        kind: TransportKind::Tcp,
    };

    match connector.dial(target, DialOpts::default()).await {
        Ok(mut stream) => {
            if stream.write_all(payload).await.is_err() {
                return false;
            }
            let mut back = vec![0u8; payload.len()];
            stream.read_exact(&mut back).await.is_ok() && back == payload
        }
        Err(_) => false,
    }
}

async fn run_concurrent_trojan_round(
    server: String,
    password: String,
    echo_addr: SocketAddr,
    total: usize,
    prefix: &str,
) -> usize {
    let mut set = JoinSet::new();
    for i in 0..total {
        let server = server.clone();
        let password = password.clone();
        let payload = format!("{prefix}-{i}");
        set.spawn(async move {
            let connector = TrojanConnector::new(TrojanConfig {
                server,
                tag: None,
                password,
                connect_timeout_sec: Some(3),
                sni: Some("localhost".to_string()),
                alpn: None,
                skip_cert_verify: true,
                transport_layer: TransportConfig::Tcp,
                reality: None,
                multiplex: None,
            });
            dial_echo_once(&connector, echo_addr, payload.as_bytes()).await
        });
    }

    let mut ok = 0usize;
    while let Some(result) = set.join_next().await {
        if matches!(result, Ok(true)) {
            ok += 1;
        }
    }
    ok
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_trojan_server_restart_recovery() {
    init_crypto();
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let (cert, key) = generate_test_certs("localhost");
    let Some(server) = start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
    else {
        eprintln!("Skipping trojan restart test: server bind retries exhausted");
        return;
    };

    let connector = TrojanConnector::new(TrojanConfig {
        server: listen_addr.to_string(),
        tag: None,
        password: "test-password".to_string(),
        connect_timeout_sec: Some(3),
        sni: Some("localhost".to_string()),
        alpn: None,
        skip_cert_verify: true,
        transport_layer: TransportConfig::Tcp,
        reality: None,
        multiplex: None,
    });

    assert!(
        dial_echo_once(&connector, echo_addr, b"trojan-before-restart").await,
        "baseline trojan flow should succeed before restart"
    );

    server.stop().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        !dial_echo_once(&connector, echo_addr, b"trojan-during-down").await,
        "trojan flow should fail while server is down"
    );

    let Some(restarted) = start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
    else {
        panic!("trojan restart failed to bind on {listen_addr}");
    };

    assert!(
        dial_echo_once(&connector, echo_addr, b"trojan-after-restart").await,
        "trojan flow should recover after server restart"
    );

    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_trojan_server_multi_flap_recovery() {
    init_crypto();
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let (cert, key) = generate_test_certs("localhost");
    let Some(mut server) = start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
    else {
        eprintln!("Skipping trojan multi-flap test: server bind retries exhausted");
        return;
    };

    let connector = TrojanConnector::new(TrojanConfig {
        server: listen_addr.to_string(),
        tag: None,
        password: "test-password".to_string(),
        connect_timeout_sec: Some(3),
        sni: Some("localhost".to_string()),
        alpn: None,
        skip_cert_verify: true,
        transport_layer: TransportConfig::Tcp,
        reality: None,
        multiplex: None,
    });

    assert!(
        dial_echo_once(&connector, echo_addr, b"trojan-before-flap").await,
        "baseline trojan flow should succeed before multi-flap"
    );

    for flap in 1..=2 {
        server.stop().await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let down_payload = format!("trojan-during-flap-{flap}");
        assert!(
            !dial_echo_once(&connector, echo_addr, down_payload.as_bytes()).await,
            "trojan flow should fail while server is down (flap #{flap})"
        );

        let Some(restarted) =
            start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
        else {
            panic!("trojan multi-flap restart failed to bind on {listen_addr}");
        };

        let recover_payload = format!("trojan-after-flap-{flap}");
        assert!(
            dial_echo_once(&connector, echo_addr, recover_payload.as_bytes()).await,
            "trojan flow should recover after flap #{flap}"
        );
        server = restarted;
    }

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_trojan_restart_recovery_concurrent_burst() {
    init_crypto();
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let (cert, key) = generate_test_certs("localhost");
    let Some(server) = start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
    else {
        eprintln!("Skipping trojan concurrent recovery test: server bind retries exhausted");
        return;
    };

    let total = 30usize;
    let before = run_concurrent_trojan_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        total,
        "trojan-before-burst",
    )
    .await;
    assert!(
        before >= 27,
        "trojan pre-restart concurrent burst too low: {before}/{total}"
    );

    server.stop().await;
    tokio::time::sleep(Duration::from_millis(350)).await;

    let during = run_concurrent_trojan_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        total,
        "trojan-during-burst",
    )
    .await;
    assert_eq!(
        during, 0,
        "trojan burst should fully fail while server is down, got {during}/{total}"
    );

    let Some(restarted) = start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
    else {
        panic!("trojan concurrent recovery restart failed to bind on {listen_addr}");
    };

    let after = run_concurrent_trojan_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        total,
        "trojan-after-burst",
    )
    .await;
    assert!(
        after >= 27,
        "trojan post-restart concurrent burst too low: {after}/{total}"
    );

    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_trojan_auth_fault_then_concurrent_recovery() {
    init_crypto();
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let (cert, key) = generate_test_certs("localhost");
    let Some(server) = start_trojan_with_retry(listen_addr, "test-password", &cert, &key).await
    else {
        eprintln!("Skipping trojan auth fault recovery test: server bind retries exhausted");
        return;
    };

    let baseline_total = 30usize;
    let baseline_ok = run_concurrent_trojan_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        baseline_total,
        "trojan-baseline-ok",
    )
    .await;
    assert!(
        baseline_ok >= 27,
        "trojan baseline concurrent burst too low: {baseline_ok}/{baseline_total}"
    );

    let fault_total = 1usize;
    let fault_ok = run_concurrent_trojan_round(
        listen_addr.to_string(),
        "wrong-password".to_string(),
        echo_addr,
        fault_total,
        "trojan-auth-fault",
    )
    .await;
    assert_eq!(
        fault_ok, 0,
        "trojan wrong-password fault should fail, got {fault_ok}/{fault_total}"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;

    let recovery_total = 30usize;
    let recovery_ok = run_concurrent_trojan_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        recovery_total,
        "trojan-recovery-ok",
    )
    .await;
    assert!(
        recovery_ok >= 27,
        "trojan post-fault concurrent recovery too low: {recovery_ok}/{recovery_total}"
    );

    server.stop().await;
}
