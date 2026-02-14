#![cfg(feature = "net_e2e")]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use sb_adapters::inbound::shadowsocks::{ShadowsocksInboundConfig, ShadowsocksUser};
use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_adapters::outbound::{DialOpts, OutboundConnector, Target};
use sb_adapters::TransportKind;
use sb_core::router::engine::RouterHandle;

struct ShadowsocksServerHandle {
    stop_tx: mpsc::Sender<()>,
}

impl ShadowsocksServerHandle {
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
                eprintln!("Skipping shadowsocks restart test: cannot bind echo server ({err})");
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
                eprintln!("Skipping shadowsocks restart test: cannot allocate listen addr ({err})");
                None
            } else {
                panic!("allocate listen addr failed: {err}");
            }
        }
    }
}

async fn start_ss_server_on(
    listen: SocketAddr,
    method: &str,
    password: &str,
) -> Option<ShadowsocksServerHandle> {
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
            panic!("Failed to bind shadowsocks server {listen}: {err}");
        }
    };
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("ss local_addr: {err}"));
    drop(listener);

    let (stop_tx, stop_rx) = mpsc::channel(1);

    #[allow(deprecated)]
    let config = ShadowsocksInboundConfig {
        listen: addr,
        method: method.to_string(),
        password: None,
        users: vec![ShadowsocksUser::new(
            "default".to_string(),
            password.to_string(),
        )],
        router: Arc::new(RouterHandle::new_mock()),
        tag: None,
        stats: None,
        multiplex: None,
        transport_layer: None,
    };

    tokio::spawn(async move {
        let _ = sb_adapters::inbound::shadowsocks::serve(config, stop_rx).await;
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    Some(ShadowsocksServerHandle { stop_tx })
}

async fn start_ss_with_retry(
    listen: SocketAddr,
    method: &str,
    password: &str,
) -> Option<ShadowsocksServerHandle> {
    for _ in 0..20 {
        if let Some(handle) = start_ss_server_on(listen, method, password).await {
            return Some(handle);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

async fn dial_echo_once(
    connector: &ShadowsocksConnector,
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

async fn run_concurrent_ss_round(
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
            let connector = match ShadowsocksConnector::new(ShadowsocksConfig {
                server,
                tag: None,
                method: "aes-256-gcm".to_string(),
                password,
                connect_timeout_sec: Some(3),
                multiplex: None,
            }) {
                Ok(c) => c,
                Err(_) => return false,
            };
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
async fn test_shadowsocks_server_restart_recovery() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let Some(server) = start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
    else {
        eprintln!("Skipping shadowsocks restart test: server bind retries exhausted");
        return;
    };

    let connector = ShadowsocksConnector::new(ShadowsocksConfig {
        server: listen_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password".to_string(),
        connect_timeout_sec: Some(3),
        multiplex: None,
    })
    .expect("failed to create shadowsocks connector");

    assert!(
        dial_echo_once(&connector, echo_addr, b"ss-before-restart").await,
        "baseline shadowsocks flow should succeed before restart"
    );

    server.stop().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        !dial_echo_once(&connector, echo_addr, b"ss-during-down").await,
        "shadowsocks flow should fail while server is down"
    );

    let Some(restarted) = start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
    else {
        panic!("shadowsocks restart failed to bind on {listen_addr}");
    };

    assert!(
        dial_echo_once(&connector, echo_addr, b"ss-after-restart").await,
        "shadowsocks flow should recover after server restart"
    );

    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shadowsocks_server_multi_flap_recovery() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let Some(mut server) = start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
    else {
        eprintln!("Skipping shadowsocks multi-flap test: server bind retries exhausted");
        return;
    };

    let connector = ShadowsocksConnector::new(ShadowsocksConfig {
        server: listen_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: "test-password".to_string(),
        connect_timeout_sec: Some(3),
        multiplex: None,
    })
    .expect("failed to create shadowsocks connector");

    assert!(
        dial_echo_once(&connector, echo_addr, b"ss-before-flap").await,
        "baseline shadowsocks flow should succeed before multi-flap"
    );

    for flap in 1..=2 {
        server.stop().await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let down_payload = format!("ss-during-flap-{flap}");
        assert!(
            !dial_echo_once(&connector, echo_addr, down_payload.as_bytes()).await,
            "shadowsocks flow should fail while server is down (flap #{flap})"
        );

        let Some(restarted) =
            start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
        else {
            panic!("shadowsocks multi-flap restart failed to bind on {listen_addr}");
        };

        let recover_payload = format!("ss-after-flap-{flap}");
        assert!(
            dial_echo_once(&connector, echo_addr, recover_payload.as_bytes()).await,
            "shadowsocks flow should recover after flap #{flap}"
        );
        server = restarted;
    }

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_shadowsocks_restart_recovery_concurrent_burst() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let Some(server) = start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
    else {
        eprintln!("Skipping shadowsocks concurrent recovery test: server bind retries exhausted");
        return;
    };

    let total = 30usize;
    let before = run_concurrent_ss_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        total,
        "ss-before-burst",
    )
    .await;
    assert!(
        before >= 27,
        "shadowsocks pre-restart concurrent burst too low: {before}/{total}"
    );

    server.stop().await;
    tokio::time::sleep(Duration::from_millis(350)).await;

    let during = run_concurrent_ss_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        total,
        "ss-during-burst",
    )
    .await;
    assert_eq!(
        during, 0,
        "shadowsocks burst should fully fail while server is down, got {during}/{total}"
    );

    let Some(restarted) = start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
    else {
        panic!("shadowsocks concurrent recovery restart failed to bind on {listen_addr}");
    };

    let after = run_concurrent_ss_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        total,
        "ss-after-burst",
    )
    .await;
    assert!(
        after >= 27,
        "shadowsocks post-restart concurrent burst too low: {after}/{total}"
    );

    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_shadowsocks_auth_fault_then_concurrent_recovery() {
    let Some(echo_addr) = start_echo_server().await else {
        return;
    };
    let Some(listen_addr) = allocate_tcp_addr() else {
        return;
    };

    let Some(server) = start_ss_with_retry(listen_addr, "aes-256-gcm", "test-password").await
    else {
        eprintln!("Skipping shadowsocks auth fault recovery test: server bind retries exhausted");
        return;
    };

    let baseline_total = 30usize;
    let baseline_ok = run_concurrent_ss_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        baseline_total,
        "ss-baseline-ok",
    )
    .await;
    assert!(
        baseline_ok >= 27,
        "shadowsocks baseline concurrent burst too low: {baseline_ok}/{baseline_total}"
    );

    let fault_total = 1usize;
    let fault_ok = run_concurrent_ss_round(
        listen_addr.to_string(),
        "wrong-password".to_string(),
        echo_addr,
        fault_total,
        "ss-auth-fault",
    )
    .await;
    assert_eq!(
        fault_ok, 0,
        "shadowsocks wrong-password fault should fail, got {fault_ok}/{fault_total}"
    );

    tokio::time::sleep(Duration::from_millis(300)).await;

    let recovery_total = 30usize;
    let recovery_ok = run_concurrent_ss_round(
        listen_addr.to_string(),
        "test-password".to_string(),
        echo_addr,
        recovery_total,
        "ss-recovery-ok",
    )
    .await;
    assert!(
        recovery_ok >= 27,
        "shadowsocks post-fault concurrent recovery too low: {recovery_ok}/{recovery_total}"
    );

    server.stop().await;
}
