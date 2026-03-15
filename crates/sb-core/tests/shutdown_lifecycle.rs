use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR};
use sb_core::runtime::supervisor::{Supervisor, SupervisorHandle};
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout, Instant};

fn minimal_ir() -> ConfigIR {
    ConfigIR {
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn reserve_loopback_addr() -> io::Result<SocketAddr> {
    let listener = StdTcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn http_direct_ir(listen_addr: SocketAddr) -> ConfigIR {
    ConfigIR {
        inbounds: vec![InboundIR {
            tag: Some("http-in".to_string()),
            ty: InboundType::Http,
            listen: listen_addr.ip().to_string(),
            port: listen_addr.port(),
            sniff: false,
            udp: false,
            allow_private_network: true,
            ..Default::default()
        }],
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".to_string()),
            ..Default::default()
        }],
        route: RouteIR {
            default: Some("direct".to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn open_connect_tunnel(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut stream = loop {
        match TcpStream::connect(proxy_addr).await {
            Ok(stream) => break stream,
            Err(err)
                if Instant::now() < deadline
                    && matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
                    ) =>
            {
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err),
        }
    };
    let request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target_addr.ip(),
        target_addr.port(),
        target_addr.ip(),
        target_addr.port()
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed before CONNECT response completed",
            ));
        }
        response.extend_from_slice(&buf[..n]);
    }

    let response_text = String::from_utf8_lossy(&response);
    if !response_text.starts_with("HTTP/1.1 200") {
        return Err(io::Error::other(format!(
            "unexpected CONNECT response: {response_text}"
        )));
    }

    Ok(stream)
}

async fn wait_for_active_inbounds(handle: &SupervisorHandle, expected: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let total = {
            let state = handle.state().await;
            let guard = state.read().await;
            guard
                .bridge
                .inbounds
                .iter()
                .filter_map(|inbound| inbound.active_connections())
                .sum::<u64>()
        };

        if total == expected {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn start_hold_open_server() -> io::Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (release_tx, release_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let _ = release_rx.await;
        drop(socket);
    });

    Ok((addr, release_tx))
}

async fn wait_for_listener_bind(addr: SocketAddr) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(err)
                if Instant::now() < deadline
                    && matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
                    ) =>
            {
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn wait_for_port_rebind(addr: SocketAddr) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match StdTcpListener::bind(addr) {
            Ok(listener) => {
                drop(listener);
                return Ok(());
            }
            Err(err)
                if Instant::now() < deadline && matches!(err.kind(), io::ErrorKind::AddrInUse) =>
            {
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[tokio::test]
async fn shutdown_converges_quickly() {
    let ir = minimal_ir();
    let sup = Supervisor::start(ir).await.expect("start supervisor");
    let handle = sup.handle();
    handle
        .shutdown_graceful(std::time::Duration::from_millis(100))
        .await
        .expect("shutdown");
}

#[tokio::test]
async fn repeated_init_and_shutdown_no_leak() {
    let ir = minimal_ir();
    let sup1 = Supervisor::start(ir.clone())
        .await
        .expect("start supervisor #1");
    let h1 = sup1.handle();
    h1.shutdown_graceful(std::time::Duration::from_millis(100))
        .await
        .expect("shutdown #1");

    let sup2 = Supervisor::start(ir).await.expect("start supervisor #2");
    let h2 = sup2.handle();
    h2.shutdown_graceful(std::time::Duration::from_millis(100))
        .await
        .expect("shutdown #2");
}

#[tokio::test]
async fn graceful_shutdown_waits_for_http_connection_to_drain() {
    let listen_addr = reserve_loopback_addr().expect("reserve proxy addr");
    let (target_addr, release_target) = start_hold_open_server().await.expect("hold-open server");
    let registry = sb_adapters::build_default_registry();

    let supervisor = Supervisor::start_with_registry(http_direct_ir(listen_addr), Some(registry))
        .await
        .expect("start supervisor");
    let handle = supervisor.handle();

    let tunnel = open_connect_tunnel(listen_addr, target_addr)
        .await
        .expect("open CONNECT tunnel");

    assert!(
        wait_for_active_inbounds(&handle, 1).await,
        "expected one active inbound connection before shutdown"
    );

    let shutdown_task = tokio::spawn(async move {
        let started = Instant::now();
        supervisor
            .shutdown_graceful(Duration::from_secs(2))
            .await
            .expect("graceful shutdown");
        started.elapsed()
    });

    sleep(Duration::from_millis(250)).await;
    assert!(
        !shutdown_task.is_finished(),
        "shutdown should wait while the CONNECT tunnel is still active"
    );

    drop(tunnel);
    let _ = release_target.send(());

    let elapsed = timeout(Duration::from_secs(3), shutdown_task)
        .await
        .expect("shutdown task should finish")
        .expect("shutdown task join");

    assert!(
        elapsed >= Duration::from_millis(250),
        "shutdown returned before the active tunnel drained: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "shutdown should complete once the tunnel drains, got {elapsed:?}"
    );
    assert!(
        wait_for_active_inbounds(&handle, 0).await,
        "expected no active inbound connections after shutdown"
    );
}

#[tokio::test]
async fn graceful_shutdown_releases_listener_and_clears_runtime_trackers() {
    let listen_addr = reserve_loopback_addr().expect("reserve proxy addr");
    let registry = sb_adapters::build_default_registry();
    let supervisor = Supervisor::start_with_registry(http_direct_ir(listen_addr), Some(registry))
        .await
        .expect("start supervisor");
    let handle = supervisor.handle();

    wait_for_listener_bind(listen_addr)
        .await
        .expect("http listener should bind before shutdown");
    assert!(
        wait_for_active_inbounds(&handle, 0).await,
        "probe connection should drain before tracker assertions"
    );

    let task_token = {
        let state = handle.state().await;
        let guard = state.read().await;
        guard.context.connections.register(
            "127.0.0.1:12345".into(),
            "example.com:443".into(),
            "tcp".into(),
        );
        guard
            .context
            .task_monitor
            .register("shutdown-cleanup".into())
    };

    supervisor
        .shutdown_graceful(Duration::from_secs(1))
        .await
        .expect("graceful shutdown");

    assert!(
        task_token.is_cancelled(),
        "shutdown should cancel tracked background tasks"
    );

    let state = handle.state().await;
    let guard = state.read().await;
    assert_eq!(
        guard.context.connections.count(),
        0,
        "shutdown should clear tracked connections"
    );
    assert_eq!(
        guard.context.task_monitor.count(),
        0,
        "shutdown should clear tracked tasks"
    );
    drop(guard);

    wait_for_port_rebind(listen_addr)
        .await
        .expect("listener port should become reusable after shutdown");
}
