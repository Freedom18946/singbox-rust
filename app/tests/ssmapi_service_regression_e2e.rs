#![cfg(feature = "parity")]

use sb_adapters::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};
use sb_config::ir::{
    ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RouteIR, ServiceIR, ServiceType,
    ShadowsocksUserIR,
};
use sb_core::adapter::bridge::build_bridge;
use sb_core::router::Engine;
use sb_core::runtime::Runtime;
use sb_types::{Session, TargetAddr};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Instant};

const AUTH_TOKEN: &str = "ssmapi-regression-token";

fn reserve_loopback_port(label: &str) -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().unwrap().port()),
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
            ) =>
        {
            eprintln!("skipping ssmapi regression test: cannot reserve {label} port ({err})");
            None
        }
        Err(err) => panic!("failed to reserve {label} port: {err}"),
    }
}

async fn start_tcp_echo() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok((addr, handle))
}

async fn start_udp_echo() -> io::Result<(SocketAddr, JoinHandle<()>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    Ok((addr, handle))
}

fn build_ir(ss_port: u16, api_port: u16, cache_path: String) -> ConfigIR {
    ConfigIR {
        inbounds: vec![InboundIR {
            ty: InboundType::Shadowsocks,
            tag: Some("ss-managed".to_string()),
            listen: "127.0.0.1".to_string(),
            port: ss_port,
            udp: true,
            method: Some("aes-256-gcm".to_string()),
            password: None,
            users_shadowsocks: Some(vec![ShadowsocksUserIR {
                name: "bootstrap".to_string(),
                password: "bootstrap-pw".to_string(),
            }]),
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
        services: vec![ServiceIR {
            ty: ServiceType::Ssmapi,
            tag: Some("ssmapi-regression".to_string()),
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(api_port),
            servers: Some(HashMap::from([(
                "/server-a".to_string(),
                "ss-managed".to_string(),
            )])),
            cache_path: Some(cache_path),
            auth_token: Some(AUTH_TOKEN.to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn ss_connector(ss_addr: SocketAddr, password: &str) -> ShadowsocksConnector {
    ShadowsocksConnector::new(ShadowsocksConfig {
        server: ss_addr.to_string(),
        tag: None,
        method: "aes-256-gcm".to_string(),
        password: password.to_string(),
        connect_timeout_sec: Some(5),
        detour: None,
        multiplex: None,
    })
    .expect("create Shadowsocks connector")
}

async fn wait_for_api(client: &reqwest::Client, base_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(resp) = client
            .get(format!("{base_url}/server-a/server/v1"))
            .bearer_auth(AUTH_TOKEN)
            .send()
            .await
        {
            if resp.status().is_success() {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "SSMAPI service did not become ready"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_tcp(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(50)).await,
            Err(err) => panic!("Shadowsocks TCP listener did not become ready: {err}"),
        }
    }
}

async fn ssmapi_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    body: Option<Value>,
) -> reqwest::Response {
    let mut req = client.request(method, url).bearer_auth(AUTH_TOKEN);
    if let Some(body) = body {
        req = req.json(&body);
    }
    req.send().await.expect("SSMAPI HTTP request")
}

async fn stats(client: &reqwest::Client, base_url: &str) -> Value {
    ssmapi_json(
        client,
        reqwest::Method::GET,
        format!("{base_url}/server-a/server/v1/stats"),
        None,
    )
    .await
    .json()
    .await
    .expect("stats JSON")
}

fn user<'a>(stats: &'a Value, name: &str) -> &'a Value {
    stats["users"]
        .as_array()
        .expect("stats.users array")
        .iter()
        .find(|u| u["username"] == name)
        .unwrap_or_else(|| panic!("missing user {name} in stats: {stats}"))
}

async fn wait_for_stats<F>(client: &reqwest::Client, base_url: &str, pred: F) -> Value
where
    F: Fn(&Value) -> bool,
{
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let value = stats(client, base_url).await;
        if pred(&value) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for SSMAPI stats, last value: {value}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn add_user(client: &reqwest::Client, base_url: &str, name: &str, password: &str) {
    let resp = ssmapi_json(
        client,
        reqwest::Method::POST,
        format!("{base_url}/server-a/server/v1/users"),
        Some(json!({ "username": name, "uPSK": password })),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
}

fn stop_runtime(runtime: &Runtime) {
    for inbound in &runtime.bridge().inbounds {
        let _ = inbound.close();
    }
    for service in &runtime.bridge().services {
        let _ = service.close();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_shadowsocks_ssmapi_tcp_udp_stats_and_cache() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    sb_adapters::register_all();
    sb_api::services::register_all();

    let Some(ss_port) = reserve_loopback_port("shadowsocks") else {
        return;
    };
    let Some(api_port) = reserve_loopback_port("ssmapi") else {
        return;
    };
    let (tcp_echo, tcp_handle) = match start_tcp_echo().await {
        Ok(v) => v,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping ssmapi regression test: cannot bind TCP echo ({err})");
            return;
        }
        Err(err) => panic!("failed to start TCP echo: {err}"),
    };
    let (udp_echo, udp_handle) = match start_udp_echo().await {
        Ok(v) => v,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipping ssmapi regression test: cannot bind UDP echo ({err})");
            return;
        }
        Err(err) => panic!("failed to start UDP echo: {err}"),
    };

    let temp = TempDir::new().expect("tempdir");
    let cache_path = temp.path().join("ssmapi-cache.json");
    let ir = build_ir(ss_port, api_port, cache_path.to_string_lossy().to_string());
    let engine = Engine::new(Arc::new(ir.clone()));
    let bridge = build_bridge(&ir, engine.clone(), sb_core::context::Context::default());
    let switchboard = sb_core::runtime::switchboard::OutboundSwitchboard::new();
    let runtime = Runtime::new(engine, bridge, switchboard).start();

    let client = reqwest::Client::new();
    let api_base = format!("http://127.0.0.1:{api_port}");
    let ss_addr: SocketAddr = format!("127.0.0.1:{ss_port}").parse().unwrap();

    wait_for_api(&client, &api_base).await;
    wait_for_tcp(ss_addr).await;

    let unauth = client
        .get(format!("{api_base}/server-a/server/v1/users"))
        .send()
        .await
        .expect("unauth request");
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    add_user(&client, &api_base, "alice", "alice-pw").await;
    add_user(&client, &api_base, "bob", "bob-pw").await;

    let duplicate = ssmapi_json(
        &client,
        reqwest::Method::POST,
        format!("{api_base}/server-a/server/v1/users"),
        Some(json!({ "username": "alice", "uPSK": "alice-pw" })),
    )
    .await;
    assert_eq!(duplicate.status(), reqwest::StatusCode::BAD_REQUEST);

    let bad_json = client
        .post(format!("{api_base}/server-a/server/v1/users"))
        .bearer_auth(AUTH_TOKEN)
        .body("{bad-json")
        .send()
        .await
        .expect("bad json request");
    assert_eq!(bad_json.status(), reqwest::StatusCode::BAD_REQUEST);

    let missing_user = ssmapi_json(
        &client,
        reqwest::Method::GET,
        format!("{api_base}/server-a/server/v1/users/missing"),
        None,
    )
    .await;
    assert_eq!(missing_user.status(), reqwest::StatusCode::NOT_FOUND);

    let missing_endpoint = client
        .get(format!("{api_base}/missing/server/v1/users"))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("missing endpoint request");
    assert_eq!(missing_endpoint.status(), reqwest::StatusCode::NOT_FOUND);

    let tcp_session = Session::outbound(TargetAddr::from_host_port(
        tcp_echo.ip().to_string(),
        tcp_echo.port(),
    ));
    let mut tcp_stream = ss_connector(ss_addr, "alice-pw")
        .dial(&tcp_session)
        .await
        .expect("dial Shadowsocks TCP");
    let tcp_payload = b"ssmapi tcp regression";
    tcp_stream.write_all(tcp_payload).await.expect("tcp write");
    let mut tcp_back = vec![0u8; tcp_payload.len()];
    timeout(Duration::from_secs(5), tcp_stream.read_exact(&mut tcp_back))
        .await
        .expect("tcp read timeout")
        .expect("tcp read");
    assert_eq!(tcp_back, tcp_payload);

    let udp_target = TargetAddr::from_host_port(udp_echo.ip().to_string(), udp_echo.port());
    let udp_session = Session::outbound(udp_target.clone());
    let udp = ss_connector(ss_addr, "bob-pw")
        .udp_relay_dial(&udp_session)
        .await
        .expect("dial Shadowsocks UDP");
    let udp_payload = b"ssmapi udp regression";
    udp.send_to(udp_payload, &udp_target)
        .await
        .expect("udp send");
    let mut udp_back = [0u8; 256];
    let (n, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut udp_back))
        .await
        .expect("udp recv timeout")
        .expect("udp recv");
    assert_eq!(&udp_back[..n], udp_payload);

    let value = wait_for_stats(&client, &api_base, |value| {
        value["tcpSessions"].as_i64().unwrap_or_default() >= 1
            && value["udpSessions"].as_i64().unwrap_or_default() >= 1
            && user(value, "alice")["tcpSessions"]
                .as_i64()
                .unwrap_or_default()
                >= 1
            && user(value, "bob")["udpSessions"]
                .as_i64()
                .unwrap_or_default()
                >= 1
            && user(value, "alice")["uplinkBytes"]
                .as_i64()
                .unwrap_or_default()
                >= tcp_payload.len() as i64
            && user(value, "bob")["uplinkPackets"]
                .as_i64()
                .unwrap_or_default()
                >= 1
            && user(value, "bob")["downlinkPackets"]
                .as_i64()
                .unwrap_or_default()
                >= 1
    })
    .await;
    assert!(user(&value, "alice").get("uPSK").is_none());
    assert!(user(&value, "bob").get("uPSK").is_none());

    let update = ssmapi_json(
        &client,
        reqwest::Method::PUT,
        format!("{api_base}/server-a/server/v1/users/bob"),
        Some(json!({ "uPSK": "bob-new-pw" })),
    )
    .await;
    assert_eq!(update.status(), reqwest::StatusCode::NO_CONTENT);

    let delete = ssmapi_json(
        &client,
        reqwest::Method::DELETE,
        format!("{api_base}/server-a/server/v1/users/alice"),
        None,
    )
    .await;
    assert_eq!(delete.status(), reqwest::StatusCode::NO_CONTENT);

    stop_runtime(&runtime);

    let cache_json: Value = serde_json::from_slice(
        &std::fs::read(&cache_path).expect("SSMAPI cache should be written on close"),
    )
    .expect("cache JSON");
    assert!(cache_json["endpoints"]["/server-a"].is_object());
    assert_eq!(
        cache_json["endpoints"]["/server-a"]["users"]["bob"],
        Value::String("bob-new-pw".to_string())
    );

    tcp_handle.abort();
    udp_handle.abort();
}
