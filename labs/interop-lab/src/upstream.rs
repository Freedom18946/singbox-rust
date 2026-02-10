use crate::case_spec::{TrafficAction, UpstreamKind, UpstreamServiceSpec};
use crate::snapshot::TrafficResult;
use anyhow::{anyhow, Context, Result};
use axum::body::Bytes;
use axum::extract::ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::{Json, Router};
use futures_util::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

#[derive(Default)]
pub struct UpstreamHarness {
    pub endpoints: BTreeMap<String, String>,
    handles: Vec<UpstreamHandle>,
}

struct UpstreamHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl UpstreamHarness {
    pub async fn shutdown(mut self) {
        for handle in &mut self.handles {
            if let Some(tx) = handle.shutdown.take() {
                let _ = tx.send(());
            }
        }
        for handle in self.handles {
            let _ = handle.join.await;
        }
    }

    pub fn resolve_templates(&self, raw: &str) -> String {
        let mut out = raw.to_string();
        for (name, endpoint) in &self.endpoints {
            let key1 = format!("{{{{upstream.{name}}}}}");
            let key2 = format!("{{{{upstream.{name}.endpoint}}}}");
            let key3 = format!("{{{{upstream.{name}.addr}}}}");
            out = out.replace(&key1, endpoint);
            out = out.replace(&key2, endpoint);
            out = out.replace(&key3, endpoint);
        }
        out
    }
}

#[derive(Clone)]
struct HttpState {
    service_name: String,
}

pub async fn start_upstreams(specs: &[UpstreamServiceSpec]) -> Result<UpstreamHarness> {
    let mut harness = UpstreamHarness::default();

    for spec in specs {
        match spec.kind {
            UpstreamKind::HttpEcho => {
                let listener = TcpListener::bind(&spec.bind)
                    .await
                    .with_context(|| format!("binding http echo {}", spec.bind))?;
                let addr = listener.local_addr().with_context(|| "http local_addr")?;
                let state = HttpState {
                    service_name: spec.name.clone(),
                };
                let app = Router::new()
                    .route("/*path", any(http_echo))
                    .with_state(state);
                let (tx, rx) = oneshot::channel::<()>();
                let join = tokio::spawn(async move {
                    let shutdown = async move {
                        let _ = rx.await;
                    };
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown)
                        .await;
                });
                harness.endpoints.insert(
                    spec.name.clone(),
                    format!("http://{}:{}", addr.ip(), addr.port()),
                );
                harness.handles.push(UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                });
            }
            UpstreamKind::WsEcho => {
                let listener = TcpListener::bind(&spec.bind)
                    .await
                    .with_context(|| format!("binding ws echo {}", spec.bind))?;
                let addr = listener.local_addr().with_context(|| "ws local_addr")?;
                let app = Router::new().route("/", get(ws_echo));
                let (tx, rx) = oneshot::channel::<()>();
                let join = tokio::spawn(async move {
                    let shutdown = async move {
                        let _ = rx.await;
                    };
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown)
                        .await;
                });
                harness.endpoints.insert(
                    spec.name.clone(),
                    format!("ws://{}:{}/", addr.ip(), addr.port()),
                );
                harness.handles.push(UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                });
            }
            UpstreamKind::TcpEcho => {
                let listener = TcpListener::bind(&spec.bind)
                    .await
                    .with_context(|| format!("binding tcp echo {}", spec.bind))?;
                let addr = listener.local_addr().with_context(|| "tcp local_addr")?;
                let (tx, mut rx) = oneshot::channel::<()>();
                let join = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut rx => {
                                break;
                            }
                            accepted = listener.accept() => {
                                match accepted {
                                    Ok((mut stream, _)) => {
                                        tokio::spawn(async move {
                                            let mut buf = [0_u8; 2048];
                                            loop {
                                                match stream.read(&mut buf).await {
                                                    Ok(0) => break,
                                                    Ok(n) => {
                                                        if stream.write_all(&buf[..n]).await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });
                harness.endpoints.insert(
                    spec.name.clone(),
                    format!("tcp://{}:{}", addr.ip(), addr.port()),
                );
                harness.handles.push(UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                });
            }
            UpstreamKind::UdpEcho => {
                let socket = UdpSocket::bind(&spec.bind)
                    .await
                    .with_context(|| format!("binding udp echo {}", spec.bind))?;
                let addr = socket.local_addr().with_context(|| "udp local_addr")?;
                let (tx, mut rx) = oneshot::channel::<()>();
                let join = tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    loop {
                        tokio::select! {
                            _ = &mut rx => {
                                break;
                            }
                            recv = socket.recv_from(&mut buf) => {
                                if let Ok((n, peer)) = recv {
                                    let _ = socket.send_to(&buf[..n], peer).await;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                });
                harness.endpoints.insert(
                    spec.name.clone(),
                    format!("udp://{}:{}", addr.ip(), addr.port()),
                );
                harness.handles.push(UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                });
            }
            UpstreamKind::DnsStub => {
                let socket = UdpSocket::bind(&spec.bind)
                    .await
                    .with_context(|| format!("binding dns stub {}", spec.bind))?;
                let addr = socket.local_addr().with_context(|| "dns local_addr")?;
                let (tx, mut rx) = oneshot::channel::<()>();
                let join = tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    loop {
                        tokio::select! {
                            _ = &mut rx => {
                                break;
                            }
                            recv = socket.recv_from(&mut buf) => {
                                match recv {
                                    Ok((n, peer)) => {
                                        let data = &buf[..n];
                                        if let Ok(req) = Message::from_vec(data) {
                                            let mut resp = Message::new();
                                            resp.set_id(req.id());
                                            resp.set_message_type(MessageType::Response);
                                            resp.set_op_code(req.op_code());
                                            resp.set_recursion_desired(req.recursion_desired());
                                            resp.set_recursion_available(true);
                                            resp.set_authoritative(false);
                                            resp.set_response_code(ResponseCode::NoError);
                                            for q in req.queries() {
                                                resp.add_query(q.clone());
                                            }
                                            let mut encoded = Vec::with_capacity(256);
                                            let mut encoder = BinEncoder::new(&mut encoded);
                                            if resp.emit(&mut encoder).is_ok() {
                                                let _ = socket.send_to(&encoded, peer).await;
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });
                harness.endpoints.insert(
                    spec.name.clone(),
                    format!("udp://{}:{}", addr.ip(), addr.port()),
                );
                harness.handles.push(UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                });
            }
            UpstreamKind::TlsEcho => {
                let listener = TcpListener::bind(&spec.bind)
                    .await
                    .with_context(|| format!("binding tls echo {}", spec.bind))?;
                let addr = listener.local_addr().with_context(|| "tls local_addr")?;

                let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                    .with_context(|| "generating self-signed cert")?;
                let cert_der = cert.serialize_der().with_context(|| "serializing cert")?;
                let key_der = cert.serialize_private_key_der();

                let cert_chain = vec![CertificateDer::from(cert_der)];
                let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
                let config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(cert_chain, key)
                    .with_context(|| "building tls server config")?;
                let acceptor = TlsAcceptor::from(Arc::new(config));

                let (tx, mut rx) = oneshot::channel::<()>();
                let join = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut rx => {
                                break;
                            }
                            accepted = listener.accept() => {
                                match accepted {
                                    Ok((stream, _)) => {
                                        let acceptor = acceptor.clone();
                                        tokio::spawn(async move {
                                            if let Ok(mut tls) = acceptor.accept(stream).await {
                                                let mut buf = [0_u8; 2048];
                                                loop {
                                                    match tls.read(&mut buf).await {
                                                        Ok(0) => break,
                                                        Ok(n) => {
                                                            if tls.write_all(&buf[..n]).await.is_err() {
                                                                break;
                                                            }
                                                        }
                                                        Err(_) => break,
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });

                harness.endpoints.insert(
                    spec.name.clone(),
                    format!("tls://{}:{}", addr.ip(), addr.port()),
                );
                harness.handles.push(UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                });
            }
        }
    }

    Ok(harness)
}

pub async fn run_traffic_plan(
    harness: &UpstreamHarness,
    actions: &[TrafficAction],
) -> Result<Vec<TrafficResult>> {
    let mut out = Vec::with_capacity(actions.len());

    for action in actions {
        let result = match action {
            TrafficAction::HttpGet {
                name,
                url,
                proxy,
                expect_status,
            } => {
                let url = harness.resolve_templates(url);
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let response = if let Some(proxy) = resolved_proxy.as_deref() {
                    http_get_via_curl(&url, Some(proxy)).await
                } else {
                    http_get_via_reqwest(&url).await
                };
                match response {
                    Ok((status, body)) => {
                        let success = expect_status.map(|s| s == status).unwrap_or(status < 400);
                        TrafficResult {
                            name: name.clone(),
                            success,
                            detail: json!({
                                "status": status,
                                "url": url,
                                "proxy": resolved_proxy,
                                "body": body
                            }),
                        }
                    }
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "url": url,
                            "proxy": resolved_proxy,
                            "error": err.to_string()
                        }),
                    },
                }
            }
            TrafficAction::TcpRoundTrip {
                name,
                addr,
                payload,
                proxy,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let result = if let Some(proxy) = resolved_proxy.as_deref() {
                    tcp_roundtrip_via_proxy(proxy, &addr, payload.as_bytes()).await
                } else {
                    tcp_roundtrip(&addr, payload.as_bytes()).await
                };
                match result {
                    Ok(back) => TrafficResult {
                        name: name.clone(),
                        success: back == payload.as_bytes(),
                        detail: json!({
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "echo": String::from_utf8_lossy(&back)
                        }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "error": err.to_string()
                        }),
                    },
                }
            }
            TrafficAction::UdpRoundTrip {
                name,
                addr,
                payload,
                proxy,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let result = if let Some(proxy) = resolved_proxy.as_deref() {
                    udp_roundtrip_via_proxy(proxy, &addr, payload.as_bytes()).await
                } else {
                    udp_roundtrip(&addr, payload.as_bytes()).await
                };
                match result {
                    Ok(back) => TrafficResult {
                        name: name.clone(),
                        success: back == payload.as_bytes(),
                        detail: json!({
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "echo": String::from_utf8_lossy(&back)
                        }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "error": err.to_string()
                        }),
                    },
                }
            }
            TrafficAction::DnsQuery { name, addr, qname } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let result = dns_query(&addr, qname).await;
                match result {
                    Ok(detail) => TrafficResult {
                        name: name.clone(),
                        success: true,
                        detail,
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({ "addr": addr, "error": err.to_string() }),
                    },
                }
            }
        };

        out.push(result);
    }

    Ok(out)
}

async fn http_get_via_reqwest(url: &str) -> Result<(u16, String)> {
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .with_context(|| format!("http get {url}"))?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Ok((status, body))
}

async fn http_get_via_curl(url: &str, proxy: Option<&str>) -> Result<(u16, String)> {
    let marker = "__INTEROP_STATUS__:";
    let mut cmd = Command::new("curl");
    cmd.arg("-sS").arg("-L").arg("--max-time").arg("12");

    if let Some(proxy) = proxy {
        if proxy.starts_with("socks5://") {
            let addr = proxy.trim_start_matches("socks5://");
            cmd.arg("--socks5-hostname").arg(addr);
        } else if proxy.starts_with("socks5h://") {
            let addr = proxy.trim_start_matches("socks5h://");
            cmd.arg("--socks5-hostname").arg(addr);
        } else {
            cmd.arg("-x").arg(proxy);
        }
    }

    cmd.arg("-w").arg(format!("\n{marker}%{{http_code}}"));
    cmd.arg(url);

    let output = cmd
        .output()
        .await
        .with_context(|| format!("running curl for {url}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(anyhow!(
            "curl failed status={} stderr={}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8(output.stdout).with_context(|| "curl stdout non-utf8")?;
    let idx = stdout
        .rfind(marker)
        .ok_or_else(|| anyhow!("curl output missing status marker"))?;
    let body = stdout[..idx].trim_end_matches('\n').to_string();
    let status_raw = stdout[idx + marker.len()..].trim();
    let status = status_raw
        .parse::<u16>()
        .with_context(|| format!("invalid curl http status: {status_raw}"))?;
    Ok((status, body))
}

async fn http_echo(
    State(state): State<HttpState>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> impl IntoResponse {
    let payload = json!({
        "service": state.service_name,
        "method": method.to_string(),
        "path": uri.path(),
        "query": uri.query(),
        "body_len": body.len(),
    });
    (StatusCode::OK, Json(payload))
}

async fn ws_echo(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_ws)
}

async fn handle_ws(mut socket: WebSocket) {
    let _ = socket
        .send(AxumWsMessage::Text("{\"event\":\"ready\"}".to_string()))
        .await;

    while let Some(next) = socket.next().await {
        match next {
            Ok(AxumWsMessage::Text(text)) => {
                let _ = socket.send(AxumWsMessage::Text(text)).await;
            }
            Ok(AxumWsMessage::Binary(data)) => {
                let _ = socket.send(AxumWsMessage::Binary(data)).await;
            }
            Ok(AxumWsMessage::Close(_)) => break,
            Ok(AxumWsMessage::Ping(v)) => {
                let _ = socket.send(AxumWsMessage::Pong(v)).await;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

fn normalize_addr(input: &str) -> String {
    input
        .trim_start_matches("tcp://")
        .trim_start_matches("udp://")
        .trim_start_matches("tls://")
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

async fn tcp_roundtrip(addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting tcp {addr}"))?;
    stream
        .write_all(payload)
        .await
        .with_context(|| format!("tcp write {addr}"))?;
    let mut buf = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut buf)
        .await
        .with_context(|| format!("tcp read {addr}"))?;
    Ok(buf)
}

async fn tcp_roundtrip_via_proxy(proxy: &str, addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    if proxy.starts_with("socks5://") || proxy.starts_with("socks5h://") {
        let proxy_addr = normalize_addr(
            proxy
                .trim_start_matches("socks5://")
                .trim_start_matches("socks5h://"),
        );
        return tcp_roundtrip_via_socks5(&proxy_addr, addr, payload).await;
    }

    Err(anyhow!("unsupported tcp proxy scheme: {proxy}"))
}

async fn tcp_roundtrip_via_socks5(proxy_addr: &str, target_addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("connecting socks5 proxy {proxy_addr}"))?;

    // greeting: SOCKS5 + 1 auth method + no-auth
    stream
        .write_all(&[0x05_u8, 0x01, 0x00])
        .await
        .with_context(|| "writing socks5 greeting")?;
    let mut greeting_resp = [0_u8; 2];
    stream
        .read_exact(&mut greeting_resp)
        .await
        .with_context(|| "reading socks5 greeting response")?;
    if greeting_resp != [0x05, 0x00] {
        return Err(anyhow!(
            "socks5 greeting rejected: version={} method={}",
            greeting_resp[0],
            greeting_resp[1]
        ));
    }

    let (host, port) = parse_host_port(target_addr)?;
    let mut req = vec![0x05_u8, 0x01, 0x00]; // v5, connect, reserved
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host_bytes = host.as_bytes();
            if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize {
                return Err(anyhow!("invalid socks5 domain target: {host}"));
            }
            req.push(0x03);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
        }
    }
    req.extend_from_slice(&port.to_be_bytes());

    stream
        .write_all(&req)
        .await
        .with_context(|| format!("writing socks5 connect request for {target_addr}"))?;

    let mut resp_head = [0_u8; 4];
    stream
        .read_exact(&mut resp_head)
        .await
        .with_context(|| "reading socks5 connect response header")?;
    if resp_head[0] != 0x05 {
        return Err(anyhow!("invalid socks5 response version: {}", resp_head[0]));
    }
    if resp_head[1] != 0x00 {
        return Err(anyhow!("socks5 connect rejected with code: {}", resp_head[1]));
    }

    match resp_head[3] {
        0x01 => {
            let mut buf = [0_u8; 4 + 2];
            stream
                .read_exact(&mut buf)
                .await
                .with_context(|| "reading socks5 ipv4 bind address")?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .with_context(|| "reading socks5 domain bind length")?;
            let mut buf = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut buf)
                .await
                .with_context(|| "reading socks5 domain bind address")?;
        }
        0x04 => {
            let mut buf = [0_u8; 16 + 2];
            stream
                .read_exact(&mut buf)
                .await
                .with_context(|| "reading socks5 ipv6 bind address")?;
        }
        atyp => {
            return Err(anyhow!("unknown socks5 bind atyp: {atyp}"));
        }
    }

    stream
        .write_all(payload)
        .await
        .with_context(|| format!("writing payload via socks5 to {target_addr}"))?;
    let mut buf = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut buf)
        .await
        .with_context(|| format!("reading payload via socks5 from {target_addr}"))?;
    Ok(buf)
}

fn parse_host_port(addr: &str) -> Result<(String, u16)> {
    if let Ok(v4) = addr.parse::<std::net::SocketAddrV4>() {
        return Ok((v4.ip().to_string(), v4.port()));
    }
    if let Ok(v6) = addr.parse::<std::net::SocketAddrV6>() {
        return Ok((v6.ip().to_string(), v6.port()));
    }

    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port_part)) = rest.split_once("]:") {
            let port = port_part
                .parse::<u16>()
                .with_context(|| format!("invalid port in address: {addr}"))?;
            return Ok((host.to_string(), port));
        }
    }

    if let Some((host, port_part)) = addr.rsplit_once(':') {
        let port = port_part
            .parse::<u16>()
            .with_context(|| format!("invalid port in address: {addr}"))?;
        return Ok((host.to_string(), port));
    }

    Err(anyhow!("invalid host:port address: {addr}"))
}

async fn udp_roundtrip(addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .with_context(|| "binding udp client")?;
    socket
        .send_to(payload, addr)
        .await
        .with_context(|| format!("udp send {addr}"))?;
    let mut buf = [0_u8; 4096];
    let (n, _peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| anyhow!("udp recv timeout from {addr}"))?
    .with_context(|| format!("udp recv {addr}"))?;
    Ok(buf[..n].to_vec())
}

async fn udp_roundtrip_via_proxy(proxy: &str, addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    if proxy.starts_with("socks5://") || proxy.starts_with("socks5h://") {
        let proxy_addr = normalize_addr(
            proxy
                .trim_start_matches("socks5://")
                .trim_start_matches("socks5h://"),
        );
        return udp_roundtrip_via_socks5(&proxy_addr, addr, payload).await;
    }

    Err(anyhow!("unsupported udp proxy scheme: {proxy}"))
}

async fn udp_roundtrip_via_socks5(proxy_addr: &str, target_addr: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let mut control = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("connecting socks5 proxy {proxy_addr}"))?;

    // greeting: SOCKS5 + 1 auth method + no-auth
    control
        .write_all(&[0x05_u8, 0x01, 0x00])
        .await
        .with_context(|| "writing socks5 greeting")?;
    let mut greeting_resp = [0_u8; 2];
    control
        .read_exact(&mut greeting_resp)
        .await
        .with_context(|| "reading socks5 greeting response")?;
    if greeting_resp != [0x05, 0x00] {
        return Err(anyhow!(
            "socks5 greeting rejected: version={} method={}",
            greeting_resp[0],
            greeting_resp[1]
        ));
    }

    // UDP ASSOCIATE command.
    control
        .write_all(&[0x05_u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .with_context(|| "writing socks5 udp associate request")?;

    let mut resp_head = [0_u8; 4];
    control
        .read_exact(&mut resp_head)
        .await
        .with_context(|| "reading socks5 udp associate response header")?;
    if resp_head[0] != 0x05 {
        return Err(anyhow!("invalid socks5 response version: {}", resp_head[0]));
    }
    if resp_head[1] != 0x00 {
        return Err(anyhow!(
            "socks5 udp associate rejected with code: {}",
            resp_head[1]
        ));
    }

    let (bind_host, bind_port) = read_socks5_addr_port(&mut control, resp_head[3]).await?;
    let (proxy_host, _) = parse_host_port(proxy_addr)?;
    let relay_host = if bind_host == "0.0.0.0" || bind_host == "::" {
        proxy_host
    } else {
        bind_host
    };
    let relay_addr = format_host_port(&relay_host, bind_port);

    let (target_host, target_port) = parse_host_port(target_addr)?;
    let mut packet = vec![0x00_u8, 0x00, 0x00]; // RSV + FRAG
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            packet.push(0x01);
            packet.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            packet.push(0x04);
            packet.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host_bytes = target_host.as_bytes();
            if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize {
                return Err(anyhow!("invalid socks5 domain target: {target_host}"));
            }
            packet.push(0x03);
            packet.push(host_bytes.len() as u8);
            packet.extend_from_slice(host_bytes);
        }
    }
    packet.extend_from_slice(&target_port.to_be_bytes());
    packet.extend_from_slice(payload);

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .with_context(|| "binding udp client")?;
    socket
        .send_to(&packet, &relay_addr)
        .await
        .with_context(|| format!("sending udp packet to socks relay {relay_addr}"))?;

    let mut recv_buf = [0_u8; 4096];
    let (n, _peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut recv_buf),
    )
    .await
    .map_err(|_| anyhow!("udp recv timeout from socks relay {relay_addr}"))?
    .with_context(|| format!("udp recv from socks relay {relay_addr}"))?;
    let pkt = &recv_buf[..n];
    if pkt.len() < 4 {
        return Err(anyhow!("socks udp response too short"));
    }
    if pkt[0] != 0x00 || pkt[1] != 0x00 || pkt[2] != 0x00 {
        return Err(anyhow!("invalid socks udp header"));
    }

    let data_offset = match pkt[3] {
        0x01 => 4 + 4 + 2,
        0x04 => 4 + 16 + 2,
        0x03 => {
            if pkt.len() < 5 {
                return Err(anyhow!("invalid socks udp domain header"));
            }
            4 + 1 + (pkt[4] as usize) + 2
        }
        atyp => return Err(anyhow!("unknown socks udp atyp: {atyp}")),
    };
    if pkt.len() < data_offset {
        return Err(anyhow!("invalid socks udp packet length"));
    }

    Ok(pkt[data_offset..].to_vec())
}

async fn read_socks5_addr_port(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16)> {
    match atyp {
        0x01 => {
            let mut ip = [0_u8; 4];
            let mut port = [0_u8; 2];
            stream
                .read_exact(&mut ip)
                .await
                .with_context(|| "reading socks5 ipv4 address")?;
            stream
                .read_exact(&mut port)
                .await
                .with_context(|| "reading socks5 ipv4 port")?;
            Ok((
                format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
                u16::from_be_bytes(port),
            ))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .with_context(|| "reading socks5 domain length")?;
            let mut host = vec![0_u8; len[0] as usize];
            let mut port = [0_u8; 2];
            stream
                .read_exact(&mut host)
                .await
                .with_context(|| "reading socks5 domain address")?;
            stream
                .read_exact(&mut port)
                .await
                .with_context(|| "reading socks5 domain port")?;
            Ok((
                String::from_utf8(host).with_context(|| "socks5 domain is not utf8")?,
                u16::from_be_bytes(port),
            ))
        }
        0x04 => {
            let mut ip = [0_u8; 16];
            let mut port = [0_u8; 2];
            stream
                .read_exact(&mut ip)
                .await
                .with_context(|| "reading socks5 ipv6 address")?;
            stream
                .read_exact(&mut port)
                .await
                .with_context(|| "reading socks5 ipv6 port")?;
            Ok((std::net::Ipv6Addr::from(ip).to_string(), u16::from_be_bytes(port)))
        }
        _ => Err(anyhow!("unknown socks5 atyp: {atyp}")),
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn dns_query(addr: &str, qname: &str) -> Result<serde_json::Value> {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .with_context(|| "binding dns client")?;

    let mut message = Message::new();
    message.set_id(0x1234);
    message.set_op_code(OpCode::Query);
    message.set_message_type(MessageType::Query);
    message.set_recursion_desired(true);

    let name = Name::from_ascii(qname).with_context(|| format!("invalid dns name {qname}"))?;
    message.add_query(Query::query(name, RecordType::A));

    let mut encoded = Vec::with_capacity(512);
    message
        .emit(&mut BinEncoder::new(&mut encoded))
        .with_context(|| "encoding dns query")?;

    socket
        .send_to(&encoded, addr)
        .await
        .with_context(|| format!("sending dns query to {addr}"))?;

    let mut buf = [0_u8; 2048];
    let (n, _peer) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| anyhow!("dns recv timeout from {addr}"))?
    .with_context(|| format!("receiving dns response from {addr}"))?;

    let decoded = Message::from_vec(&buf[..n]).with_context(|| "decoding dns response")?;
    Ok(json!({
        "id": decoded.id(),
        "message_type": format!("{:?}", decoded.message_type()),
        "rcode": format!("{:?}", decoded.response_code()),
        "answers": decoded.answers().len(),
    }))
}
