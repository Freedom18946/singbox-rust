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
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
                expect_status,
            } => {
                let url = harness.resolve_templates(url);
                let response = reqwest::Client::new().get(&url).send().await;
                match response {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        let success = expect_status.map(|s| s == status).unwrap_or(status < 400);
                        TrafficResult {
                            name: name.clone(),
                            success,
                            detail: json!({ "status": status, "url": url, "body": body }),
                        }
                    }
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({ "url": url, "error": err.to_string() }),
                    },
                }
            }
            TrafficAction::TcpRoundTrip {
                name,
                addr,
                payload,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let result = tcp_roundtrip(&addr, payload.as_bytes()).await;
                match result {
                    Ok(back) => TrafficResult {
                        name: name.clone(),
                        success: back == payload.as_bytes(),
                        detail: json!({ "addr": addr, "echo": String::from_utf8_lossy(&back) }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({ "addr": addr, "error": err.to_string() }),
                    },
                }
            }
            TrafficAction::UdpRoundTrip {
                name,
                addr,
                payload,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let result = udp_roundtrip(&addr, payload.as_bytes()).await;
                match result {
                    Ok(back) => TrafficResult {
                        name: name.clone(),
                        success: back == payload.as_bytes(),
                        detail: json!({ "addr": addr, "echo": String::from_utf8_lossy(&back) }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({ "addr": addr, "error": err.to_string() }),
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
