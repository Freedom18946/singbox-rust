use crate::case_spec::{FaultSpec, TrafficAction, UpstreamKind, UpstreamServiceSpec};
use crate::snapshot::TrafficResult;
use crate::util::{percentile_us, resolve_command_with_fallback, resolve_with_env, sha256_hex};
use anyhow::{anyhow, Context, Result};
use axum::body::Bytes;
use axum::extract::ws::{Message as AxumWsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::{Json, Router};
use futures_util::StreamExt;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sb_adapters::inbound::shadowsocks::{serve as serve_shadowsocks, ShadowsocksInboundConfig};
use sb_adapters::inbound::shadowtls::{serve as serve_shadowtls, ShadowTlsInboundConfig};
use sb_adapters::inbound::trojan::{serve as serve_trojan, TrojanInboundConfig};
use sb_adapters::inbound::vless::{serve as serve_vless, VlessInboundConfig};
use sb_adapters::inbound::vmess::{serve as serve_vmess, VmessInboundConfig};
use sb_common::conntrack::ConnTracker;
use sb_core::router::engine::RouterHandle;
use sb_core::router::rules::{
    install_global as install_global_rules, parse_rules, RuleEngine as Engine,
};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Once;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::{oneshot, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_rustls::TlsAcceptor;

const TCP_ROUNDTRIP_TIMEOUT_MS: u64 = 10_000;

// --- Test harness constants (NOT production credentials) ---
const INTEROP_PASSWORD: &str = "interop-password";
const INTEROP_VLESS_UUID: &str = "00000000-0000-0000-0000-000000000001";
const INTEROP_VMESS_UUID: &str = "00000000-0000-0000-0000-000000000002";
const INTEROP_CERT_PATH: &str = "vendor/anytls-rs/examples/singbox/certs/anytls.local.crt.fixture";
const INTEROP_KEY_PATH: &str = "vendor/anytls-rs/examples/singbox/certs/anytls.local.key.fixture";

static PROTOCOL_UPSTREAM_RULES_INIT: Once = Once::new();

fn ensure_protocol_upstream_rules() {
    PROTOCOL_UPSTREAM_RULES_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rules = parse_rules("default=direct");
        install_global_rules(Engine::build(rules));
    });
}

fn new_conn_tracker() -> Arc<ConnTracker> {
    Arc::new(ConnTracker::new())
}

async fn copy_until_handshake_finished<R, W>(dst: &mut W, src: &mut R) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const TLS_HEADER_SIZE: usize = 5;
    const HANDSHAKE: u8 = 22;
    const CHANGE_CIPHER_SPEC: u8 = 20;

    let mut seen_change_cipher_spec = false;
    let mut header = [0u8; TLS_HEADER_SIZE];
    loop {
        src.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        dst.write_all(&header).await?;
        let mut payload = vec![0u8; length];
        src.read_exact(&mut payload).await?;
        dst.write_all(&payload).await?;
        if header[0] != HANDSHAKE {
            if header[0] != CHANGE_CIPHER_SPEC {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unexpected tls frame type: {}", header[0]),
                ));
            }
            if !seen_change_cipher_spec {
                seen_change_cipher_spec = true;
                continue;
            }
        }
        if seen_change_cipher_spec {
            dst.flush().await?;
            return Ok(());
        }
    }
}

#[derive(Default)]
pub struct UpstreamHarness {
    pub endpoints: BTreeMap<String, String>,
    specs: BTreeMap<String, UpstreamServiceSpec>,
    service_delays_ms: Arc<RwLock<BTreeMap<String, u64>>>,
    dns_query_counts: Arc<RwLock<BTreeMap<String, u64>>>,
    handles: BTreeMap<String, UpstreamHandle>,
}

struct UpstreamHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

fn signal_upstream_shutdown(tx: oneshot::Sender<()>, context: &str) {
    if tx.send(()).is_err() {
        tracing::debug!(%context, "upstream shutdown signal skipped: receiver already closed");
    }
}

async fn await_upstream_join(join: JoinHandle<()>, context: &str) {
    match tokio::time::timeout(Duration::from_secs(5), join).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(%context, error = %err, "upstream task join failed");
        }
        Err(_) => {
            tracing::warn!(%context, "upstream task join timed out");
        }
    }
}

impl UpstreamHarness {
    pub async fn shutdown(mut self) {
        for handle in self.handles.values_mut() {
            if let Some(tx) = handle.shutdown.take() {
                signal_upstream_shutdown(tx, "harness shutdown");
            }
        }
        for (_name, handle) in self.handles {
            await_upstream_join(handle.join, "harness shutdown").await;
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

    pub async fn set_service_delay(&self, target: &str, delay_ms: u64) {
        let mut map = self.service_delays_ms.write().await;
        if delay_ms == 0 {
            map.remove(target);
        } else {
            map.insert(target.to_string(), delay_ms);
        }
    }

    fn insert_handle(&mut self, name: String, handle: UpstreamHandle) {
        self.handles.insert(name, handle);
    }

    pub async fn disconnect_target(&mut self, target: &str) -> Result<()> {
        let mut handle = self
            .handles
            .remove(target)
            .ok_or_else(|| anyhow!("fault disconnect target not found: {target}"))?;
        if let Some(tx) = handle.shutdown.take() {
            signal_upstream_shutdown(tx, "disconnect target");
        }
        if let Err(err) = handle.join.await {
            tracing::warn!(target = %target, error = %err, "upstream disconnect join failed");
        }
        Ok(())
    }

    pub async fn reconnect_target(&mut self, target: &str) -> Result<()> {
        if let Some(mut existing) = self.handles.remove(target) {
            if let Some(tx) = existing.shutdown.take() {
                signal_upstream_shutdown(tx, "reconnect target");
            }
            if let Err(err) = existing.join.await {
                tracing::warn!(target = %target, error = %err, "upstream reconnect join failed");
            }
        }
        let spec = self
            .specs
            .get(target)
            .cloned()
            .ok_or_else(|| anyhow!("fault reconnect target not found: {target}"))?;
        start_single_upstream(self, &spec).await
    }

    pub async fn dns_query_count(&self, target: &str) -> Option<u64> {
        let map = self.dns_query_counts.read().await;
        map.get(target).copied()
    }
}

#[derive(Clone)]
struct HttpState {
    service_name: String,
    delays_ms: Arc<RwLock<BTreeMap<String, u64>>>,
}

#[derive(Clone)]
struct HttpStaticState {
    service_name: String,
    delays_ms: Arc<RwLock<BTreeMap<String, u64>>>,
    body: Bytes,
    content_type: HeaderValue,
}

#[derive(Clone)]
struct WsState {
    service_name: String,
    delays_ms: Arc<RwLock<BTreeMap<String, u64>>>,
}

pub async fn start_upstreams(specs: &[UpstreamServiceSpec]) -> Result<UpstreamHarness> {
    let mut harness = UpstreamHarness::default();

    for spec in specs {
        harness.specs.insert(spec.name.clone(), spec.clone());
        start_single_upstream(&mut harness, spec).await?;
    }

    Ok(harness)
}

async fn start_single_upstream(
    harness: &mut UpstreamHarness,
    spec: &UpstreamServiceSpec,
) -> Result<()> {
    match spec.kind {
        UpstreamKind::HttpEcho => {
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding http echo {}", spec.bind))?;
            let addr = listener.local_addr().with_context(|| "http local_addr")?;
            let state = HttpState {
                service_name: spec.name.clone(),
                delays_ms: harness.service_delays_ms.clone(),
            };
            let app = Router::new()
                .route("/", any(http_echo))
                .route("/*path", any(http_echo))
                .with_state(state);
            let (tx, rx) = oneshot::channel::<()>();
            let join = tokio::spawn(async move {
                let shutdown = async move {
                    if rx.await.is_err() {
                        tracing::debug!("http echo shutdown channel closed before signal");
                    }
                };
                if let Err(err) = axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
                {
                    tracing::warn!(error = %err, "http echo upstream serve failed");
                }
            });
            harness.endpoints.insert(
                spec.name.clone(),
                format!("http://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::HttpStatic => {
            let content_path = spec.content_path.as_ref().ok_or_else(|| {
                anyhow!("http_static upstream {} requires content_path", spec.name)
            })?;
            let body = tokio::fs::read(content_path)
                .await
                .with_context(|| format!("reading static response {}", content_path.display()))?;
            let content_type = HeaderValue::from_str(
                spec.content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream"),
            )
            .with_context(|| format!("invalid content_type for {}", spec.name))?;
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding http static {}", spec.bind))?;
            let addr = listener
                .local_addr()
                .with_context(|| "http static local_addr")?;
            let state = HttpStaticState {
                service_name: spec.name.clone(),
                delays_ms: harness.service_delays_ms.clone(),
                body: Bytes::from(body),
                content_type,
            };
            let app = Router::new()
                .route("/", get(http_static))
                .route("/*path", get(http_static))
                .with_state(state);
            let (tx, rx) = oneshot::channel::<()>();
            let join = tokio::spawn(async move {
                let shutdown = async move {
                    if rx.await.is_err() {
                        tracing::debug!("http static shutdown channel closed before signal");
                    }
                };
                if let Err(err) = axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
                {
                    tracing::warn!(error = %err, "http static upstream serve failed");
                }
            });
            harness.endpoints.insert(
                spec.name.clone(),
                format!("http://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::WsEcho => {
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding ws echo {}", spec.bind))?;
            let addr = listener.local_addr().with_context(|| "ws local_addr")?;
            let state = WsState {
                service_name: spec.name.clone(),
                delays_ms: harness.service_delays_ms.clone(),
            };
            let app = Router::new().route("/", get(ws_echo)).with_state(state);
            let (tx, rx) = oneshot::channel::<()>();
            let join = tokio::spawn(async move {
                let shutdown = async move {
                    if rx.await.is_err() {
                        tracing::debug!("ws echo shutdown channel closed before signal");
                    }
                };
                if let Err(err) = axum::serve(listener, app)
                    .with_graceful_shutdown(shutdown)
                    .await
                {
                    tracing::warn!(error = %err, "ws echo upstream serve failed");
                }
            });
            harness.endpoints.insert(
                spec.name.clone(),
                format!("ws://{}:{}/", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::TcpEcho => {
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding tcp echo {}", spec.bind))?;
            let addr = listener.local_addr().with_context(|| "tcp local_addr")?;
            let service_name = spec.name.clone();
            let delays = harness.service_delays_ms.clone();
            let semaphore = Arc::new(Semaphore::new(1024));
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
                                    let delays = delays.clone();
                                    let svc = service_name.clone();
                                    let sem = semaphore.clone();
                                    tokio::spawn(async move {
                                        let _permit = match sem.acquire().await {
                                            Ok(p) => p,
                                            Err(_) => return,
                                        };
                                        let mut buf = vec![0_u8; 256 * 1024]; // 256KB for large payload support
                                        loop {
                                            match stream.read(&mut buf).await {
                                                Ok(0) => break,
                                                Ok(n) => {
                                                    let delay_ms = service_delay(&delays, &svc).await;
                                                    if delay_ms > 0 {
                                                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                                    }
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
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::UdpEcho => {
            let socket = UdpSocket::bind(&spec.bind)
                .await
                .with_context(|| format!("binding udp echo {}", spec.bind))?;
            let addr = socket.local_addr().with_context(|| "udp local_addr")?;
            let service_name = spec.name.clone();
            let delays = harness.service_delays_ms.clone();
            let (tx, mut rx) = oneshot::channel::<()>();
            let join = tokio::spawn(async move {
                let mut buf = [0_u8; 65536]; // 64KB for large UDP payload support
                loop {
                    tokio::select! {
                        _ = &mut rx => {
                            break;
                        }
                        recv = socket.recv_from(&mut buf) => {
                            if let Ok((n, peer)) = recv {
                                let delay_ms = service_delay(&delays, &service_name).await;
                                if delay_ms > 0 {
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
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
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::DnsStub => {
            let socket = UdpSocket::bind(&spec.bind)
                .await
                .with_context(|| format!("binding dns stub {}", spec.bind))?;
            let addr = socket.local_addr().with_context(|| "dns local_addr")?;
            let service_name = spec.name.clone();
            let delays = harness.service_delays_ms.clone();
            let counts = harness.dns_query_counts.clone();
            let answer_ipv4 = spec
                .answer_ipv4
                .as_deref()
                .unwrap_or("198.51.100.1")
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid dns stub answer_ipv4 for {}", spec.name))?;
            let ttl_secs = spec.ttl_secs.unwrap_or(300);
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
                                        {
                                            let mut map = counts.write().await;
                                            let entry = map.entry(service_name.clone()).or_insert(0);
                                            *entry = entry.saturating_add(1);
                                        }
                                        let delay_ms = service_delay(&delays, &service_name).await;
                                        if delay_ms > 0 {
                                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                        }
                                        let mut resp = Message::new(
                                            req.metadata.id,
                                            MessageType::Response,
                                            req.metadata.op_code,
                                        );
                                        resp.metadata.recursion_desired =
                                            req.metadata.recursion_desired;
                                        resp.metadata.recursion_available = true;
                                        resp.metadata.authoritative = false;
                                        resp.metadata.response_code = ResponseCode::NoError;
                                        for q in &req.queries {
                                            resp.add_query(q.clone());
                                            // Add synthetic A record (TEST-NET-2, RFC 5737)
                                            if q.query_type() == RecordType::A {
                                                resp.add_answer(Record::from_rdata(
                                                    q.name().clone(),
                                                    ttl_secs,
                                                    RData::A(hickory_proto::rr::rdata::A(
                                                        answer_ipv4,
                                                    )),
                                                ));
                                            }
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
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
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

            let service_name = spec.name.clone();
            let delays = harness.service_delays_ms.clone();
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
                                    let delays = delays.clone();
                                    let svc = service_name.clone();
                                    tokio::spawn(async move {
                                        if let Ok(mut tls) = acceptor.accept(stream).await {
                                            let mut buf = vec![0_u8; 256 * 1024]; // 256KB, matching TcpEcho
                                            loop {
                                                match tls.read(&mut buf).await {
                                                    Ok(0) => break,
                                                    Ok(n) => {
                                                        let delay_ms = service_delay(&delays, &svc).await;
                                                        if delay_ms > 0 {
                                                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                                        }
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
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::TlsRelayTcp => {
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding tls relay {}", spec.bind))?;
            let addr = listener
                .local_addr()
                .with_context(|| "tls relay local_addr")?;

            let target = spec
                .target
                .as_ref()
                .map(|v| normalize_addr(&harness.resolve_templates(v)))
                .ok_or_else(|| anyhow!("tls relay upstream '{}' missing target", spec.name))?;
            let handshake_target = spec
                .handshake_target
                .as_ref()
                .map(|v| normalize_addr(&harness.resolve_templates(v)))
                .ok_or_else(|| {
                    anyhow!(
                        "tls relay upstream '{}' missing handshake_target",
                        spec.name
                    )
                })?;

            let (tx, mut rx) = oneshot::channel::<()>();
            let join = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut rx => {
                            break;
                        }
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((mut client, _)) => {
                                    let target = target.clone();
                                    let handshake_target = handshake_target.clone();
                                    tokio::spawn(async move {
                                        let mut handshake = match TcpStream::connect(&handshake_target).await {
                                            Ok(stream) => stream,
                                            Err(_) => return,
                                        };
                                        {
                                            let (mut client_read, mut client_write) = client.split();
                                            let (mut handshake_read, mut handshake_write) = handshake.split();
                                            if tokio::try_join!(
                                                copy_until_handshake_finished(&mut handshake_write, &mut client_read),
                                                copy_until_handshake_finished(&mut client_write, &mut handshake_read),
                                            )
                                            .is_err()
                                            {
                                                return;
                                            }
                                        }
                                        drop(handshake);

                                        let mut upstream = match TcpStream::connect(&target).await {
                                            Ok(stream) => stream,
                                            Err(_) => return,
                                        };
                                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
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
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::TrojanInbound => {
            ensure_protocol_upstream_rules();
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding trojan upstream {}", spec.bind))?;
            let addr = listener.local_addr().with_context(|| "trojan local_addr")?;
            drop(listener);

            let router = std::sync::Arc::new(RouterHandle::new_mock());
            let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
            let (tx, mut rx) = oneshot::channel::<()>();

            let cfg = TrojanInboundConfig {
                listen: addr,
                #[allow(deprecated)]
                password: Some(INTEROP_PASSWORD.to_string()),
                users: vec![],
                cert_path: INTEROP_CERT_PATH.to_string(),
                key_path: INTEROP_KEY_PATH.to_string(),
                router,
                tag: Some(spec.name.clone()),
                stats: None,
                conn_tracker: new_conn_tracker(),
                reality: None,
                multiplex: None,
                transport_layer: None,
                fallback: None,
                fallback_for_alpn: HashMap::new(),
            };

            let join = tokio::spawn(async move {
                let serve = serve_trojan(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        if stop_tx.send(()).await.is_err() {
                            tracing::debug!("trojan upstream stop channel already closed");
                        }
                        if let Err(err) = serve.await {
                            tracing::warn!(error = %err, "trojan upstream serve failed during shutdown");
                        }
                    }
                    result = &mut serve => {
                        if let Err(err) = result {
                            tracing::warn!(error = %err, "trojan upstream serve failed");
                        }
                    }
                }
            });

            tokio::time::sleep(Duration::from_millis(300)).await;
            harness.endpoints.insert(
                spec.name.clone(),
                format!("trojan://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::ShadowsocksInbound => {
            ensure_protocol_upstream_rules();
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding shadowsocks upstream {}", spec.bind))?;
            let addr = listener
                .local_addr()
                .with_context(|| "shadowsocks local_addr")?;
            drop(listener);

            let router = std::sync::Arc::new(RouterHandle::new_mock());
            let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
            let (tx, mut rx) = oneshot::channel::<()>();

            let cfg = ShadowsocksInboundConfig {
                listen: addr,
                method: "aes-256-gcm".to_string(),
                #[allow(deprecated)]
                password: Some(INTEROP_PASSWORD.to_string()),
                users: vec![],
                router,
                tag: Some(spec.name.clone()),
                stats: None,
                conn_tracker: new_conn_tracker(),
                multiplex: None,
                transport_layer: None,
            };

            let join = tokio::spawn(async move {
                let serve = serve_shadowsocks(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        if stop_tx.send(()).await.is_err() {
                            tracing::debug!("shadowsocks upstream stop channel already closed");
                        }
                        if let Err(err) = serve.await {
                            tracing::warn!(error = %err, "shadowsocks upstream serve failed during shutdown");
                        }
                    }
                    _ = &mut serve => {}
                }
            });

            tokio::time::sleep(Duration::from_millis(300)).await;
            harness.endpoints.insert(
                spec.name.clone(),
                format!("ss://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::ShadowTlsInbound => {
            ensure_protocol_upstream_rules();
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding shadowtls upstream {}", spec.bind))?;
            let addr = listener
                .local_addr()
                .with_context(|| "shadowtls local_addr")?;
            drop(listener);

            let router = std::sync::Arc::new(RouterHandle::new_mock());
            let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
            let (tx, mut rx) = oneshot::channel::<()>();

            let cfg = ShadowTlsInboundConfig {
                listen: addr,
                detour: spec
                    .target
                    .clone()
                    .unwrap_or_else(|| "shadowtls-upstream-detour".to_string()),
                version: 2,
                password: Some("shadowtls-upstream-password".to_string()),
                users: Vec::new(),
                handshake: Some(
                    parse_host_port(spec.handshake_target.as_deref().unwrap_or("google.com:443"))
                        .map(|(host, port)| {
                            sb_adapters::inbound::shadowtls::ShadowTlsHandshakeConfig {
                                server: host,
                                server_port: port,
                            }
                        })
                        .unwrap_or(sb_adapters::inbound::shadowtls::ShadowTlsHandshakeConfig {
                            server: "google.com".to_string(),
                            server_port: 443,
                        }),
                ),
                handshake_for_server_name: std::collections::HashMap::new(),
                strict_mode: false,
                wildcard_sni: sb_adapters::inbound::shadowtls::ShadowTlsWildcardSniMode::Off,
                tag: Some(spec.name.clone()),
                tls: Some(sb_transport::TlsConfig::Standard(
                    sb_transport::tls::StandardTlsConfig {
                        server_name: Some("localhost".to_string()),
                        alpn: vec!["http/1.1".to_string()],
                        insecure: false,
                        cert_path: Some(INTEROP_CERT_PATH.to_string()),
                        key_path: Some(INTEROP_KEY_PATH.to_string()),
                        cert_pem: None,
                        key_pem: None,
                    },
                )),
                router: Some(router),
                stats: None,
            };

            let join = tokio::spawn(async move {
                let serve = serve_shadowtls(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        if stop_tx.send(()).await.is_err() {
                            tracing::debug!("shadowtls upstream stop channel already closed");
                        }
                        if let Err(err) = serve.await {
                            tracing::warn!(error = %err, "shadowtls upstream serve failed during shutdown");
                        }
                    }
                    _ = &mut serve => {}
                }
            });

            tokio::time::sleep(Duration::from_millis(300)).await;
            harness.endpoints.insert(
                spec.name.clone(),
                format!("shadowtls://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::VlessInbound => {
            ensure_protocol_upstream_rules();
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding vless upstream {}", spec.bind))?;
            let addr = listener.local_addr().with_context(|| "vless local_addr")?;
            drop(listener);

            let router = std::sync::Arc::new(RouterHandle::new_mock());
            let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
            let (tx, mut rx) = oneshot::channel::<()>();

            let cfg = VlessInboundConfig {
                listen: addr,
                uuid: uuid::Uuid::parse_str(INTEROP_VLESS_UUID)
                    .with_context(|| "parsing interop VLESS UUID")?,
                router,
                tag: Some(spec.name.clone()),
                stats: None,
                conn_tracker: new_conn_tracker(),
                reality: None,
                multiplex: None,
                transport_layer: None,
                fallback: None,
                fallback_for_alpn: HashMap::new(),
                flow: None,
            };

            let join = tokio::spawn(async move {
                let serve = serve_vless(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        if stop_tx.send(()).await.is_err() {
                            tracing::debug!("vless upstream stop channel already closed");
                        }
                        if let Err(err) = serve.await {
                            tracing::warn!(error = %err, "vless upstream serve failed during shutdown");
                        }
                    }
                    _ = &mut serve => {}
                }
            });

            tokio::time::sleep(Duration::from_millis(300)).await;
            harness.endpoints.insert(
                spec.name.clone(),
                format!("vless://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
        UpstreamKind::VmessInbound => {
            ensure_protocol_upstream_rules();
            let listener = TcpListener::bind(&spec.bind)
                .await
                .with_context(|| format!("binding vmess upstream {}", spec.bind))?;
            let addr = listener.local_addr().with_context(|| "vmess local_addr")?;
            drop(listener);

            let router = std::sync::Arc::new(RouterHandle::new_mock());
            let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
            let (tx, mut rx) = oneshot::channel::<()>();

            let cfg = VmessInboundConfig {
                listen: addr,
                uuid: uuid::Uuid::parse_str(INTEROP_VMESS_UUID)
                    .with_context(|| "parsing interop VMess UUID")?,
                security: "aes-128-gcm".to_string(),
                router,
                tag: Some(spec.name.clone()),
                stats: None,
                conn_tracker: new_conn_tracker(),
                multiplex: None,
                transport_layer: None,
                fallback: None,
                fallback_for_alpn: HashMap::new(),
            };

            let join = tokio::spawn(async move {
                let serve = serve_vmess(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        if stop_tx.send(()).await.is_err() {
                            tracing::debug!("vmess upstream stop channel already closed");
                        }
                        if let Err(err) = serve.await {
                            tracing::warn!(error = %err, "vmess upstream serve failed during shutdown");
                        }
                    }
                    _ = &mut serve => {}
                }
            });

            tokio::time::sleep(Duration::from_millis(300)).await;
            harness.endpoints.insert(
                spec.name.clone(),
                format!("vmess://{}:{}", addr.ip(), addr.port()),
            );
            harness.insert_handle(
                spec.name.clone(),
                UpstreamHandle {
                    shutdown: Some(tx),
                    join,
                },
            );
        }
    }
    Ok(())
}

pub async fn run_traffic_plan(
    harness: &mut UpstreamHarness,
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
            TrafficAction::HttpGetLatency {
                name,
                url,
                proxy,
                expect_status,
                samples,
                warmup,
                timeout_ms,
                max_p95_ms,
            } => {
                let url = harness.resolve_templates(url);
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let total_samples = warmup.saturating_add(*samples);
                let mut latencies_us = Vec::with_capacity(*samples);
                let mut statuses = Vec::with_capacity(*samples);
                let mut failed_detail = None;

                for idx in 0..total_samples {
                    let started = tokio::time::Instant::now();
                    let response =
                        tokio::time::timeout(Duration::from_millis((*timeout_ms).max(1)), async {
                            if let Some(proxy) = resolved_proxy.as_deref() {
                                http_get_via_curl(&url, Some(proxy)).await
                            } else {
                                http_get_via_reqwest(&url).await
                            }
                        })
                        .await;

                    let (status, _body) = match response {
                        Ok(Ok((status, body))) => (status, body),
                        Ok(Err(err)) => {
                            failed_detail = Some(json!({
                                "url": url,
                                "proxy": resolved_proxy,
                                "timeout_ms": timeout_ms,
                                "error": err.to_string(),
                            }));
                            break;
                        }
                        Err(_) => {
                            failed_detail = Some(json!({
                                "url": url,
                                "proxy": resolved_proxy,
                                "timeout_ms": timeout_ms,
                                "error": format!("http get timeout after {}ms", timeout_ms),
                            }));
                            break;
                        }
                    };

                    if let Some(expected) = expect_status {
                        if status != *expected {
                            failed_detail = Some(json!({
                                "url": url,
                                "proxy": resolved_proxy,
                                "timeout_ms": timeout_ms,
                                "expect_status": expected,
                                "status": status,
                            }));
                            break;
                        }
                    }

                    if idx >= *warmup {
                        latencies_us.push(started.elapsed().as_micros() as u64);
                        statuses.push(status);
                    }
                }

                if let Some(detail) = failed_detail {
                    TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "action": "http_get_latency",
                            "samples": total_samples,
                            "warmup": warmup,
                            "max_p95_ms": max_p95_ms,
                            "detail": detail,
                        }),
                    }
                } else {
                    let p95_us = percentile_us(&latencies_us, 95);
                    let max_us = latencies_us.iter().copied().max().unwrap_or(0);
                    let min_us = latencies_us.iter().copied().min().unwrap_or(0);
                    let avg_us = if latencies_us.is_empty() {
                        0.0
                    } else {
                        latencies_us.iter().map(|v| *v as f64).sum::<f64>()
                            / latencies_us.len() as f64
                    };
                    TrafficResult {
                        name: name.clone(),
                        success: p95_us <= max_p95_ms.saturating_mul(1000),
                        detail: json!({
                            "action": "http_get_latency",
                            "url": url,
                            "proxy": resolved_proxy,
                            "samples": total_samples,
                            "warmup": warmup,
                            "timeout_ms": timeout_ms,
                            "expect_status": expect_status,
                            "statuses": statuses,
                            "p95_us": p95_us,
                            "p95_ms": p95_us as f64 / 1000.0,
                            "max_p95_ms": max_p95_ms,
                            "min_ms": min_us as f64 / 1000.0,
                            "max_ms": max_us as f64 / 1000.0,
                            "avg_ms": avg_us / 1000.0,
                        }),
                    }
                }
            }
            TrafficAction::TcpRoundTrip {
                name,
                addr,
                payload,
                proxy,
                source_port,
                payload_size,
                payload_tls_client_hello,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let actual_payload =
                    resolve_payload(payload, *payload_size, *payload_tls_client_hello);
                let result = match tokio::time::timeout(
                    Duration::from_millis(TCP_ROUNDTRIP_TIMEOUT_MS),
                    async {
                        if let Some(proxy) = resolved_proxy.as_deref() {
                            tcp_roundtrip_via_proxy(proxy, &addr, &actual_payload, *source_port)
                                .await
                        } else {
                            tcp_roundtrip(&addr, &actual_payload, *source_port).await
                        }
                    },
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!(
                        "tcp roundtrip timeout after {TCP_ROUNDTRIP_TIMEOUT_MS}ms"
                    )),
                };
                match result {
                    Ok(back) => {
                        let payload_hash = sha256_hex(&actual_payload);
                        let echo_hash = sha256_hex(&back);
                        TrafficResult {
                            name: name.clone(),
                            success: back == actual_payload,
                            detail: json!({
                                "addr": addr,
                                "proxy": resolved_proxy,
                                "source_port": source_port,
                                "payload_len": actual_payload.len(),
                                "echo_len": back.len(),
                                "payload_hash": payload_hash,
                                "echo_hash": echo_hash,
                            }),
                        }
                    }
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                                "addr": addr,
                                "proxy": resolved_proxy,
                                "source_port": source_port,
                                "error": err.to_string()
                        }),
                    },
                }
            }
            TrafficAction::TcpThroughput {
                name,
                addr,
                proxy,
                payload_size,
                samples,
                warmup,
                timeout_ms,
                min_mib_per_sec,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = harness.resolve_templates(proxy);
                let payload = resolve_payload("", Some(*payload_size), false);
                let total_samples = warmup.saturating_add(*samples);
                let mut rates = Vec::with_capacity(*samples);
                let mut failed_detail = None;

                for idx in 0..total_samples {
                    let started = tokio::time::Instant::now();
                    let result = tokio::time::timeout(
                        Duration::from_millis((*timeout_ms).max(1)),
                        tcp_roundtrip_via_proxy(&resolved_proxy, &addr, &payload, None),
                    )
                    .await;
                    let echoed = match result {
                        Ok(Ok(echoed)) => echoed,
                        Ok(Err(err)) => {
                            failed_detail = Some(json!({
                                "sample": idx,
                                "error": err.to_string(),
                            }));
                            break;
                        }
                        Err(_) => {
                            failed_detail = Some(json!({
                                "sample": idx,
                                "error": format!("tcp throughput timeout after {}ms", timeout_ms),
                            }));
                            break;
                        }
                    };
                    if echoed != payload {
                        failed_detail = Some(json!({
                            "sample": idx,
                            "error": "tcp throughput echo mismatch",
                            "payload_hash": sha256_hex(&payload),
                            "echo_hash": sha256_hex(&echoed),
                        }));
                        break;
                    }
                    if idx >= *warmup {
                        rates.push(throughput_bytes_per_sec(
                            *payload_size,
                            started.elapsed().as_micros() as u64,
                        ));
                    }
                }

                if let Some(detail) = failed_detail {
                    TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "action": "tcp_throughput",
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "payload_size": payload_size,
                            "samples": samples,
                            "warmup": warmup,
                            "timeout_ms": timeout_ms,
                            "min_mib_per_sec": min_mib_per_sec,
                            "detail": detail,
                        }),
                    }
                } else {
                    let min_bytes_per_sec = rates.iter().copied().min().unwrap_or(0);
                    let median_bytes_per_sec = percentile_us(&rates, 50);
                    let required_bytes_per_sec = (*min_mib_per_sec * 1_048_576.0).ceil() as u64;
                    TrafficResult {
                        name: name.clone(),
                        success: min_bytes_per_sec >= required_bytes_per_sec,
                        detail: json!({
                            "action": "tcp_throughput",
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "payload_size": payload_size,
                            "samples": samples,
                            "warmup": warmup,
                            "timeout_ms": timeout_ms,
                            "rate_basis": "payload bytes per full SOCKS5 connect+echo second",
                            "bytes_per_sec": rates,
                            "min_mib_per_sec": min_bytes_per_sec as f64 / 1_048_576.0,
                            "median_mib_per_sec": median_bytes_per_sec as f64 / 1_048_576.0,
                            "required_min_mib_per_sec": min_mib_per_sec,
                        }),
                    }
                }
            }
            TrafficAction::UdpRoundTrip {
                name,
                addr,
                payload,
                proxy,
                payload_size,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let actual_payload = resolve_payload(payload, *payload_size, false);
                let result = if let Some(proxy) = resolved_proxy.as_deref() {
                    udp_roundtrip_via_proxy(proxy, &addr, &actual_payload).await
                } else {
                    udp_roundtrip(&addr, &actual_payload).await
                };
                match result {
                    Ok(back) => {
                        let payload_hash = sha256_hex(&actual_payload);
                        let echo_hash = sha256_hex(&back);
                        TrafficResult {
                            name: name.clone(),
                            success: back == actual_payload,
                            detail: json!({
                                "addr": addr,
                                "proxy": resolved_proxy,
                                "payload_len": actual_payload.len(),
                                "echo_len": back.len(),
                                "payload_hash": payload_hash,
                                "echo_hash": echo_hash,
                            }),
                        }
                    }
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
            TrafficAction::DnsQuery {
                name,
                addr,
                qname,
                proxy,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let result = dns_query(&addr, qname, resolved_proxy.as_deref()).await;
                match result {
                    Ok(mut detail) => {
                        if let Some(obj) = detail.as_object_mut() {
                            obj.insert("proxy".to_string(), json!(resolved_proxy));
                            obj.insert("addr".to_string(), json!(addr));
                        }
                        TrafficResult {
                            name: name.clone(),
                            success: true,
                            detail,
                        }
                    }
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
            TrafficAction::UpstreamQueryCount { name, target } => {
                let count = harness.dns_query_count(target).await.unwrap_or(0);
                TrafficResult {
                    name: name.clone(),
                    success: true,
                    detail: json!({
                        "target": target,
                        "count": count,
                    }),
                }
            }
            TrafficAction::FaultDisconnect { name, target } => {
                match harness.disconnect_target(target).await {
                    Ok(()) => TrafficResult {
                        name: name.clone(),
                        success: true,
                        detail: json!({ "action": "fault_disconnect", "target": target }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "action": "fault_disconnect",
                            "target": target,
                            "error": err.to_string()
                        }),
                    },
                }
            }
            TrafficAction::FaultReconnect { name, target } => {
                match harness.reconnect_target(target).await {
                    Ok(()) => TrafficResult {
                        name: name.clone(),
                        success: true,
                        detail: json!({
                            "action": "fault_reconnect",
                            "target": target,
                            "endpoint": harness.endpoints.get(target)
                        }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "action": "fault_reconnect",
                            "target": target,
                            "error": err.to_string()
                        }),
                    },
                }
            }
            TrafficAction::Sleep { name, ms } => {
                tokio::time::sleep(Duration::from_millis(*ms)).await;
                TrafficResult {
                    name: name.clone(),
                    success: true,
                    detail: json!({ "action": "sleep", "ms": ms }),
                }
            }
            TrafficAction::Command {
                name,
                command,
                args,
                env,
                workdir,
                timeout_ms,
                expect_exit,
            } => {
                let resolved_command = resolve_command_with_fallback(&resolve_with_env(
                    &harness.resolve_templates(command),
                ));
                let resolved_args: Vec<String> = args
                    .iter()
                    .map(|arg| resolve_with_env(&harness.resolve_templates(arg)))
                    .collect();
                let resolved_env: BTreeMap<String, String> = env
                    .iter()
                    .map(|(k, v)| (k.clone(), resolve_with_env(&harness.resolve_templates(v))))
                    .collect();
                let resolved_workdir = workdir.as_ref().map(|dir| {
                    let raw = dir.to_string_lossy();
                    std::path::PathBuf::from(resolve_with_env(&harness.resolve_templates(&raw)))
                });

                let mut cmd = Command::new(&resolved_command);
                cmd.args(&resolved_args);
                for (k, v) in &resolved_env {
                    cmd.env(k, v);
                }
                if let Some(dir) = &resolved_workdir {
                    cmd.current_dir(dir);
                }

                let started_at = tokio::time::Instant::now();
                let output =
                    tokio::time::timeout(Duration::from_millis((*timeout_ms).max(1)), cmd.output())
                        .await;
                match output {
                    Ok(Ok(output)) => {
                        let code = output.status.code();
                        let success = if let Some(expected) = expect_exit {
                            code == Some(*expected)
                        } else {
                            output.status.success()
                        };
                        TrafficResult {
                            name: name.clone(),
                            success,
                            detail: json!({
                                "action": "command",
                                "command": resolved_command,
                                "args": resolved_args,
                                "env": resolved_env,
                                "workdir": resolved_workdir.as_ref().map(|p| p.to_string_lossy().to_string()),
                                "elapsed_ms": started_at.elapsed().as_millis() as u64,
                                "exit_code": code,
                                "expect_exit": expect_exit,
                                "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
                                "stderr": String::from_utf8_lossy(&output.stderr).to_string()
                            }),
                        }
                    }
                    Ok(Err(err)) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "action": "command",
                            "command": resolved_command,
                            "args": resolved_args,
                            "error": err.to_string()
                        }),
                    },
                    Err(_) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "action": "command",
                            "command": resolved_command,
                            "args": resolved_args,
                            "timeout_ms": timeout_ms
                        }),
                    },
                }
            }
            TrafficAction::CommandStart { name, handle, .. } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "command_start",
                    "handle": handle,
                    "error": "command_start requires run_traffic_plan_with_kernel_control context",
                }),
            },
            TrafficAction::CommandWait { name, handle, .. } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "command_wait",
                    "handle": handle,
                    "error": "command_wait requires run_traffic_plan_with_kernel_control context",
                }),
            },
            TrafficAction::ApiHttp {
                name, method, path, ..
            } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "api_http",
                    "method": method,
                    "path": path,
                    "error": "api_http requires run_traffic_plan_with_kernel_control context",
                }),
            },
            TrafficAction::FaultJitter {
                name,
                target,
                base_ms,
                jitter_ms,
                ratio,
            } => {
                let clamped_ratio = ratio.clamp(0.0, 1.0);
                let applied = compute_jitter_delay(target, *base_ms, *jitter_ms, clamped_ratio);
                harness.set_service_delay(target, applied).await;
                TrafficResult {
                    name: name.clone(),
                    success: true,
                    detail: json!({
                        "action": "fault_jitter",
                        "target": target,
                        "base_ms": base_ms,
                        "jitter_ms": jitter_ms,
                        "ratio": clamped_ratio,
                        "applied_delay_ms": applied,
                    }),
                }
            }
            TrafficAction::WsRoundTrip {
                name,
                url,
                payload,
                proxy,
                timeout_ms,
            } => {
                let url = harness.resolve_templates(url);
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let result =
                    ws_roundtrip(&url, payload, resolved_proxy.as_deref(), *timeout_ms).await;
                match result {
                    Ok(echo) => TrafficResult {
                        name: name.clone(),
                        success: echo == *payload,
                        detail: json!({
                            "url": url,
                            "proxy": resolved_proxy,
                            "echo": echo,
                        }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "url": url,
                            "proxy": resolved_proxy,
                            "error": err.to_string(),
                        }),
                    },
                }
            }
            TrafficAction::ApiWsSoak { name, path, .. } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "api_ws_soak",
                    "path": path,
                    "error": "api_ws_soak requires run_traffic_plan_with_kernel_control context",
                }),
            },
            TrafficAction::ApiHttpLatency {
                name, method, path, ..
            } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "api_http_latency",
                    "method": method,
                    "path": path,
                    "error": "api_http_latency requires run_traffic_plan_with_kernel_control context",
                }),
            },
            TrafficAction::ApiWsExpectCloseOnKernelControl {
                name,
                path,
                action,
                target,
                ..
            } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "api_ws_expect_close_on_kernel_control",
                    "path": path,
                    "op": format!("{:?}", action),
                    "target": format!("{:?}", target),
                    "error": "api_ws_expect_close_on_kernel_control requires run_traffic_plan_with_kernel_control context",
                }),
            },
            TrafficAction::TlsRoundTrip {
                name,
                addr,
                payload,
                proxy,
                skip_verify,
                timeout_ms,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let result = tls_roundtrip(
                    &addr,
                    payload.as_bytes(),
                    resolved_proxy.as_deref(),
                    *skip_verify,
                    *timeout_ms,
                )
                .await;
                match result {
                    Ok(back) => TrafficResult {
                        name: name.clone(),
                        success: back == payload.as_bytes(),
                        detail: json!({
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "echo": String::from_utf8_lossy(&back),
                        }),
                    },
                    Err(err) => TrafficResult {
                        name: name.clone(),
                        success: false,
                        detail: json!({
                            "addr": addr,
                            "proxy": resolved_proxy,
                            "error": err.to_string(),
                        }),
                    },
                }
            }
            TrafficAction::KernelControl {
                name,
                action,
                target,
                wait_ready_ms,
            } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "kernel_control",
                    "op": format!("{:?}", action),
                    "target": format!("{:?}", target),
                    "wait_ready_ms": wait_ready_ms,
                    "error": "kernel_control must be handled by orchestrator",
                }),
            },
            TrafficAction::TcpDrainDuringShutdown { name, .. } => TrafficResult {
                name: name.clone(),
                success: false,
                detail: json!({
                    "action": "tcp_drain_during_shutdown",
                    "error": "tcp_drain_during_shutdown must be handled by orchestrator",
                }),
            },
        };

        out.push(result);
    }

    Ok(out)
}

pub async fn apply_faults(harness: &mut UpstreamHarness, faults: &[FaultSpec]) -> Result<()> {
    for fault in faults {
        match fault {
            FaultSpec::Delay { target, ms } => {
                harness.set_service_delay(target, *ms).await;
            }
            FaultSpec::Disconnect { target } => {
                harness.disconnect_target(target).await?;
            }
        }
    }
    Ok(())
}

fn compute_jitter_delay(target: &str, base_ms: u64, jitter_ms: u64, ratio: f64) -> u64 {
    if base_ms == 0 && jitter_ms == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    target.hash(&mut hasher);
    let hash = hasher.finish();
    let bucket = (hash % 1000) as f64 / 1000.0;
    let scaled_jitter = (jitter_ms as f64 * ratio * bucket).round() as u64;
    base_ms.saturating_add(scaled_jitter)
}

/// Resolve the effective payload bytes:
/// 1. when `payload_tls_client_hello` is set, synthesize a minimal TLS ClientHello,
/// 2. else when `payload_size` is set, generate a deterministic pattern,
/// 3. otherwise use the literal `payload` string.
fn resolve_payload(
    payload: &str,
    payload_size: Option<usize>,
    payload_tls_client_hello: bool,
) -> Vec<u8> {
    if payload_tls_client_hello {
        return build_tls_client_hello("api.example.com", "h2");
    }
    match payload_size {
        Some(size) if size > 0 => {
            // Deterministic fill: repeating ASCII bytes 0x41..0x5A ('A'..'Z')
            let mut buf = vec![0u8; size];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = 0x41 + (i % 26) as u8;
            }
            buf
        }
        _ => payload.as_bytes().to_vec(),
    }
}

fn throughput_bytes_per_sec(payload_size: usize, elapsed_us: u64) -> u64 {
    let elapsed_us = elapsed_us.max(1) as u128;
    ((payload_size as u128).saturating_mul(1_000_000) / elapsed_us).min(u64::MAX as u128) as u64
}

fn build_tls_client_hello(sni: &str, alpn: &str) -> Vec<u8> {
    let mut hs = Vec::new();
    hs.push(0x01);
    hs.extend_from_slice(&[0, 0, 0]);
    hs.extend_from_slice(&[0x03, 0x03]);
    hs.extend_from_slice(&[0u8; 32]);
    hs.push(0);
    hs.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    hs.push(1);
    hs.push(0);

    let ext_len_pos = hs.len();
    hs.extend_from_slice(&[0x00, 0x00]);

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    let sni_ext_data_len_pos = sni_ext.len();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    let sni_list_len_pos = sni_ext.len();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    sni_ext.push(0);
    let sni_bytes = sni.as_bytes();
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    let sni_list_len = (1 + 2 + sni_bytes.len()) as u16;
    sni_ext[sni_list_len_pos..sni_list_len_pos + 2].copy_from_slice(&sni_list_len.to_be_bytes());
    let sni_ext_data_len = (2 + sni_list_len as usize) as u16;
    sni_ext[sni_ext_data_len_pos..sni_ext_data_len_pos + 2]
        .copy_from_slice(&sni_ext_data_len.to_be_bytes());
    hs.extend_from_slice(&sni_ext);

    let mut alpn_ext = Vec::new();
    alpn_ext.extend_from_slice(&[0x00, 0x10]);
    let alpn_ext_data_len_pos = alpn_ext.len();
    alpn_ext.extend_from_slice(&[0x00, 0x00]);
    let alpn_list_len_pos = alpn_ext.len();
    alpn_ext.extend_from_slice(&[0x00, 0x00]);
    let alpn_bytes = alpn.as_bytes();
    alpn_ext.push(alpn_bytes.len() as u8);
    alpn_ext.extend_from_slice(alpn_bytes);
    let alpn_list_len = (1 + alpn_bytes.len()) as u16;
    alpn_ext[alpn_list_len_pos..alpn_list_len_pos + 2]
        .copy_from_slice(&alpn_list_len.to_be_bytes());
    let alpn_ext_data_len = (2 + alpn_list_len as usize) as u16;
    alpn_ext[alpn_ext_data_len_pos..alpn_ext_data_len_pos + 2]
        .copy_from_slice(&alpn_ext_data_len.to_be_bytes());
    hs.extend_from_slice(&alpn_ext);

    let final_ext_len = (sni_ext.len() + alpn_ext.len()) as u16;
    hs[ext_len_pos..ext_len_pos + 2].copy_from_slice(&final_ext_len.to_be_bytes());

    let hs_body_len = (hs.len() - 4) as u32;
    hs[1..4].copy_from_slice(&[
        (hs_body_len >> 16) as u8,
        (hs_body_len >> 8) as u8,
        hs_body_len as u8,
    ]);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

async fn http_get_via_reqwest(url: &str) -> Result<(u16, String)> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .with_context(|| format!("building reqwest client for {url}"))?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("http get {url}"))?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .with_context(|| format!("reading response body for {url}"))?;
    Ok((status, body))
}

async fn http_get_via_curl(url: &str, proxy: Option<&str>) -> Result<(u16, String)> {
    let client = if let Some(proxy) = proxy {
        let reqwest_proxy =
            reqwest::Proxy::all(proxy).with_context(|| format!("building proxy for {proxy}"))?;
        reqwest::Client::builder()
            .timeout(Duration::from_secs(12))
            .redirect(reqwest::redirect::Policy::limited(10))
            .proxy(reqwest_proxy)
            .build()
            .with_context(|| format!("building proxied http client for {url}"))?
    } else {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(12))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .with_context(|| format!("building http client for {url}"))?
    };

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("proxied http get {url}"))?;
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Ok((status, body))
}

async fn http_echo(
    State(state): State<HttpState>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> impl IntoResponse {
    let delay_ms = service_delay(&state.delays_ms, &state.service_name).await;
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    let payload = json!({
        "service": state.service_name,
        "method": method.to_string(),
        "path": uri.path(),
        "query": uri.query(),
        "body_len": body.len(),
    });
    (StatusCode::OK, Json(payload))
}

async fn http_static(State(state): State<HttpStaticState>) -> impl IntoResponse {
    let delay_ms = service_delay(&state.delays_ms, &state.service_name).await;
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    let mut response = state.body.clone().into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, state.content_type.clone());
    response
}

async fn ws_echo(State(state): State<WsState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: WebSocket, state: WsState) {
    let delay_ms = service_delay(&state.delays_ms, &state.service_name).await;
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    let _ = socket
        .send(AxumWsMessage::Text("{\"event\":\"ready\"}".to_string()))
        .await;

    while let Some(next) = socket.next().await {
        match next {
            Ok(AxumWsMessage::Text(text)) => {
                let delay_ms = service_delay(&state.delays_ms, &state.service_name).await;
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                let _ = socket.send(AxumWsMessage::Text(text)).await;
            }
            Ok(AxumWsMessage::Binary(data)) => {
                let delay_ms = service_delay(&state.delays_ms, &state.service_name).await;
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
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

async fn service_delay(delays: &Arc<RwLock<BTreeMap<String, u64>>>, service_name: &str) -> u64 {
    let map = delays.read().await;
    map.get(service_name).copied().unwrap_or(0)
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

async fn connect_tcp(addr: &str, source_port: Option<u16>) -> Result<TcpStream> {
    let Some(source_port) = source_port else {
        return TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting tcp {addr}"));
    };

    let remote = lookup_host(addr)
        .await
        .with_context(|| format!("resolving tcp address {addr}"))?
        .next()
        .ok_or_else(|| anyhow!("tcp address resolved empty: {addr}"))?;
    let socket = if remote.is_ipv4() {
        TcpSocket::new_v4().with_context(|| "creating IPv4 TCP socket")?
    } else {
        TcpSocket::new_v6().with_context(|| "creating IPv6 TCP socket")?
    };
    socket
        .set_reuseaddr(true)
        .with_context(|| format!("enabling source port reuse for {source_port}"))?;
    let local_ip = if remote.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    socket
        .bind(SocketAddr::new(local_ip, source_port))
        .with_context(|| format!("binding TCP source port {source_port}"))?;
    let stream = socket
        .connect(remote)
        .await
        .with_context(|| format!("connecting TCP {remote} from source port {source_port}"))?;
    // Dual-kernel cases reuse fixed source ports against the same proxy endpoint.
    // Abortive close prevents the first lane's TIME_WAIT tuple from blocking the
    // second lane or an immediate repeat run.
    stream
        .set_linger(Some(Duration::ZERO))
        .with_context(|| format!("enabling abortive close for source port {source_port}"))?;
    Ok(stream)
}

async fn tcp_roundtrip(addr: &str, payload: &[u8], source_port: Option<u16>) -> Result<Vec<u8>> {
    let mut stream = connect_tcp(addr, source_port)
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Socks5ProxySpec {
    addr: String,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5ProxySpec {
    fn auth(&self) -> Option<(&str, &str)> {
        self.username
            .as_deref()
            .map(|username| (username, self.password.as_deref().unwrap_or_default()))
    }
}

fn parse_socks5_proxy(proxy: &str) -> Result<Socks5ProxySpec> {
    let parsed = url::Url::parse(proxy).with_context(|| format!("parsing SOCKS5 proxy {proxy}"))?;
    if !matches!(parsed.scheme(), "socks5" | "socks5h") {
        return Err(anyhow!(
            "unsupported SOCKS5 proxy scheme: {}",
            parsed.scheme()
        ));
    }
    if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() || parsed.fragment().is_some()
    {
        return Err(anyhow!(
            "SOCKS5 proxy URL must not contain path, query, or fragment"
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| anyhow!("SOCKS5 proxy URL is missing host"))?;
    let port = parsed.port().unwrap_or(1080);
    let addr = match host {
        url::Host::Ipv6(address) => format!("[{address}]:{port}"),
        url::Host::Ipv4(address) => format!("{address}:{port}"),
        url::Host::Domain(domain) => format!("{domain}:{port}"),
    };
    let username = (!parsed.username().is_empty()).then(|| parsed.username().to_string());
    if username.is_none() && parsed.password().is_some() {
        return Err(anyhow!("SOCKS5 proxy password requires username"));
    }
    let password = username
        .as_ref()
        .map(|_| parsed.password().unwrap_or_default().to_string());
    Ok(Socks5ProxySpec {
        addr,
        username,
        password,
    })
}

async fn tcp_roundtrip_via_proxy(
    proxy: &str,
    addr: &str,
    payload: &[u8],
    source_port: Option<u16>,
) -> Result<Vec<u8>> {
    if proxy.starts_with("socks5://") || proxy.starts_with("socks5h://") {
        let proxy = parse_socks5_proxy(proxy)?;
        return tcp_roundtrip_via_socks5(&proxy.addr, addr, payload, source_port, proxy.auth())
            .await;
    }
    if proxy.starts_with("http://") {
        let proxy_addr = normalize_addr(proxy.trim_start_matches("http://"));
        return tcp_roundtrip_via_http_connect(&proxy_addr, addr, payload, source_port).await;
    }

    Err(anyhow!("unsupported tcp proxy scheme: {proxy}"))
}

async fn tcp_roundtrip_via_socks5(
    proxy_addr: &str,
    target_addr: &str,
    payload: &[u8],
    source_port: Option<u16>,
    auth: Option<(&str, &str)>,
) -> Result<Vec<u8>> {
    let mut stream =
        socks5_connect_with_source_port(proxy_addr, target_addr, source_port, auth).await?;
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

async fn tcp_roundtrip_via_http_connect(
    proxy_addr: &str,
    target_addr: &str,
    payload: &[u8],
    source_port: Option<u16>,
) -> Result<Vec<u8>> {
    let mut stream = connect_tcp(proxy_addr, source_port)
        .await
        .with_context(|| format!("connecting http proxy {proxy_addr}"))?;
    let request = format!("CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .with_context(|| format!("writing http connect request via {proxy_addr}"))?;
    read_http_connect_response(&mut stream, proxy_addr, target_addr).await?;
    stream
        .write_all(payload)
        .await
        .with_context(|| format!("writing payload via http connect to {target_addr}"))?;
    let mut buf = vec![0_u8; payload.len()];
    stream
        .read_exact(&mut buf)
        .await
        .with_context(|| format!("reading payload via http connect from {target_addr}"))?;
    Ok(buf)
}

async fn read_http_connect_response(
    stream: &mut TcpStream,
    proxy_addr: &str,
    target_addr: &str,
) -> Result<()> {
    let mut response = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .with_context(|| format!("reading http connect response from {proxy_addr}"))?;
        if n == 0 {
            return Err(anyhow!(
                "unexpected eof reading http connect response from {proxy_addr} to {target_addr}"
            ));
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
        if response.len() > 8192 {
            return Err(anyhow!(
                "http connect response headers too large from {proxy_addr} to {target_addr}"
            ));
        }
    }
    let response_text = String::from_utf8_lossy(&response);
    let status_line = response_text.lines().next().unwrap_or_default();
    if !(status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200")) {
        return Err(anyhow!(
            "http connect failed via {proxy_addr} to {target_addr}: {status_line}"
        ));
    }
    Ok(())
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
    let mut buf = [0_u8; 65536]; // 64KB, matching server
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

async fn udp_roundtrip_via_socks5(
    proxy_addr: &str,
    target_addr: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut control = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("connecting socks5 proxy {proxy_addr}"))?;

    socks5_greet(&mut control, None).await?;

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
    let relay_port = if bind_port == 0 {
        parse_host_port(proxy_addr)?.1
    } else {
        bind_port
    };
    let relay_addr = format_host_port(&relay_host, relay_port);

    let (target_host, target_port) = parse_host_port(target_addr)?;
    let mut packet = vec![0x00_u8, 0x00, 0x00]; // RSV + FRAG
    socks5_append_addr(&mut packet, &target_host, target_port);
    packet.extend_from_slice(payload);

    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .with_context(|| "binding udp client")?;
    socket
        .send_to(&packet, &relay_addr)
        .await
        .with_context(|| format!("sending udp packet to socks relay {relay_addr}"))?;

    let mut recv_buf = [0_u8; 65536]; // 64KB, matching server
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
            Ok((
                std::net::Ipv6Addr::from(ip).to_string(),
                u16::from_be_bytes(port),
            ))
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

async fn dns_query(addr: &str, qname: &str, proxy: Option<&str>) -> Result<serde_json::Value> {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;

    let name = Name::from_ascii(qname).with_context(|| format!("invalid dns name {qname}"))?;
    message.add_query(Query::query(name, RecordType::A));

    let mut encoded = Vec::with_capacity(512);
    message
        .emit(&mut BinEncoder::new(&mut encoded))
        .with_context(|| "encoding dns query")?;

    let response = if let Some(proxy) = proxy {
        udp_roundtrip_via_proxy(proxy, addr, &encoded)
            .await
            .with_context(|| format!("dns query via proxy {proxy} to {addr}"))?
    } else {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .with_context(|| "binding dns client")?;

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
        buf[..n].to_vec()
    };

    let decoded = Message::from_vec(&response).with_context(|| "decoding dns response")?;
    Ok(json!({
        "id": decoded.metadata.id,
        "message_type": format!("{:?}", decoded.metadata.message_type),
        "rcode": format!("{:?}", decoded.metadata.response_code),
        "answers": decoded.answers.len(),
    }))
}

async fn ws_roundtrip(
    url: &str,
    payload: &str,
    proxy: Option<&str>,
    timeout_ms: u64,
) -> Result<String> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let parsed = url::Url::parse(url).with_context(|| format!("parsing ws url {url}"))?;
    let host = parsed.host_str().unwrap_or("127.0.0.1");
    let port = parsed.port().unwrap_or(80);
    let target_addr = format!("{host}:{port}");

    let tcp = if let Some(proxy) = proxy {
        let proxy_addr = normalize_addr(
            proxy
                .trim_start_matches("socks5://")
                .trim_start_matches("socks5h://"),
        );
        socks5_connect(&proxy_addr, &target_addr).await?
    } else {
        TcpStream::connect(&target_addr)
            .await
            .with_context(|| format!("connecting to ws host {target_addr}"))?
    };

    let (mut stream, _) = tokio_tungstenite::client_async(url, tcp)
        .await
        .with_context(|| format!("ws handshake to {url}"))?;

    stream
        .send(WsMessage::Text(payload.to_string()))
        .await
        .with_context(|| "ws send payload")?;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(anyhow!("ws roundtrip timeout after {timeout_ms}ms"));
        }
        let next =
            tokio::time::timeout(deadline.saturating_duration_since(now), stream.next()).await;
        match next {
            Ok(Some(Ok(WsMessage::Text(text)))) => {
                if text == payload {
                    if let Err(err) = stream.close(None).await {
                        tracing::debug!(error = %err, "ws roundtrip close failed");
                    }
                    return Ok(text);
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(err))) => return Err(anyhow!("ws recv error: {err}")),
            Ok(None) => return Err(anyhow!("ws stream closed before echo")),
            Err(_) => return Err(anyhow!("ws roundtrip timeout after {timeout_ms}ms")),
        }
    }
}

/// SOCKS5 greeting and optional RFC 1929 username/password authentication.
async fn socks5_greet(stream: &mut TcpStream, auth: Option<(&str, &str)>) -> Result<()> {
    let method = if auth.is_some() { 0x02 } else { 0x00 };
    stream
        .write_all(&[0x05_u8, 0x01, method])
        .await
        .with_context(|| "writing socks5 greeting")?;
    let mut resp = [0_u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .with_context(|| "reading socks5 greeting response")?;
    if resp != [0x05, method] {
        return Err(anyhow!(
            "socks5 greeting rejected: version={} method={}",
            resp[0],
            resp[1]
        ));
    }
    if let Some((username, password)) = auth {
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(anyhow!("SOCKS5 username/password exceeds 255 bytes"));
        }
        let mut request = Vec::with_capacity(3 + username.len() + password.len());
        request.push(0x01);
        request.push(username.len() as u8);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        stream
            .write_all(&request)
            .await
            .with_context(|| "writing SOCKS5 username/password authentication")?;
        let mut response = [0_u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .with_context(|| "reading SOCKS5 username/password response")?;
        if response != [0x01, 0x00] {
            return Err(anyhow!(
                "SOCKS5 username/password rejected: version={} status={}",
                response[0],
                response[1]
            ));
        }
    }
    Ok(())
}

/// Append SOCKS5 address bytes (atyp + addr + port) to buffer.
fn socks5_append_addr(buf: &mut Vec<u8>, host: &str, port: u16) {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            buf.push(0x01);
            buf.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            buf.push(0x04);
            buf.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host_bytes = host.as_bytes();
            buf.push(0x03);
            buf.push(host_bytes.len() as u8);
            buf.extend_from_slice(host_bytes);
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

pub(crate) async fn socks5_connect(proxy_addr: &str, target_addr: &str) -> Result<TcpStream> {
    socks5_connect_with_source_port(proxy_addr, target_addr, None, None).await
}

async fn socks5_connect_with_source_port(
    proxy_addr: &str,
    target_addr: &str,
    source_port: Option<u16>,
    auth: Option<(&str, &str)>,
) -> Result<TcpStream> {
    let mut stream = connect_tcp(proxy_addr, source_port)
        .await
        .with_context(|| format!("connecting socks5 proxy {proxy_addr}"))?;

    socks5_greet(&mut stream, auth).await?;

    let (host, port) = parse_host_port(target_addr)?;
    let mut req = vec![0x05_u8, 0x01, 0x00]; // v5, connect, reserved
    socks5_append_addr(&mut req, &host, port);

    stream
        .write_all(&req)
        .await
        .with_context(|| "writing socks5 connect request")?;

    let mut resp_head = [0_u8; 4];
    stream
        .read_exact(&mut resp_head)
        .await
        .with_context(|| "reading socks5 connect response")?;
    if resp_head[1] != 0x00 {
        return Err(anyhow!("socks5 connect rejected: {}", resp_head[1]));
    }

    let _bound_addr = read_socks5_addr_port(&mut stream, resp_head[3]).await?;

    Ok(stream)
}

async fn tls_roundtrip(
    addr: &str,
    payload: &[u8],
    proxy: Option<&str>,
    skip_verify: bool,
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    let tcp = if let Some(proxy) = proxy {
        let proxy_addr = normalize_addr(
            proxy
                .trim_start_matches("socks5://")
                .trim_start_matches("socks5h://"),
        );
        socks5_connect(&proxy_addr, addr).await?
    } else {
        TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting tls {addr}"))?
    };

    let (host, _) = parse_host_port(addr)?;

    let config = if skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
        .map_err(|e| anyhow!("invalid server name: {e}"))?
        .to_owned();

    let mut tls = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| anyhow!("tls handshake timeout after {timeout_ms}ms"))?
    .with_context(|| format!("tls handshake with {addr}"))?;

    tls.write_all(payload)
        .await
        .with_context(|| "tls write payload")?;
    let mut buf = vec![0_u8; payload.len()];
    tokio::time::timeout(Duration::from_millis(timeout_ms), tls.read_exact(&mut buf))
        .await
        .map_err(|_| anyhow!("tls read timeout after {timeout_ms}ms"))?
        .with_context(|| "tls read echo")?;
    Ok(buf)
}

#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{connect_tcp, parse_socks5_proxy, throughput_bytes_per_sec};
    use tokio::net::TcpListener;

    #[test]
    fn throughput_rate_uses_payload_bytes_and_never_divides_by_zero() {
        assert_eq!(throughput_bytes_per_sec(1_048_576, 1_000_000), 1_048_576);
        assert_eq!(throughput_bytes_per_sec(1024, 0), 1_024_000_000);
    }

    #[test]
    fn socks5_proxy_url_preserves_case_sensitive_credentials_and_ipv6() {
        let proxy = parse_socks5_proxy("socks5://Alice:Secret@[::1]:11801").unwrap();
        assert_eq!(proxy.addr, "[::1]:11801");
        assert_eq!(proxy.auth(), Some(("Alice", "Secret")));

        let no_auth = parse_socks5_proxy("socks5h://127.0.0.1:11802").unwrap();
        assert_eq!(no_auth.addr, "127.0.0.1:11802");
        assert_eq!(no_auth.auth(), None);
    }

    #[tokio::test]
    async fn tcp_connect_binds_and_immediately_reuses_requested_source_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let source_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let source_port = source_probe.local_addr().unwrap().port();
        drop(source_probe);

        let accepted = tokio::spawn(async move {
            let mut peers = Vec::new();
            for _ in 0..2 {
                let (stream, peer) = listener.accept().await.unwrap();
                peers.push(peer);
                drop(stream);
            }
            peers
        });
        for _ in 0..2 {
            let stream = connect_tcp(&target.to_string(), Some(source_port))
                .await
                .unwrap();
            drop(stream);
        }

        let peers = accepted.await.unwrap();
        assert!(peers.iter().all(|peer| peer.port() == source_port));
    }
}
