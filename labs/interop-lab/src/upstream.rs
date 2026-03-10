use crate::case_spec::{FaultSpec, TrafficAction, UpstreamKind, UpstreamServiceSpec};
use crate::snapshot::TrafficResult;
use crate::util::{resolve_command_with_fallback, resolve_with_env, sha256_hex};
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
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sb_adapters::inbound::shadowsocks::{serve as serve_shadowsocks, ShadowsocksInboundConfig};
use sb_adapters::inbound::shadowtls::{serve as serve_shadowtls, ShadowTlsInboundConfig};
use sb_adapters::inbound::trojan::{serve as serve_trojan, TrojanInboundConfig};
use sb_core::router::engine::RouterHandle;
use sb_core::router::rules::{install_global as install_global_rules, parse_rules, Engine};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::Once;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::{oneshot, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_rustls::TlsAcceptor;

const TCP_ROUNDTRIP_TIMEOUT_MS: u64 = 10_000;
static PROTOCOL_UPSTREAM_RULES_INIT: Once = Once::new();

fn ensure_protocol_upstream_rules() {
    PROTOCOL_UPSTREAM_RULES_INIT.call_once(|| {
        let rules = parse_rules("default=direct");
        install_global_rules(Engine::build(rules));
    });
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
    handles: BTreeMap<String, UpstreamHandle>,
}

struct UpstreamHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<()>,
}

impl UpstreamHarness {
    pub async fn shutdown(mut self) {
        for handle in self.handles.values_mut() {
            if let Some(tx) = handle.shutdown.take() {
                let _ = tx.send(());
            }
        }
        for (_name, handle) in self.handles {
            let _ = tokio::time::timeout(Duration::from_secs(5), handle.join).await;
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
            let _ = tx.send(());
        }
        let _ = handle.join.await;
        Ok(())
    }

    pub async fn reconnect_target(&mut self, target: &str) -> Result<()> {
        if let Some(mut existing) = self.handles.remove(target) {
            if let Some(tx) = existing.shutdown.take() {
                let _ = tx.send(());
            }
            let _ = existing.join.await;
        }
        let spec = self
            .specs
            .get(target)
            .cloned()
            .ok_or_else(|| anyhow!("fault reconnect target not found: {target}"))?;
        start_single_upstream(self, &spec).await
    }
}

#[derive(Clone)]
struct HttpState {
    service_name: String,
    delays_ms: Arc<RwLock<BTreeMap<String, u64>>>,
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
                                        let delay_ms = service_delay(&delays, &service_name).await;
                                        if delay_ms > 0 {
                                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                        }
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
                                            // Add synthetic A record (TEST-NET-2, RFC 5737)
                                            if q.query_type() == RecordType::A {
                                                resp.add_answer(Record::from_rdata(
                                                    q.name().clone(),
                                                    300,
                                                    RData::A(hickory_proto::rr::rdata::A(
                                                        Ipv4Addr::new(198, 51, 100, 1),
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
                password: Some("interop-password".to_string()),
                users: vec![],
                cert_path: "vendor/anytls-rs/examples/singbox/certs/anytls.local.crt".to_string(),
                key_path: "vendor/anytls-rs/examples/singbox/certs/anytls.local.key".to_string(),
                router,
                tag: Some(spec.name.clone()),
                stats: None,
                #[cfg(feature = "tls_reality")]
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
                        let _ = stop_tx.send(()).await;
                        let _ = serve.await;
                    }
                    _ = &mut serve => {}
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
                password: Some("interop-password".to_string()),
                users: vec![],
                router,
                tag: Some(spec.name.clone()),
                stats: None,
                multiplex: None,
                transport_layer: None,
            };

            let join = tokio::spawn(async move {
                let serve = serve_shadowsocks(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        let _ = stop_tx.send(()).await;
                        let _ = serve.await;
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
                        .map(|(host, port)| sb_adapters::inbound::shadowtls::ShadowTlsHandshakeConfig {
                            server: host,
                            server_port: port,
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
                tls: Some(sb_transport::TlsConfig::Standard(sb_transport::tls::StandardTlsConfig {
                    server_name: Some("localhost".to_string()),
                    alpn: vec!["http/1.1".to_string()],
                    insecure: false,
                    cert_path: Some(
                        "vendor/anytls-rs/examples/singbox/certs/anytls.local.crt".to_string(),
                    ),
                    key_path: Some(
                        "vendor/anytls-rs/examples/singbox/certs/anytls.local.key".to_string(),
                    ),
                    cert_pem: None,
                    key_pem: None,
                })),
                router: Some(router),
                stats: None,
            };

            let join = tokio::spawn(async move {
                let serve = serve_shadowtls(cfg, stop_rx);
                tokio::pin!(serve);
                tokio::select! {
                    _ = &mut rx => {
                        let _ = stop_tx.send(()).await;
                        let _ = serve.await;
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
            TrafficAction::TcpRoundTrip {
                name,
                addr,
                payload,
                proxy,
                payload_size,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let actual_payload = resolve_payload(payload, *payload_size);
                let result = match tokio::time::timeout(
                    Duration::from_millis(TCP_ROUNDTRIP_TIMEOUT_MS),
                    async {
                        if let Some(proxy) = resolved_proxy.as_deref() {
                            tcp_roundtrip_via_proxy(proxy, &addr, &actual_payload).await
                        } else {
                            tcp_roundtrip(&addr, &actual_payload).await
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
            TrafficAction::UdpRoundTrip {
                name,
                addr,
                payload,
                proxy,
                payload_size,
            } => {
                let addr = normalize_addr(&harness.resolve_templates(addr));
                let resolved_proxy = proxy.as_ref().map(|p| harness.resolve_templates(p));
                let actual_payload = resolve_payload(payload, *payload_size);
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

/// Resolve the effective payload bytes: if `payload_size` is set, generate
/// a deterministic pattern of that size; otherwise use the literal `payload` string.
fn resolve_payload(payload: &str, payload_size: Option<usize>) -> Vec<u8> {
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

async fn http_get_via_reqwest(url: &str) -> Result<(u16, String)> {
    static CLIENT: std::sync::LazyLock<reqwest::Client> =
        std::sync::LazyLock::new(reqwest::Client::new);
    let response = CLIENT
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

async fn tcp_roundtrip_via_socks5(
    proxy_addr: &str,
    target_addr: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut stream = socks5_connect(proxy_addr, target_addr).await?;
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

    socks5_greet(&mut control).await?;

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
        "id": decoded.id(),
        "message_type": format!("{:?}", decoded.message_type()),
        "rcode": format!("{:?}", decoded.response_code()),
        "answers": decoded.answers().len(),
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
                    let _ = stream.close(None).await;
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

/// SOCKS5 greeting: send auth method, validate server accepts no-auth.
async fn socks5_greet(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(&[0x05_u8, 0x01, 0x00])
        .await
        .with_context(|| "writing socks5 greeting")?;
    let mut resp = [0_u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .with_context(|| "reading socks5 greeting response")?;
    if resp != [0x05, 0x00] {
        return Err(anyhow!(
            "socks5 greeting rejected: version={} method={}",
            resp[0],
            resp[1]
        ));
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

async fn socks5_connect(proxy_addr: &str, target_addr: &str) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .with_context(|| format!("connecting socks5 proxy {proxy_addr}"))?;

    socks5_greet(&mut stream).await?;

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

    let _ = read_socks5_addr_port(&mut stream, resp_head[3]).await?;

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
