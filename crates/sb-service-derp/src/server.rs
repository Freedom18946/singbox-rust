//! DERP service implementation.

use super::client_registry::ClientRegistry;
use super::protocol::{
    clamp_private_key, decode_node_private_key, derive_public_key, encode_node_private_key,
    open_from, seal_to, ClientInfoPayload, DerpFrame, FrameType, PrivateKey, PublicKey,
    ServerInfoPayload, NONCE_LEN, PROTOCOL_VERSION,
};
use bytes::Bytes;
use hyper::body::HttpBody as _;
use hyper::header::{
    CONNECTION, CONTENT_TYPE, LOCATION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY,
    SEC_WEBSOCKET_PROTOCOL, UPGRADE,
};
use hyper::service::service_fn;
use hyper::{
    Body, Method, Request as HyperRequest, Response as HyperResponse, StatusCode, Version,
};
use reqwest::Url;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};
use rustls_pemfile;
use sb_config::ir::{
    DerpDialOptionsIR, DerpMeshPeerIR, DerpOutboundTlsOptionsIR, DerpVerifyClientUrlIR, Listable,
    ServiceIR, StringOrObj,
};
use sb_core::dns::dns_router::{DnsQueryContext, DnsRouter};
use sb_core::service::{Service, ServiceContext, StartStage};
use sb_metrics;
use sb_transport::{DialError, Dialer, FnDialer, IoStream, TransportBuilder};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::io::{self};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

/// DERP service implementation.
///
/// Provides:
/// - STUN server (UDP) for connectivity checks
/// - HTTP server stub (returns 200 OK for root/health, 404 for others)
/// - DERP protocol server (real frame-based client-to-client relay)
/// - TCP mock relay (legacy, for backward compatibility)
use futures::{FutureExt, SinkExt, StreamExt};

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

type RelayStream = Pin<Box<dyn AsyncReadWrite + Send + Unpin>>;

#[derive(Clone, Default)]
struct DerpRuntimeCtx {
    dns_router: Option<Arc<dyn DnsRouter>>,
    outbounds: Option<Arc<sb_core::outbound::OutboundRegistryHandle>>,
}

#[derive(Debug, Clone)]
struct DerpVerifyClientUrlCfg {
    url: Url,
    dial: DerpDialOptionsIR,
}

#[derive(Debug, Clone)]
struct DerpMeshPeerCfg {
    server: String,
    port: u16,
    host: Option<String>,
    tls: Option<DerpOutboundTlsOptionsIR>,
    dial: DerpDialOptionsIR,
}

include!("http_support.rs");

pub struct DerpService {
    tag: Arc<str>,
    listen_addr: SocketAddr,
    // Listen Options (Go parity: option.ListenOptions)
    bind_interface: Option<String>,
    routing_mark: Option<u32>,
    reuse_addr: bool,
    tcp_fast_open: bool,
    tcp_multi_path: bool,

    // STUN options (Go parity: service.derp.stun)
    stun_addr: SocketAddr,
    stun_enabled: bool,
    stun_options: Option<sb_config::ir::DerpStunOptionsIR>,
    mesh_psk: Option<String>,
    home: String,
    server_private_key: PrivateKey,
    server_public_key: PublicKey,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    client_registry: Arc<ClientRegistry>,
    rate_limiter: Arc<RateLimiter>,
    // Legacy mock relay support (backward compatibility)
    pending_relays: Arc<parking_lot::Mutex<HashMap<String, RelayStream>>>,
    running: AtomicBool,
    shutdown_notify: Arc<Notify>,
    stun_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    http_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    mesh_with: Vec<DerpMeshPeerCfg>,
    mesh_tasks: parking_lot::Mutex<Vec<JoinHandle<()>>>,
    /// URLs for client verification (HTTP-based)
    verify_client_urls: Vec<DerpVerifyClientUrlCfg>,
    /// Endpoint tags for client verification (Go parity: endpoint tag list).
    verify_client_endpoint_tags: Vec<String>,
    /// Resolved tailscaled LocalAPI socket paths for verification (populated at PostStart).
    verify_client_endpoint_sockets: Arc<parking_lot::RwLock<Vec<String>>>,

    runtime: DerpRuntimeCtx,
    endpoints: Option<Arc<std::collections::HashMap<String, Arc<dyn sb_core::endpoint::Endpoint>>>>,
}

/// How long to keep a half-open relay connection while waiting for a peer.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct RelayHandshake {
    session: String,
    token: Option<String>,
}

include!("service_lifecycle.rs");
include!("http.rs");
include!("handshake.rs");
include!("mesh.rs");
include!("relay.rs");

/// A stream adapter that replays already-read prefix bytes before delegating to the inner stream.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = self.prefix.len() - self.offset;
            let to_copy = remaining.min(buf.remaining());
            let start = self.offset;
            let end = start + to_copy;
            buf.put_slice(&self.prefix[start..end]);
            self.offset += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Service for DerpService {
    fn service_type(&self) -> &str {
        "derp"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(
                    service = "derp",
                    tag = self.tag.as_ref(),
                    "Initialize stage"
                );
                Ok(())
            }
            StartStage::Start => {
                if self.running.swap(true, Ordering::SeqCst) {
                    return Ok(());
                }

                let listen_addr = self.listen_addr;
                let shutdown = self.shutdown_notify.clone();
                let mesh_psk = self.mesh_psk.clone();
                let client_registry = self.client_registry.clone();
                let server_private_key = self.server_private_key;
                let server_public_key = self.server_public_key;
                let tag = self.tag.clone();
                let home: Arc<str> = Arc::from(self.home.clone().into_boxed_str());
                let runtime = self.runtime.clone();
                let verify_client_urls: Arc<[DerpVerifyClientUrlCfg]> =
                    Arc::from(self.verify_client_urls.clone().into_boxed_slice());
                let verify_client_endpoints = self.verify_client_endpoint_sockets.clone();

                // Pre-bind sockets so failures surface synchronously.
                let http_listener = self.create_listener()?;

                let _http_addr = http_listener.local_addr()?;

                // HTTP stub server (TCP)
                let http_shutdown = shutdown.clone();
                let pending_relays = self.pending_relays.clone();
                let tls_acceptor = self.tls_acceptor.clone();
                let rate_limiter = self.rate_limiter.clone();
                let mesh_psk_http = mesh_psk.clone();
                let verify_client_urls_http = verify_client_urls.clone();
                let verify_client_endpoints_http = verify_client_endpoints.clone();
                let home_http = home.clone();
                let runtime_http = runtime.clone();
                let http_handle = tokio::spawn(async move {
                    if let Err(e) = Self::run_http_server(
                        http_listener,
                        http_shutdown,
                        tag,
                        home_http,
                        rate_limiter,
                        client_registry,
                        server_private_key,
                        server_public_key,
                        pending_relays,
                        mesh_psk_http,
                        runtime_http,
                        verify_client_urls_http,
                        verify_client_endpoints_http,
                        tls_acceptor,
                    )
                    .await
                    {
                        tracing::error!(service = "derp", error = %e, "HTTP server failed");
                    }
                });
                *self.http_task.lock() = Some(http_handle);

                // Optional STUN server (UDP)
                tracing::info!(
                    service = "derp",
                    tag = self.tag.as_ref(),
                    listen = %listen_addr,
                    stun = %self.stun_addr,
                    stun_enabled = self.stun_enabled,
                    "Starting DERP service"
                );

                if self.stun_enabled {
                    let udp_socket = self.create_stun_socket()?;
                    let _stun_addr = udp_socket.local_addr().unwrap_or(self.stun_addr);
                    let tag = self.tag.clone();

                    let stun_shutdown = shutdown.clone();
                    let stun_handle = tokio::spawn(async move {
                        if let Err(e) = Self::run_stun_server(udp_socket, stun_shutdown, tag).await
                        {
                            tracing::error!(service = "derp", error = %e, "STUN server failed");
                        }
                    });

                    *self.stun_task.lock() = Some(stun_handle);
                } else {
                    tracing::info!(
                        service = "derp",
                        tag = self.tag.as_ref(),
                        "STUN disabled for DERP service"
                    );
                }
                // Ensure metrics surface even before clients connect.
                sb_metrics::set_derp_clients(&self.tag, 0);

                Ok(())
            }
            StartStage::PostStart => {
                if !self.verify_client_endpoint_tags.is_empty() {
                    let endpoints = self.endpoints.as_ref().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "verify_client_endpoint configured but no endpoints map injected",
                        )
                    })?;

                    let mut sockets: Vec<String> = Vec::new();
                    for tag in &self.verify_client_endpoint_tags {
                        let ep = endpoints.get(tag).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::NotFound,
                                format!("verify_client_endpoint: endpoint not found: {tag}"),
                            )
                        })?;
                        if ep.endpoint_type() != "tailscale" {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("verify_client_endpoint: endpoint is not tailscale: {tag}"),
                            )
                            .into());
                        }
                        let any = ep.as_ref() as &dyn std::any::Any;
                        let ts = any
                            .downcast_ref::<sb_core::endpoint::tailscale::TailscaleEndpoint>()
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    format!(
                                        "verify_client_endpoint: endpoint downcast failed: {tag}"
                                    ),
                                )
                            })?;
                        let path = ts.localapi_socket_path()?;
                        sockets.push(path);
                    }

                    *self.verify_client_endpoint_sockets.write() = sockets;
                }

                // Mesh peers are started in PostStart (Go parity).
                if !self.mesh_with.is_empty() {
                    let Some(psk) = self.mesh_psk.clone() else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "missing mesh psk",
                        )
                        .into());
                    };
                    let mut tasks = self.mesh_tasks.lock();
                    for peer in &self.mesh_with {
                        let peer = peer.clone();
                        let psk = psk.clone();
                        let tag = self.tag.clone();
                        let runtime = self.runtime.clone();
                        let client_registry = self.client_registry.clone();
                        let server_private_key = self.server_private_key;
                        let server_public_key = self.server_public_key;
                        let shutdown = self.shutdown_notify.clone();
                        let task = tokio::spawn(async move {
                            Self::run_mesh_client(
                                peer,
                                psk,
                                tag,
                                runtime,
                                client_registry,
                                server_private_key,
                                server_public_key,
                                shutdown,
                            )
                            .await;
                        });
                        tasks.push(task);
                    }
                }

                Ok(())
            }
            StartStage::Started => Ok(()),
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(
            service = "derp",
            tag = self.tag.as_ref(),
            "Closing DERP service"
        );

        self.running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();
        sb_metrics::set_derp_clients(&self.tag, 0);

        if let Some(handle) = self.stun_task.lock().take() {
            handle.abort();
        }

        if let Some(handle) = self.http_task.lock().take() {
            handle.abort();
        }

        {
            let mut tasks = self.mesh_tasks.lock();
            for task in tasks.drain(..) {
                task.abort();
            }
        }

        Ok(())
    }
}

/// DERP config file persisted at `config_path` (Go `derpConfig`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DerpConfigFile {
    #[serde(rename = "PrivateKey")]
    private_key: String,
}

/// Load or generate DERP server private key.
///
/// Go reference: `go_fork_source/sing-box-1.13.13/service/derp/service.go` (`readDERPConfig`).
fn load_or_generate_server_private_key(key_path: Option<&str>) -> io::Result<PrivateKey> {
    if let Some(path) = key_path {
        match load_private_key_from_config(path) {
            Ok(key) => {
                tracing::info!(
                    service = "derp",
                    path = path,
                    "Loaded DERP private key from config"
                );
                Ok(key)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::info!(
                    service = "derp",
                    path = path,
                    "Generating new DERP config (file not found)"
                );
                let key = generate_secure_server_private_key()?;
                save_private_key_to_config(path, &key)?;
                tracing::info!(service = "derp", path = path, "Saved new DERP config");
                Ok(key)
            }
            Err(e) => Err(io::Error::other(format!(
                "Failed to load DERP config from {path}: {e}",
            ))),
        }
    } else {
        tracing::warn!(
            service = "derp",
            "No config_path configured - generating ephemeral DERP key (will change on restart)"
        );
        generate_secure_server_private_key()
    }
}

fn generate_secure_server_private_key() -> io::Result<PrivateKey> {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)
        .map_err(|e| io::Error::other(format!("RNG error: {e}")))?;
    clamp_private_key(&mut key);
    Ok(key)
}

fn load_private_key_from_config(path: &str) -> io::Result<PrivateKey> {
    let bytes = fs::read(path)?;
    let cfg: DerpConfigFile = serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid derp config json: {e}"),
        )
    })?;
    decode_node_private_key(&cfg.private_key).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid private key: {e}"),
        )
    })
}

fn save_private_key_to_config(path: &str, key: &PrivateKey) -> io::Result<()> {
    use std::path::Path;

    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }

    let cfg = DerpConfigFile {
        private_key: encode_node_private_key(key),
    };
    let bytes = serde_json::to_vec(&cfg).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialize derp config: {e}"),
        )
    })?;
    fs::write(path, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Load TLS certificates from PEM file.
fn load_tls_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let cert_bytes = fs::read(path)?;
    let mut cursor = std::io::Cursor::new(cert_bytes);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse certificates: {}", e),
            )
        })?;

    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No certificates found in PEM file",
        ));
    }

    Ok(certs)
}

/// Load TLS private key from PEM file.
fn load_tls_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let key_bytes = fs::read(path)?;
    let mut cursor = std::io::Cursor::new(key_bytes);

    loop {
        match rustls_pemfile::read_one(&mut cursor).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse private key: {}", e),
            )
        })? {
            Some(rustls_pemfile::Item::Pkcs8Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs8(k));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs1(k));
            }
            Some(rustls_pemfile::Item::Sec1Key(k)) => {
                return Ok(PrivateKeyDer::Sec1(k));
            }
            Some(_other) => continue,
            None => break,
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "No private key found in PEM file",
    ))
}

/// Create TLS acceptor from certificate and key paths.
fn create_tls_acceptor(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> io::Result<Option<Arc<TlsAcceptor>>> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            sb_tls::ensure_crypto_provider();

            let certs = load_tls_certs(cert)?;
            let private_key = load_tls_private_key(key)?;

            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, private_key)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("TLS configuration error: {}", e),
                    )
                })?;

            // Match Go behavior: advertise HTTP/2 + HTTP/1.1 via ALPN.
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            Ok(Some(Arc::new(TlsAcceptor::from(Arc::new(config)))))
        }
        (None, None) => Ok(None), // No TLS configured
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Both cert_path and key_path must be provided for TLS",
        )),
    }
}

fn load_mesh_psk(
    ir: &ServiceIR,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(psk) = &ir.mesh_psk {
        return Ok(Some(psk.trim().to_string()));
    }

    if let Some(psk_path) = &ir.mesh_psk_file {
        let content = fs::read_to_string(psk_path)?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "mesh_psk_file is empty").into(),
            );
        }
        return Ok(Some(trimmed.to_string()));
    }

    Ok(None)
}

/// Build a DERP service.
pub fn build_derp_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    match DerpService::from_ir(ir, ctx) {
        Ok(service) => Some(service as Arc<dyn Service>),
        Err(e) => {
            tracing::error!(
                service = "derp",
                error = %e,
                "Failed to create DERP service"
            );
            None
        }
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
