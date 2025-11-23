//! AnyTLS inbound adapter backed by anytls-rs.
//!
//! This implementation mirrors Go's AnyTLS inbound:
//! - TLS listener (certificate from config or inline PEM)
//! - Multiple user/password support
//! - Optional padding scheme definition
//! - Router-aware outbound selection (direct/proxy)
//! - Full stream relay with SYNACK semantics

use anyhow::{anyhow, Context, Result};
use anytls_rs::padding::PaddingFactory;
use anytls_rs::protocol::{Command, Frame};
use anytls_rs::session::{Session, Stream};
use anytls_rs::util::auth::hash_password;
use anytls_rs::util::AnyTlsError;
use bytes::Bytes;
use sb_core::adapter::{AnyTlsUserParam, InboundParam, InboundService};
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, registry,
    socks5_connect_through_socks5, ConnectOpts, OutboundRegistryHandle,
};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

const ANYTLS_INBOUND_TAG: &str = "anytls";

#[derive(Clone)]
struct AnyTlsServerConfig {
    listen: SocketAddr,
    tls: Arc<TlsAcceptor>,
    padding: Arc<PaddingFactory>,
    users: Arc<Vec<AnyTlsUser>>,
    #[allow(dead_code)]
    router: Arc<router::RouterHandle>,
    #[allow(dead_code)]
    outbounds: Arc<OutboundRegistryHandle>,
}

#[derive(Debug, Clone)]
struct AnyTlsUser {
    name: Option<String>,
    password_hash: [u8; 32],
}

#[derive(Clone)]
struct ConnectionCtx {
    peer_addr: SocketAddr,
    user: Option<String>,
}

pub struct AnyTlsInboundAdapter {
    config: Arc<AnyTlsServerConfig>,
    shutdown_tx: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl std::fmt::Debug for AnyTlsInboundAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsInboundAdapter")
            .field("listen", &self.config.listen)
            .finish()
    }
}

impl AnyTlsInboundAdapter {
    pub fn new(
        param: &InboundParam,
        router: Arc<router::RouterHandle>,
        outbounds: Arc<OutboundRegistryHandle>,
    ) -> std::io::Result<Box<dyn InboundService>> {
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = listen_str.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid listen address '{}': {e}", listen_str),
            )
        })?;

        let tls = build_tls_acceptor(param).map_err(as_io_error)?;
        let padding = build_padding_factory(param).map_err(as_io_error)?;
        let users = prepare_users(param).map_err(as_io_error)?;

        let config = AnyTlsServerConfig {
            listen,
            tls,
            padding,
            users,
            router,
            outbounds,
        };

        Ok(Box::new(Self {
            config: Arc::new(config),
            shutdown_tx: Arc::new(Mutex::new(None)),
        }))
    }
}

impl InboundService for AnyTlsInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        let (stop_tx, stop_rx) = mpsc::channel(1);
        {
            let mut guard = self.shutdown_tx.blocking_lock();
            *guard = Some(stop_tx);
        }
        let cfg = self.config.clone();

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(err) = serve_anytls(cfg, stop_rx).await {
                        error!(error=%err, "anytls: server exited with error");
                    }
                });
                Ok(())
            }
            Err(_) => {
                let runtime = tokio::runtime::Runtime::new()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                runtime
                    .block_on(serve_anytls(cfg, stop_rx))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.blocking_lock().take() {
            let _ = tx.blocking_send(());
        }
    }
}

async fn serve_anytls(cfg: Arc<AnyTlsServerConfig>, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("failed to bind {}", cfg.listen))?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "anytls: server bound");

    loop {
        tokio::select! {
            _ = stop_rx.recv() => {
                info!("anytls: stopping listener");
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, peer)) => {
                        let cfg_clone = cfg.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(cfg_clone, stream, peer).await {
                                warn!(%peer, error=%err, "anytls: connection error");
                            }
                        });
                    }
                    Err(err) => {
                        sb_core::metrics::http::record_error_display(&err);
                        sb_core::metrics::record_inbound_error_display(ANYTLS_INBOUND_TAG, &err);
                        warn!(error=%err, "anytls: accept error");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_connection(
    cfg: Arc<AnyTlsServerConfig>,
    stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let tls_stream = cfg
        .tls
        .accept(stream)
        .await
        .with_context(|| "TLS handshake failed")?;
    let (mut reader, writer) = tokio::io::split(tls_stream);

    let user = authenticate_handshake(&mut reader, cfg.users.as_ref())
        .await
        .map_err(|err| anyhow!("authentication failed: {err}"))?;

    let mut session = Session::new_server(reader, writer, cfg.padding.clone());
    let (stream_tx, mut stream_rx) = tokio::sync::mpsc::unbounded_channel();
    session.set_stream_callback(stream_tx);
    let session = Arc::new(session);
    let conn_ctx = Arc::new(ConnectionCtx {
        peer_addr: peer,
        user,
    });

    let session_for_streams = session.clone();
    let cfg_for_streams = cfg.clone();
    let ctx_for_streams = conn_ctx.clone();
    tokio::spawn(async move {
        while let Some(stream) = stream_rx.recv().await {
            let cfg_inner = cfg_for_streams.clone();
            let ctx_inner = ctx_for_streams.clone();
            let session_inner = session_for_streams.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_stream(cfg_inner, ctx_inner, stream, session_inner).await {
                    warn!(error=%err, "anytls: stream handler error");
                }
            });
        }
    });

    let session_clone = session.clone();
    tokio::spawn(async move {
        if let Err(err) = session_clone.recv_loop().await {
            debug!(error=%err, "anytls: recv loop exited");
        }
    });

    let session_clone = session.clone();
    tokio::spawn(async move {
        if let Err(err) = session_clone.process_stream_data().await {
            debug!(error=%err, "anytls: process_stream_data exited");
        }
    });

    Ok(())
}

async fn handle_stream(
    cfg: Arc<AnyTlsServerConfig>,
    conn_ctx: Arc<ConnectionCtx>,
    stream: Arc<Stream>,
    session: Arc<Session>,
) -> Result<()> {
    let destination = read_socks_destination(stream.clone()).await?;
    let peer_version = session.peer_version();
    let stream_id = stream.id();

    let upstream = match connect_via_router(&destination, conn_ctx.as_ref()).await {
        Ok(conn) => conn,
        Err(err) => {
            send_synack_error(&session, &stream, stream_id, peer_version, &err.to_string()).await;
            return Err(err);
        }
    };

    relay_stream(stream, session, upstream, &destination, peer_version).await
}

async fn relay_stream(
    stream: Arc<Stream>,
    session: Arc<Session>,
    upstream: TcpStream,
    destination: &SocksDestination,
    peer_version: u8,
) -> Result<()> {
    let stream_id = stream.id();
    if peer_version >= 2 {
        let synack = Frame::control(Command::SynAck, stream_id);
        if let Err(err) = session.write_control_frame(synack).await {
            warn!(error=%err, "anytls: failed to send SYNACK");
        }
        stream.notify_synack(Ok(())).await;
    }

    debug!(
        stream_id,
        host = destination.host,
        port = destination.port,
        "anytls: relaying stream"
    );

    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let stream_reader = Arc::clone(stream.reader());
    let stream_for_write = stream.clone();

    let to_upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = {
                let mut guard = stream_reader.lock().await;
                guard.read(&mut buf).await?
            };
            if n == 0 {
                upstream_write.shutdown().await.ok();
                break;
            }
            upstream_write.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    });

    let to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = upstream_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stream_for_write
                .send_data(Bytes::copy_from_slice(&buf[..n]))
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stream send_data failed")
                })?;
        }
        Ok::<(), std::io::Error>(())
    });

    let (res1, res2) = tokio::join!(to_upstream, to_client);
    res1??;
    res2??;
    Ok(())
}

async fn send_synack_error(
    session: &Session,
    stream: &Arc<Stream>,
    stream_id: u32,
    peer_version: u8,
    msg: &str,
) {
    if peer_version >= 2 {
        let frame = Frame::with_data(
            Command::SynAck,
            stream_id,
            Bytes::copy_from_slice(msg.as_bytes()),
        );
        if let Err(err) = session.write_control_frame(frame).await {
            warn!(error=%err, "anytls: failed to send error SYNACK");
        }
        stream
            .notify_synack(Err(AnyTlsError::Protocol(msg.to_string())))
            .await;
    }
}

struct SocksDestination {
    host: String,
    port: u16,
}

async fn read_socks_destination(stream: Arc<Stream>) -> Result<SocksDestination> {
    let reader = stream.reader().clone();
    let mut guard = reader.lock().await;

    let mut atyp = [0u8; 1];
    guard
        .read_exact(&mut atyp)
        .await
        .context("failed to read address type")?;

    let host = match atyp[0] {
        0x01 => {
            let mut buf = [0u8; 4];
            guard
                .read_exact(&mut buf)
                .await
                .context("failed to read IPv4 address")?;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        0x04 => {
            let mut buf = [0u8; 16];
            guard
                .read_exact(&mut buf)
                .await
                .context("failed to read IPv6 address")?;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            guard
                .read_exact(&mut len)
                .await
                .context("failed to read domain length")?;
            let mut buf = vec![0u8; len[0] as usize];
            guard
                .read_exact(&mut buf)
                .await
                .context("failed to read domain")?;
            String::from_utf8(buf).context("invalid domain name")?
        }
        other => return Err(anyhow!("unsupported address type 0x{other:02x}")),
    };

    let mut port_buf = [0u8; 2];
    guard
        .read_exact(&mut port_buf)
        .await
        .context("failed to read port")?;
    let port = u16::from_be_bytes(port_buf);

    Ok(SocksDestination { host, port })
}

async fn connect_via_router(dest: &SocksDestination, ctx: &ConnectionCtx) -> Result<TcpStream> {
    let mut decision = RDecision::Direct;
    if let Some(engine) = rules_global::global() {
        let route_ctx = RouteCtx {
            domain: Some(dest.host.as_str()),
            ip: None,
            transport_udp: false,
            port: Some(dest.port),
            process_name: None,
            process_path: None,
            inbound_tag: Some(ANYTLS_INBOUND_TAG),
            outbound_tag: None,
            auth_user: ctx.user.as_deref(),
            query_type: None,
        };
        let d = engine.decide(&route_ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("destination rejected by router"));
        }
        decision = d;
    }

    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let target = format!("{}:{}", dest.host, dest.port);

    let stream = match decision {
        RDecision::Direct => direct_connect_hostport(&dest.host, dest.port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            if let Some(reg) = registry::global() {
                if reg.pools.contains_key(&name) {
                    let selector = PoolSelector::new(ANYTLS_INBOUND_TAG.into(), "default".into());
                    if let Some(entry) = selector.select(&name, ctx.peer_addr, &target, &()) {
                        match entry.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(
                                    &entry.addr.to_string(),
                                    &dest.host,
                                    dest.port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(
                                    &entry.addr.to_string(),
                                    &dest.host,
                                    dest.port,
                                    &opts,
                                )
                                .await?
                            }
                        }
                    } else {
                        fallback_connect(proxy, &dest.host, dest.port, &opts).await?
                    }
                } else {
                    fallback_connect(proxy, &dest.host, dest.port, &opts).await?
                }
            } else {
                fallback_connect(proxy, &dest.host, dest.port, &opts).await?
            }
        }
        RDecision::Proxy(None) => fallback_connect(proxy, &dest.host, dest.port, &opts).await?,
        RDecision::Reject => return Err(anyhow!("destination rejected by router")),
    };

    Ok(stream)
}

async fn fallback_connect(
    proxy: &ProxyChoice,
    host: &str,
    port: u16,
    opts: &ConnectOpts,
) -> Result<TcpStream> {
    let stream = match proxy {
        ProxyChoice::Direct => direct_connect_hostport(host, port, opts).await?,
        ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, host, port, opts).await?,
        ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, host, port, opts).await?,
    };
    Ok(stream)
}

fn build_tls_acceptor(param: &InboundParam) -> Result<Arc<TlsAcceptor>> {
    let (certs, key) = load_cert_and_key(param)?;
    let builder = rustls::ServerConfig::builder().with_no_client_auth();
    let mut config = builder.with_single_cert(certs, key)?;
    if let Some(alpn) = &param.tls_alpn {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(TlsAcceptor::from(Arc::new(config))))
}

fn load_cert_and_key(
    param: &InboundParam,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_pem = if let Some(pem) = &param.tls_cert_pem {
        pem.clone()
    } else if let Some(path) = &param.tls_cert_path {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read certificate from {}", path))?
    } else {
        return Err(anyhow!(
            "AnyTLS inbound requires tls_cert_pem or tls_cert_path"
        ));
    };

    let key_pem = if let Some(pem) = &param.tls_key_pem {
        pem.clone()
    } else if let Some(path) = &param.tls_key_path {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read private key from {}", path))?
    } else {
        return Err(anyhow!(
            "AnyTLS inbound requires tls_key_pem or tls_key_path"
        ));
    };

    let mut cert_reader = Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in PEM data"));
    }

    let mut key_reader = Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse private key")?
        .ok_or_else(|| anyhow!("no private key found in PEM data"))?;

    Ok((certs, key))
}

fn build_padding_factory(param: &InboundParam) -> Result<Arc<PaddingFactory>> {
    if let Some(lines) = &param.anytls_padding {
        let joined = lines.join("\n");
        let factory = PaddingFactory::new(joined.as_bytes())
            .map_err(|err| anyhow!("invalid padding scheme: {err}"))?;
        Ok(Arc::new(factory))
    } else {
        Ok(PaddingFactory::default())
    }
}

fn prepare_users(param: &InboundParam) -> Result<Arc<Vec<AnyTlsUser>>> {
    let mut users = Vec::new();
    if let Some(explicit) = &param.users_anytls {
        for item in explicit {
            if item.password.trim().is_empty() {
                return Err(anyhow!("AnyTLS user password cannot be empty"));
            }
            users.push(AnyTlsUser {
                name: item.name.clone(),
                password_hash: hash_password(&item.password),
            });
        }
    }

    if users.is_empty() {
        if let Some(password) = &param.password {
            users.push(AnyTlsUser {
                name: None,
                password_hash: hash_password(password),
            });
        }
    }

    if users.is_empty() {
        return Err(anyhow!(
            "AnyTLS inbound requires at least one user/password entry"
        ));
    }

    Ok(Arc::new(users))
}

async fn authenticate_handshake<R: AsyncRead + Unpin>(
    reader: &mut R,
    users: &[AnyTlsUser],
) -> Result<Option<String>> {
    let mut provided = [0u8; 32];
    reader
        .read_exact(&mut provided)
        .await
        .context("failed to read authentication hash")?;

    let Some(user) = users.iter().find(|u| u.password_hash == provided) else {
        // Consume padding fields to keep stream in sync
        let mut skip = [0u8; 2];
        reader.read_exact(&mut skip).await.ok();
        let len = u16::from_be_bytes(skip) as usize;
        if len > 0 {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await.ok();
        }
        return Err(anyhow!("invalid AnyTLS password hash"));
    };

    let mut padding_len = [0u8; 2];
    reader
        .read_exact(&mut padding_len)
        .await
        .context("failed to read padding length")?;
    let padding_len = u16::from_be_bytes(padding_len) as usize;
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        reader
            .read_exact(&mut padding)
            .await
            .context("failed to read padding bytes")?;
    }

    Ok(user.name.clone())
}

fn as_io_error(err: anyhow::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
}
