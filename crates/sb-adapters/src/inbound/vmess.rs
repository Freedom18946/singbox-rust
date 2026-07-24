//! VMess AEAD inbound (TCP) server implementation
//! VMess AEAD 入站 (TCP) 服务端实现
//!
//! Canonical VMess server, wire-compatible with Go `sing-vmess`. The AEAD
//! request header, response header, and chunked AEAD body framing all live in
//! [`crate::vmess`]; this file drives the accept loop, routing, and relay.
//! 与 Go `sing-vmess` 线上兼容的 canonical VMess 服务端。AEAD 请求头、响应头与分块
//! 正文帧位于 [`crate::vmess`]；本文件负责 accept 循环、路由与转发。
//!
//! Protocol flow / 协议流程:
//! 1. Read AuthID + AEAD-sealed request header; verify and parse the target.
//! 1. 读取 AuthID + AEAD 请求头，验证并解析目标地址。
//! 2. Route; connect upstream.
//! 2. 路由决策；连接上游。
//! 3. Write AEAD response header.
//! 3. 写出 AEAD 响应头。
//! 4. Relay through the chunked AEAD body stream.
//! 4. 通过分块 AEAD 正文流双向转发。

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::inbound::connect::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use crate::outbound::pool_selector::PoolSelector;
use crate::vmess;
use sb_core::net::metered;
use sb_core::outbound::registry;
use sb_core::router;
use sb_core::router::rules::Decision as RDecision;
use sb_core::router::{RouteCtx, Transport};
use sb_core::v2ray_stats::StatsManager;

#[derive(Clone)]
pub struct VmessInboundConfig {
    pub listen: SocketAddr,
    pub uuid: Uuid,
    pub security: String, // "aes-128-gcm" or "chacha20-poly1305"
    pub router: Arc<router::RouterHandle>,
    pub tag: Option<String>,
    pub stats: Option<Arc<StatsManager>>,
    pub conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
    /// Optional Multiplex configuration
    /// 可选的多路复用配置
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
    /// V2Ray transport layer configuration (WebSocket, gRPC, HTTPUpgrade)
    /// If None, defaults to TCP
    /// V2Ray 传输层配置 (WebSocket, gRPC, HTTPUpgrade)
    /// 如果为 None，默认为 TCP
    pub transport_layer: Option<crate::transport_config::TransportConfig>,
    /// Fallback target address
    pub fallback: Option<SocketAddr>,
    /// Fallback targets by ALPN
    pub fallback_for_alpn: HashMap<String, SocketAddr>,
    /// Prebuilt raw-TCP TLS acceptor. Certificate/key material is loaded before
    /// listener startup and never re-read per connection.
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    /// Bound each TLS handshake independently.
    pub tls_handshake_timeout: Duration,
}

impl std::fmt::Debug for VmessInboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessInboundConfig")
            .field("listen", &self.listen)
            .field("uuid", &self.uuid)
            .field("security", &self.security)
            .field("tag", &self.tag)
            .field("multiplex", &self.multiplex)
            .field("transport_layer", &self.transport_layer)
            .field("fallback", &self.fallback)
            .field("fallback_for_alpn", &self.fallback_for_alpn)
            .field("tls", &self.tls.is_some())
            .field("tls_handshake_timeout", &self.tls_handshake_timeout)
            .finish_non_exhaustive()
    }
}

pub async fn serve(cfg: VmessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    serve_inner(cfg, &mut stop_rx, None).await
}

async fn serve_inner(
    cfg: VmessInboundConfig,
    stop_rx: &mut mpsc::Receiver<()>,
    mut ready: Option<sb_core::adapter::InboundReadySender>,
) -> Result<()> {
    // The server honors the security type the client selects in its request
    // header (canonical VMess behavior); `cfg.security` is validated only to
    // reject obvious misconfiguration.
    match cfg.security.to_ascii_lowercase().as_str() {
        "aes-128-gcm" | "chacha20-poly1305" | "auto" | "none" | "zero" | "" => {}
        other => {
            let error = anyhow!("Unsupported VMess security: {other}");
            report_ready_error(&mut ready, &error);
            return Err(error);
        }
    }

    // Create listener based on transport configuration (defaults to TCP if not specified)
    // 根据传输配置创建监听器 (如果未指定则默认为 TCP)
    let transport = cfg.transport_layer.clone().unwrap_or_default();
    if cfg.tls.is_some()
        && transport.transport_type() != crate::transport_config::TransportType::Tcp
    {
        let error = anyhow!(
            "vmess: TLS with {:?} transport requires transport-owned termination; refusing plain or double TLS",
            transport.transport_type()
        );
        report_ready_error(&mut ready, &error);
        return Err(error);
    }
    let listener = match transport.create_inbound_listener(cfg.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            report_ready_error(&mut ready, &error);
            return Err(error.into());
        }
    };
    let actual = listener.local_addr().unwrap_or(cfg.listen);

    info!(
        addr=?cfg.listen,
        actual=?actual,
        transport=?transport.transport_type(),
        multiplex=?cfg.multiplex.is_some(),
        "vmess: inbound bound"
    );
    if let Some(sender) = ready.take() {
        let _ = sender.send(Ok(()));
    }

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => {
                // debug!("vmess: accept-loop heartbeat");
            }
            r = listener.accept() => {
                let (stream, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "vmess: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("vmess", &e);
                        continue;
                    }
                };
                let cfg_clone = cfg.clone();

                tokio::spawn(async move {
                    let stream = if let Some(acceptor) = &cfg_clone.tls {
                        match tokio::time::timeout(
                            cfg_clone.tls_handshake_timeout,
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                let negotiated_alpn = stream
                                    .get_ref()
                                    .1
                                    .alpn_protocol()
                                    .map(|value| String::from_utf8_lossy(value).into_owned());
                                let negotiated_version = stream.get_ref().1.protocol_version();
                                info!(
                                    %peer,
                                    alpn=?negotiated_alpn,
                                    version=?negotiated_version,
                                    "vmess: TLS handshake complete"
                                );
                                Box::new(stream) as Box<dyn crate::transport_config::InboundStream>
                            }
                            Ok(Err(error)) => {
                                warn!(%peer, error=%error, "vmess: TLS handshake failed");
                                sb_core::metrics::record_inbound_error_display("vmess", &error);
                                return;
                            }
                            Err(_) => {
                                warn!(
                                    %peer,
                                    timeout_ms=cfg_clone.tls_handshake_timeout.as_millis(),
                                    "vmess: TLS handshake timed out"
                                );
                                sb_core::metrics::record_inbound_error_display(
                                    "vmess",
                                    &"TLS handshake timeout",
                                );
                                return;
                            }
                        }
                    } else {
                        stream
                    };
                    if let Some(mux_cfg) = &cfg_clone.multiplex {
                        use futures::future::poll_fn;
                        use sb_transport::yamux::{Config, Connection, Mode};
                        use tokio_util::compat::TokioAsyncReadCompatExt;

                        let mut config = Config::default();
                        config.set_max_num_streams(mux_cfg.max_num_streams);
                        let mut connection = Connection::new(stream.compat(), config, Mode::Server);
                        while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                            match result {
                                Ok(stream) => {
                                    let cfg_inner = cfg_clone.clone();
                                    tokio::spawn(async move {
                                        use tokio_util::compat::FuturesAsyncReadCompatExt;
                                        let mut stream = stream.compat();
                                        if let Err(e) = handle_conn_stream(
                                            &cfg_inner,
                                            peer,
                                            &mut stream,
                                        ).await {
                                            warn!(%peer, error=%e, "vmess: mux stream error");
                                        }
                                    });
                                }
                                Err(e) => {
                                    warn!(%peer, error=%e, "vmess: mux connection error");
                                    break;
                                }
                            }
                        }
                    } else {
                        let mut stream = stream;
                        if let Err(e) = handle_conn_stream(
                            &cfg_clone,
                            peer,
                            &mut *stream,
                        ).await {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("vmess", &e);
                            warn!(error=%e, "vmess: session error");
                            let _ = stream.shutdown().await;
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

fn report_ready_error<E: std::fmt::Display>(
    ready: &mut Option<sb_core::adapter::InboundReadySender>,
    error: &E,
) {
    if let Some(sender) = ready.take() {
        let _ = sender.send(Err(std::io::Error::other(error.to_string())));
    }
}

async fn handle_fallback(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    target: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    let mut remote = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|e| anyhow!("vmess: failed to connect to fallback {}: {}", target, e))?;

    if !prefix.is_empty() {
        remote.write_all(prefix).await?;
    }

    let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
    Ok(())
}

// Helper function to handle connections from generic streams (trait objects)
// 处理来自通用流 (trait 对象) 连接的辅助函数
async fn handle_conn_stream(
    cfg: &VmessInboundConfig,
    peer: SocketAddr,
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
) -> Result<()> {
    handle_conn(cfg, peer, stream).await
}

async fn handle_conn(
    cfg: &VmessInboundConfig,
    peer: SocketAddr,
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
) -> Result<()> {
    let cmd_key = vmess::command_key(cfg.uuid.as_bytes());

    // Step 1: read the AuthID + AEAD-sealed request header, honoring fallback on
    // authentication or parse failure (forwarding the consumed bytes).
    // 步骤 1: 读取 AuthID + AEAD 请求头，鉴权/解析失败时按 fallback 转发已消费字节。
    let mut prefix = [0u8; vmess::SERVER_PREFIX_LEN];
    if let Err(e) = cli.read_exact(&mut prefix).await {
        return Err(anyhow!("vmess: failed to read request prefix: {e}"));
    }
    let (header_len, auth_id, conn_nonce) = match vmess::server_parse_length(&cmd_key, &prefix) {
        Ok(v) => v,
        Err(e) => {
            if let Some(fallback_addr) = cfg.fallback {
                debug!("vmess: auth failure, falling back to {}", fallback_addr);
                return handle_fallback(cli, fallback_addr, &prefix).await;
            }
            return Err(e);
        }
    };
    let mut enc_header = vec![0u8; header_len + vmess::CIPHER_OVERHEAD];
    cli.read_exact(&mut enc_header).await?;
    let request = match vmess::server_parse_header(&cmd_key, &auth_id, &conn_nonce, &enc_header) {
        Ok(r) => r,
        Err(e) => {
            if let Some(fallback_addr) = cfg.fallback {
                let mut consumed = prefix.to_vec();
                consumed.extend_from_slice(&enc_header);
                debug!(
                    "vmess: header parse failure, falling back to {}",
                    fallback_addr
                );
                return handle_fallback(cli, fallback_addr, &consumed).await;
            }
            return Err(e);
        }
    };

    let target_host = request.host.clone();
    let target_port = request.port;
    debug!(host=%target_host, port=%target_port, "vmess: parsed target");

    // Step 2: Router decision
    // 步骤 2: 路由决策
    let target_ip = target_host.parse::<IpAddr>().ok();
    let route_ctx = RouteCtx {
        host: target_ip.is_none().then_some(target_host.as_str()),
        ip: target_ip,
        port: Some(target_port),
        transport: Transport::Tcp,
        network: "tcp",
        inbound_tag: cfg.tag.as_deref(),
        ..Default::default()
    };
    let route_meta = cfg.router.decide_with_meta(&route_ctx);
    let decision = route_meta.decision;
    let rule = route_meta.rule;
    if matches!(decision, RDecision::Reject) {
        return Err(anyhow!("vmess: rejected by rules"));
    }

    // Step 6: Connect to upstream
    // 步骤 6: 连接上游
    let opts = ConnectOpts;
    // Match by reference so we can still use `decision` later (conntrack/chain computation).
    let (mut upstream, outbound_tag) = match &decision {
        RDecision::Direct => {
            let s = direct_connect_hostport(&target_host, target_port, &opts).await?;
            (s, Some("direct".to_string()))
        }
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("vmess".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(_pool) = reg.pools.get(name) {
                    // Use a dummy peer address for pool selection (transport layer abstraction means we don't have the real peer)
                    // 使用虚拟对等地址进行池选择 (传输层抽象意味着我们没有真正的对等端)
                    let dummy_peer = SocketAddr::from(([0, 0, 0, 0], 0));
                    if let Some(ep) = sel.select(
                        name.as_str(),
                        dummy_peer,
                        &format!("{}:{}", target_host, target_port),
                        &(),
                    ) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                let s = http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &target_host,
                                    target_port,
                                    &opts,
                                )
                                .await?;
                                (s, Some("http".to_string()))
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                let s = socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &target_host,
                                    target_port,
                                    &opts,
                                )
                                .await?;
                                (s, Some("socks5".to_string()))
                            }
                        }
                    } else {
                        return Err(anyhow!(
                            "vmess: named proxy decision '{}' has no selectable endpoint; implicit fallback is disabled; use adapter bridge/supervisor path",
                            name
                        ));
                    }
                } else {
                    return Err(anyhow!(
                        "vmess: named proxy decision '{}' not found in registry; implicit fallback is disabled; use adapter bridge/supervisor path",
                        name
                    ));
                }
            } else {
                return Err(anyhow!(
                    "vmess: named proxy decision '{}' cannot be resolved because registry is unavailable; implicit fallback is disabled; use adapter bridge/supervisor path",
                    name
                ));
            }
        }
        RDecision::Proxy(None) => {
            return Err(anyhow!(
                "vmess: proxy decision without outbound tag is unsupported; implicit fallback is disabled; provide explicit outbound in routing"
            ));
        }
        RDecision::Reject | RDecision::RejectDrop => {
            return Err(anyhow!("vmess: rejected by rules"))
        }
        // Sniff/Resolve/Hijack not yet supported in inbound handlers
        _ => return Err(anyhow!("vmess: unsupported routing action")),
    };

    // Step 4: write the AEAD response header and wrap the body stream.
    // 步骤 4: 写出 AEAD 响应头并包装 canonical 正文流。
    let mut svr = vmess::server_finish(&mut *cli, &request.keys)
        .await
        .map_err(|e| anyhow!("vmess: response handshake failed: {e}"))?;

    // Step 5: bidirectional relay through the chunked AEAD body stream.
    // 步骤 5: 通过分块 AEAD 正文流双向转发。
    let traffic = cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(cfg.tag.as_deref(), outbound_tag.as_deref(), None)
    });
    let chains = sb_core::outbound::chain::compute_chain_for_decision(
        None,
        &decision,
        outbound_tag.as_deref(),
    );
    let wiring = sb_core::conntrack::register_inbound_tcp_with_tracker(
        cfg.conn_tracker.clone(),
        peer,
        target_host.clone(),
        target_port,
        target_host.clone(),
        "vmess",
        cfg.tag.clone(),
        outbound_tag.clone(),
        chains,
        rule.clone(),
        None,
        None,
        traffic,
    );
    let _guard = wiring.guard;
    let copy_res = metered::copy_bidirectional_streaming_ctl(
        &mut svr,
        &mut upstream,
        "vmess",
        Duration::from_secs(1),
        None,
        None,
        Some(wiring.cancel),
        Some(wiring.traffic),
    )
    .await;
    if let Err(e) = copy_res {
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }

    Ok(())
}

/// Parse a decrypted VMess request header into `(host, port, security)`.
/// Retained as a stable entry point for fuzzing the header parser.
/// 解析已解密的 VMess 请求头，供 fuzz 复用。
pub fn parse_vmess_request(data: &[u8]) -> Result<(String, u16, u8)> {
    let p = vmess::parse_request_header(data)?;
    Ok((p.host, p.port, p.security))
}

use parking_lot::Mutex;
use sb_core::adapter::{InboundReadySender, InboundTaskDriver};

#[derive(Debug)]
pub struct VmessInboundAdapter {
    config: VmessInboundConfig,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl VmessInboundAdapter {
    pub fn new(config: VmessInboundConfig) -> Self {
        Self {
            config,
            stop_tx: Mutex::new(None),
        }
    }
}

impl InboundTaskDriver for VmessInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        self.serve_with_ready(None)
    }

    fn supports_startup_readiness(&self) -> bool {
        true
    }

    fn serve_with_ready(&self, ready: Option<InboundReadySender>) -> std::io::Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        *self.stop_tx.lock() = Some(tx);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(std::io::Error::other)?;
        rt.block_on(async { serve_inner(self.config.clone(), &mut rx, ready).await })
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.try_send(());
        }
    }
}
