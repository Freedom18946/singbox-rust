//! Hysteria v2 inbound adapter implementation

use crate::error::{AdapterError, Result};
use crate::traits::BoxedStream;
use sb_core::net::metered;
use sb_core::outbound::{
    Endpoint as OutEndpoint, OutboundRegistryHandle, RouteTarget as OutRouteTarget,
};
use sb_core::router::engine::RouteCtx;
use sb_core::router::{self, Transport};
use sb_core::services::v2ray_api::StatsManager;
use sb_transport::IoStream;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

#[cfg(feature = "adapter-hysteria2")]
use sb_core::outbound::hysteria2::inbound::{
    Hysteria2Inbound as CoreInbound, Hysteria2ServerConfig, Hysteria2Stream, Hysteria2User,
    MasqueradeConfig as CoreMasqueradeConfig,
};

/// Hysteria v2 inbound configuration
#[derive(Debug, Clone)]
pub struct Hysteria2InboundConfig {
    pub listen: SocketAddr,
    pub users: Vec<Hysteria2UserConfig>,
    pub cert: String,
    pub key: String,
    pub congestion_control: Option<String>,
    pub salamander: Option<String>,
    pub obfs: Option<String>,
    pub tag: Option<String>,
    pub stats: Option<Arc<StatsManager>>,
    #[cfg(feature = "adapter-hysteria2")]
    pub masquerade: Option<CoreMasqueradeConfig>,
    pub router: Arc<router::RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
}

/// Hysteria v2 user configuration
#[derive(Debug, Clone)]
pub struct Hysteria2UserConfig {
    pub password: String,
}

impl Default for Hysteria2InboundConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([0, 0, 0, 0], 443)),
            users: vec![Hysteria2UserConfig {
                password: "password".to_string(),
            }],
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            congestion_control: Some("bbr".to_string()),
            salamander: None,
            obfs: None,
            tag: None,
            stats: None,
            #[cfg(feature = "adapter-hysteria2")]
            masquerade: None,
            router: Arc::new(router::RouterHandle::from_env()),
            outbounds: Arc::new(OutboundRegistryHandle::default()),
        }
    }
}

/// Hysteria v2 inbound adapter
#[derive(Debug, Clone)]
pub struct Hysteria2Inbound {
    config: Arc<Hysteria2InboundConfig>,
    shutdown: Arc<Notify>,
    active: Arc<AtomicU64>,
    #[cfg(feature = "adapter-hysteria2")]
    _core_marker: std::marker::PhantomData<CoreInbound>,
    #[cfg(not(feature = "adapter-hysteria2"))]
    _phantom: std::marker::PhantomData<()>,
}

impl Hysteria2Inbound {
    pub fn new(config: Hysteria2InboundConfig) -> Result<Self> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            // Validate config
            if config.users.is_empty() {
                return Err(AdapterError::NotImplemented {
                    what: "Hysteria2 requires at least one user",
                });
            }

            Ok(Self {
                config: Arc::new(config),
                shutdown: Arc::new(Notify::new()),
                active: Arc::new(AtomicU64::new(0)),
                _core_marker: std::marker::PhantomData,
            })
        }
    }

    #[cfg(feature = "adapter-hysteria2")]
    pub async fn start_server(&self) -> Result<()> {
        use sb_core::outbound::hysteria2::inbound::Hysteria2Inbound as CoreInbound;

        let cfg = self.config.clone();
        let core_config = Hysteria2ServerConfig {
            listen: cfg.listen,
            users: cfg
                .users
                .iter()
                .map(|u| Hysteria2User {
                    password: u.password.clone(),
                })
                .collect(),
            cert: cfg.cert.clone(),
            key: cfg.key.clone(),
            congestion_control: cfg.congestion_control.clone(),
            salamander: cfg.salamander.clone(),
            obfs: cfg.obfs.clone(),
            masquerade: cfg.masquerade.clone(),
        };

        let core = CoreInbound::new(core_config);
        match core.start().await {
            Ok(()) => {
                // Server started, now continuously accept connections
                let shutdown = self.shutdown.clone();
                let active = self.active.clone();
                loop {
                    tokio::select! {
                        _ = shutdown.notified() => {
                            tracing::info!("Hysteria2: shutdown requested, stopping accept loop");
                            break;
                        }
                        accept_res = core.accept() => {
                            match accept_res {
                                Ok((stream, peer)) => {
                                    tracing::debug!("Hysteria2: accepted connection from {}", peer);
                                    let cfg_clone = cfg.clone();
                                    let active_clone = active.clone();
                                    tokio::spawn(async move {
                                        active_clone.fetch_add(1, Ordering::SeqCst);
                                        if let Err(e) =
                                            Self::handle_connection(stream, peer, cfg_clone.clone()).await
                                        {
                                            tracing::error!(
                                                error = ?e,
                                                "Hysteria2 inbound connection failed for peer {peer}"
                                            );
                                        }
                                        active_clone.fetch_sub(1, Ordering::SeqCst);
                                    });
                                }
                                Err(e) => {
                                    tracing::error!("Hysteria2: accept error: {}", e);
                                    return Err(AdapterError::Io(e));
                                }
                            }
                        }
                    };
                }
                Ok(())
            }
            Err(e) => {
                sb_core::metrics::http::record_error_display(&e);
                sb_core::metrics::record_inbound_error_display("hysteria2", &e);
                Err(AdapterError::Io(e))
            }
        }
    }

    #[cfg(feature = "adapter-hysteria2")]
    #[allow(clippy::too_many_lines)]
    async fn parse_connect_target(
        stream: &mut Hysteria2Stream,
        obfs: Option<&str>,
    ) -> io::Result<(String, u16)> {
        let mut idx = 0usize;
        let mut buf = [0u8; 1];

        stream.read_exact(&mut buf).await?;
        let cmd = Self::deobfuscate_byte(buf[0], obfs, idx);
        idx += 1;
        if cmd != 0x02 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected hysteria2 command: {cmd:#04x}"),
            ));
        }

        stream.read_exact(&mut buf).await?;
        let atyp = Self::deobfuscate_byte(buf[0], obfs, idx);
        idx += 1;

        let host = match atyp {
            0x01 => {
                let mut addr = [0u8; 4];
                for byte in addr.iter_mut() {
                    stream.read_exact(std::slice::from_mut(byte)).await?;
                    *byte = Self::deobfuscate_byte(*byte, obfs, idx);
                    idx += 1;
                }
                IpAddr::from(addr).to_string()
            }
            0x04 => {
                let mut addr = [0u8; 16];
                for byte in addr.iter_mut() {
                    stream.read_exact(std::slice::from_mut(byte)).await?;
                    *byte = Self::deobfuscate_byte(*byte, obfs, idx);
                    idx += 1;
                }
                IpAddr::from(addr).to_string()
            }
            0x03 => {
                stream.read_exact(&mut buf).await?;
                let len = Self::deobfuscate_byte(buf[0], obfs, idx) as usize;
                idx += 1;
                let mut domain = vec![0u8; len];
                if len > 0 {
                    stream.read_exact(&mut domain).await?;
                    for (i, b) in domain.iter_mut().enumerate() {
                        *b = Self::deobfuscate_byte(*b, obfs, idx + i);
                    }
                    idx += len;
                }
                String::from_utf8(domain).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid domain utf8")
                })?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported hysteria2 atyp: {atyp:#04x}"),
                ))
            }
        };

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let p0 = Self::deobfuscate_byte(port_buf[0], obfs, idx);
        let p1 = Self::deobfuscate_byte(port_buf[1], obfs, idx + 1);
        let port = u16::from_be_bytes([p0, p1]);

        Ok((host, port))
    }

    #[cfg(feature = "adapter-hysteria2")]
    async fn connect_via_router(
        router: &router::RouterHandle,
        outbounds: &OutboundRegistryHandle,
        host: &str,
        port: u16,
    ) -> io::Result<(IoStream, Option<String>)> {
        let ctx = RouteCtx {
            host: Some(host),
            ip: None,
            port: Some(port),
            transport: Transport::Tcp,
        };
        let target: OutRouteTarget = router.select_ctx_and_record(ctx);
        let outbound_tag = match &target {
            OutRouteTarget::Named(name) => Some(name.clone()),
            OutRouteTarget::Kind(kind) => Some(format!("{kind:?}").to_ascii_lowercase()),
        };
        let endpoint = match host.parse::<IpAddr>() {
            Ok(ip) => OutEndpoint::Ip(SocketAddr::new(ip, port)),
            Err(_) => OutEndpoint::Domain(host.to_string(), port),
        };

        #[cfg(feature = "v2ray_transport")]
        {
            outbounds
                .connect_preferred(&target, endpoint)
                .await
                .map(|stream| (stream, outbound_tag))
        }
        #[cfg(not(feature = "v2ray_transport"))]
        {
            let stream = outbounds.connect_preferred(&target, endpoint).await?;
            Ok((Box::new(stream), outbound_tag))
        }
    }

    #[cfg(feature = "adapter-hysteria2")]
    fn deobfuscate_byte(byte: u8, obfs: Option<&str>, idx: usize) -> u8 {
        if let Some(key) = obfs {
            let key_bytes = key.as_bytes();
            if key_bytes.is_empty() {
                return byte;
            }
            byte ^ key_bytes[idx % key_bytes.len()]
        } else {
            byte
        }
    }

    #[cfg(feature = "adapter-hysteria2")]
    fn map_error_code(err: &io::Error) -> u8 {
        match err.kind() {
            io::ErrorKind::ConnectionRefused | io::ErrorKind::PermissionDenied => 0x01,
            io::ErrorKind::TimedOut => 0x02,
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::NotFound => 0x03,
            _ => 0x04,
        }
    }

    #[cfg(feature = "adapter-hysteria2")]
    async fn handle_connection(
        mut stream: Hysteria2Stream,
        peer: SocketAddr,
        cfg: Arc<Hysteria2InboundConfig>,
    ) -> Result<()> {
        let (host, port) = match Self::parse_connect_target(&mut stream, cfg.obfs.as_deref()).await
        {
            Ok(dest) => dest,
            Err(e) => {
                tracing::warn!(error = %e, %peer, "hysteria2: failed to parse connect packet");
                let _ = stream.write_all(&[0x03, 0x00]).await;
                return Err(AdapterError::Io(e));
            }
        };
        tracing::debug!(%peer, %host, port, "hysteria2: connect");

        let (mut upstream, outbound_tag) =
            match Self::connect_via_router(&cfg.router, &cfg.outbounds, &host, port).await {
                Ok(s) => s,
                Err(e) => {
                    let code = Self::map_error_code(&e);
                    let _ = stream.write_all(&[code, 0x00]).await;
                    return Err(AdapterError::Io(e));
                }
            };

        if let Err(e) = stream.write_all(&[0x00, 0x00]).await {
            return Err(AdapterError::Io(e));
        }

        let traffic = cfg.stats.as_ref().and_then(|stats| {
            stats.traffic_recorder(cfg.tag.as_deref(), outbound_tag.as_deref(), None)
        });
        metered::copy_bidirectional_streaming_ctl(
            &mut stream,
            &mut upstream,
            "hysteria2",
            Duration::from_secs(1),
            None,
            None,
            None,
            traffic,
        )
        .await
        .map_err(AdapterError::Io)?;

        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        self.start_server().await
    }

    pub async fn accept(&self) -> Result<(BoxedStream, SocketAddr)> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            // This method is not used in the new architecture - start_server handles accept loop
            Err(AdapterError::NotImplemented {
                what: "Direct accept() not supported - use start() instead",
            })
        }
    }
}

impl sb_core::adapter::InboundService for Hysteria2Inbound {
    fn serve(&self) -> std::io::Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "adapter-hysteria2 feature not enabled",
            ));
        }

        #[cfg(feature = "adapter-hysteria2")]
        {
            // Use current tokio runtime or fail
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    let adapter = self.clone();
                    // Start the server
                    handle.spawn(async move {
                        if let Err(e) = adapter.start().await {
                            tracing::error!(error=?e, "Hysteria2 inbound server failed");
                        }
                    });
                    Ok(())
                }
                Err(_) => Err(std::io::Error::other("No tokio runtime available")),
            }
        }
    }

    fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
        tracing::debug!("Hysteria2 inbound shutdown requested");
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Hysteria2InboundConfig::default();
        assert_eq!(config.listen.port(), 443);
        assert_eq!(config.users.len(), 1);
        assert_eq!(config.users[0].password, "password");
    }

    #[cfg(feature = "router")]
    #[tokio::test]
    async fn connect_via_router_reaches_upstream() {
        use sb_core::outbound::{OutboundImpl, OutboundRegistry};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Upstream echo server to validate traffic actually reaches the target.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().unwrap();
        let (echo_tx, echo_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept upstream");
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.expect("read upstream");
            echo_tx.send(buf).ok();
        });

        // Router defaults to "direct"; inject a matching outbound.
        let router = router::RouterHandle::from_env();
        let mut reg = OutboundRegistry::default();
        reg.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = OutboundRegistryHandle::new(reg);

        let (mut stream, _tag) = Hysteria2Inbound::connect_via_router(
            &router,
            &outbounds,
            &upstream_addr.ip().to_string(),
            upstream_addr.port(),
        )
        .await
        .expect("route to upstream");

        stream.write_all(b"ping").await.expect("write to upstream");
        let echoed = echo_rx.await.expect("receive upstream data");
        assert_eq!(&echoed, b"ping");
    }
}
