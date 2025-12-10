use super::{
    CloseHandler, ConnectionHandler, Endpoint, EndpointStream, InboundContext, Network, Socksaddr,
    SocksaddrHost, StartStage,
};
use ipnet::IpNet;
use sb_config::ir::{EndpointIR, EndpointType};
use sb_transport::wireguard::{WireGuardConfig, WireGuardTransport};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tracing::{debug, info, warn};

/// WireGuard endpoint backed by sb-transport's userspace WireGuard.
pub struct WireGuardEndpoint {
    tag: String,
    peers: Vec<PeerConfig>,
    transports: parking_lot::Mutex<Vec<PeerTransport>>,
    /// Local addresses assigned to this WireGuard interface (for loopback detection).
    local_addresses: Vec<IpNet>,
    /// Connection handler for routing inbound connections.
    connection_handler: parking_lot::RwLock<Option<Arc<dyn ConnectionHandler>>>,
    /// DNS resolver for internal name resolution.
    dns_resolver: Option<Arc<dyn crate::dns::Resolver>>,
    /// Router handle for policy checks.
    #[cfg(feature = "router")]
    router: Option<Arc<crate::router::RouterHandle>>,
}

#[derive(Clone)]
struct PeerConfig {
    transport: WireGuardConfig,
    allowed_ips: Vec<IpNet>,
}

struct PeerTransport {
    allowed_ips: Vec<IpNet>,
    transport: Arc<WireGuardTransport>,
}

impl WireGuardEndpoint {
    pub fn new(
        ir: &EndpointIR,
        dns: Option<Arc<dyn crate::dns::Resolver>>,
        #[cfg(feature = "router")] router: Option<Arc<crate::router::RouterHandle>>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let tag = ir.tag.clone().unwrap_or_else(|| "wireguard".to_string());

        let private_key = ir
            .wireguard_private_key
            .clone()
            .ok_or_else(|| format!("wireguard endpoint '{tag}' missing private_key"))?;

        let peers_ir = ir
            .wireguard_peers
            .clone()
            .ok_or_else(|| format!("wireguard endpoint '{tag}' requires at least one peer"))?;

        let mtu = ir.wireguard_mtu.unwrap_or(1420) as u16;
        let local_addr = ir
            .wireguard_listen_port
            .map(|port| SocketAddr::from(([0, 0, 0, 0], port)));

        // Parse local addresses from the address field (used for loopback detection)
        let local_addresses: Vec<IpNet> = ir
            .wireguard_address
            .as_ref()
            .map(|addrs| addrs.iter().filter_map(|s| s.parse().ok()).collect())
            .unwrap_or_default();

        let peers = peers_ir
            .into_iter()
            .map(|peer| {
                let peer_addr: SocketAddr = match (&peer.address, peer.port) {
                    (Some(addr), Some(port)) => {
                        let socket = format!("{addr}:{port}");
                        socket
                            .parse()
                            .map_err(|_| format!("invalid peer address: {socket}"))?
                    }
                    (Some(addr), None) => addr
                        .parse()
                        .map_err(|_| format!("invalid peer address: {addr}"))?,
                    (None, _) => return Err("wireguard peer address missing".to_string()),
                };

                let peer_public_key = peer
                    .public_key
                    .clone()
                    .ok_or_else(|| format!("wireguard endpoint '{tag}' missing peer public_key"))?;

                let pre_shared_key = peer.pre_shared_key.clone();
                let keepalive = peer.persistent_keepalive_interval;

                let allowed_ips: Vec<IpNet> = peer
                    .allowed_ips
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|cidr| cidr.parse().ok())
                    .collect();

                let transport = WireGuardConfig {
                    private_key: private_key.clone(),
                    peer_public_key,
                    pre_shared_key,
                    peer_endpoint: peer_addr,
                    local_addr,
                    persistent_keepalive: keepalive,
                    mtu,
                    connect_timeout: Duration::from_secs(10),
                };

                Ok(PeerConfig {
                    transport,
                    allowed_ips,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("wireguard endpoint '{tag}' peer error: {e}"))?;

        Ok(Self {
            tag,
            peers,
            transports: parking_lot::Mutex::new(Vec::new()),
            local_addresses,

            connection_handler: parking_lot::RwLock::new(None),
            dns_resolver: dns,
            #[cfg(feature = "router")]
            router,
        })
    }

    fn ensure_started(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let handle = Handle::try_current()
            .map_err(|e| format!("WireGuard endpoint requires Tokio runtime: {e}"))?;

        let mut guard = self.transports.lock();
        if !guard.is_empty() {
            return Ok(());
        }

        for peer in &self.peers {
            let transport = handle.block_on(WireGuardTransport::new(peer.transport.clone()))?;
            guard.push(PeerTransport {
                allowed_ips: peer.allowed_ips.clone(),
                transport: Arc::new(transport),
            });
        }
        Ok(())
    }

    /// Select the appropriate peer transport based on destination address.
    ///
    /// This matches the Go behavior: find a peer whose allowed_ips contains
    /// the destination IP, or fall back to the first peer.
    fn select_peer(&self, target_ip: IpAddr) -> Option<Arc<WireGuardTransport>> {
        let transports = self.transports.lock();
        // Match allowed_ips first
        if let Some(pt) = transports
            .iter()
            .find(|pt| pt.allowed_ips.iter().any(|net| net.contains(&target_ip)))
        {
            return Some(pt.transport.clone());
        }
        // Fallback to first peer
        transports.first().map(|pt| pt.transport.clone())
    }

    /// Convert destination to loopback if it matches a local address.
    fn translate_local_destination(&self, dest: &Socksaddr) -> (Socksaddr, Option<Socksaddr>) {
        if let Some(ip) = dest.addr() {
            for local_prefix in &self.local_addresses {
                if local_prefix.contains(&ip) {
                    // Replace with loopback
                    let loopback_ip = if ip.is_ipv4() {
                        IpAddr::V4(Ipv4Addr::LOCALHOST)
                    } else {
                        IpAddr::V6(Ipv6Addr::LOCALHOST)
                    };
                    let translated = Socksaddr {
                        host: SocksaddrHost::Ip(loopback_ip),
                        port: dest.port,
                    };
                    return (translated, Some(dest.clone()));
                }
            }
        }
        (dest.clone(), None)
    }
}

impl Endpoint for WireGuardEndpoint {
    fn endpoint_type(&self) -> &str {
        "wireguard"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize | StartStage::Start => {
                self.ensure_started()?;
                info!(tag = %self.tag, "WireGuard endpoint started");
            }
            StartStage::PostStart | StartStage::Started => {}
        }
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = self.transports.lock();
        if !guard.is_empty() {
            guard.clear();
            info!(tag = %self.tag, "WireGuard endpoint closed");
        }
        Ok(())
    }

    fn local_addresses(&self) -> Vec<IpNet> {
        self.local_addresses.clone()
    }

    fn dial_context(
        &self,
        network: Network,
        destination: Socksaddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<EndpointStream>> + Send + '_>>
    {
        Box::pin(async move {
            // Log the connection attempt
            match network {
                Network::Tcp => {
                    info!(tag = %self.tag, "outbound TCP connection to {}", destination);
                }
                Network::Udp => {
                    info!(tag = %self.tag, "outbound UDP connection to {}", destination);
                }
            }

            // Handle FQDN resolution
            let target_ip = if destination.is_fqdn() {
                let fqdn = destination
                    .fqdn()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected FQDN"))?;

                // Use internal DNS resolver if available, otherwise fallback to system DNS
                if let Some(resolver) = &self.dns_resolver {
                    let answer = resolver
                        .resolve(fqdn)
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                    answer.ips.first().cloned().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("failed to resolve: {}", fqdn),
                        )
                    })?
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "internal DNS resolver required",
                    ));
                }
            } else {
                destination.addr().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid destination: {}", destination),
                    )
                })?
            };

            // Select the appropriate peer
            let transport = self.select_peer(target_ip).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "no WireGuard peer available")
            })?;

            // Dial through the WireGuard tunnel
            debug!(tag = %self.tag, "dialing {} through WireGuard tunnel", target_ip);

            // The WireGuard transport implements Dialer trait
            use sb_transport::Dialer;
            let host = target_ip.to_string();
            let stream = transport
                .connect(&host, destination.port)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;

            Ok(stream)
        })
    }

    fn listen_packet(
        &self,
        destination: Socksaddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Arc<UdpSocket>>> + Send + '_>>
    {
        Box::pin(async move {
            info!(tag = %self.tag, "outbound UDP listen to {}", destination);

            // FIXME: Cannot support userspace UDP tunneling because Endpoint trait requires UdpSocket (OS handle).
            // Binding to 0.0.0.0 causes traffic leak (bypassing WG).
            // Returning error is safer than leaking.
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "WireGuard UDP listen_packet not supported without TUN",
            ))
        })
    }

    fn prepare_connection(
        &self,
        network: Network,
        source: Socksaddr,
        destination: Socksaddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Translate local destination if needed
        let (translated_dest, origin) = self.translate_local_destination(&destination);

        if origin.is_some() {
            debug!(
                tag = %self.tag,
                "prepare_connection: {} {} -> {} (translated from {})",
                network,
                source,
                translated_dest,
                destination
            );
        } else {
            debug!(
                tag = %self.tag,
                "prepare_connection: {} {} -> {}",
                network,
                source,
                destination
            );
        }

        // Integrate with router logic for policy checks
        #[cfg(feature = "router")]
        if let Some(router) = &self.router {
            let host = destination.fqdn();
            let ip = destination.addr();
            let port = Some(destination.port);
            let net_str = match network {
                Network::Tcp => "tcp",
                Network::Udp => "udp",
            };

            let ctx = crate::router::RouteCtx {
                host,
                ip,
                port,
                network: net_str,
                inbound_tag: Some(&self.tag),
                ..Default::default()
            };

            let decision = router.decide(&ctx);
            if let crate::router::rules::Decision::Reject = decision {
                return Err(format!(
                    "connection from {} to {} rejected by rule",
                    source, destination
                )
                .into());
            }
            debug!(tag = %self.tag, "connection allowed by router: {:?}", decision);
        }

        // For now, we just validate that we can route to the destination
        if let Some(ip) = translated_dest.addr() {
            if self.select_peer(ip).is_none() {
                warn!(
                    tag = %self.tag,
                    "no peer available for destination {}",
                    ip
                );
            }
        }

        Ok(())
    }

    fn set_connection_handler(&self, handler: Arc<dyn ConnectionHandler>) {
        let mut guard = self.connection_handler.write();
        *guard = Some(handler);
        debug!(tag = %self.tag, "connection handler registered");
    }

    fn new_connection_ex(
        &self,
        conn: EndpointStream,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // Build metadata
            let mut metadata = InboundContext {
                inbound: self.tag.clone(),
                inbound_type: "wireguard".to_string(),
                network: Some(Network::Tcp),
                source: Some(source.clone()),
                destination: None,
                origin_destination: None,
            };

            // Translate local destination if needed
            let (translated_dest, origin) = self.translate_local_destination(&destination);
            metadata.destination = Some(translated_dest.clone());
            if origin.is_some() {
                metadata.origin_destination = Some(destination.clone());
            }

            info!(
                tag = %self.tag,
                "inbound TCP connection from {} to {}",
                source,
                metadata.destination.as_ref().map(|d| d.to_string()).unwrap_or_default()
            );

            // Get the handler and route the connection
            let handler = {
                let guard = self.connection_handler.read();
                guard.clone()
            };

            if let Some(handler) = handler {
                handler.route_connection(conn, metadata, on_close).await;
            } else {
                warn!(tag = %self.tag, "no connection handler registered, dropping connection");
                if let Some(close) = on_close {
                    close();
                }
            }
        })
    }

    fn new_packet_connection_ex(
        &self,
        socket: Arc<UdpSocket>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // Build metadata
            let mut metadata = InboundContext {
                inbound: self.tag.clone(),
                inbound_type: "wireguard".to_string(),
                network: Some(Network::Udp),
                source: Some(source.clone()),
                destination: None,
                origin_destination: None,
            };

            // Translate local destination if needed
            let (translated_dest, origin) = self.translate_local_destination(&destination);
            metadata.destination = Some(translated_dest.clone());
            if origin.is_some() {
                metadata.origin_destination = Some(destination.clone());
            }

            info!(
                tag = %self.tag,
                "inbound UDP connection from {} to {}",
                source,
                metadata.destination.as_ref().map(|d| d.to_string()).unwrap_or_default()
            );

            // Get the handler and route the connection
            let handler = {
                let guard = self.connection_handler.read();
                guard.clone()
            };

            if let Some(handler) = handler {
                handler
                    .route_packet_connection(socket, metadata, on_close)
                    .await;
            } else {
                warn!(tag = %self.tag, "no connection handler registered, dropping UDP connection");
                if let Some(close) = on_close {
                    close();
                }
            }
        })
    }
}

pub fn build_wireguard_endpoint(
    ir: &EndpointIR,
    ctx: &super::EndpointContext,
) -> Option<Arc<dyn Endpoint>> {
    if ir.ty != EndpointType::Wireguard {
        return None;
    }
    match WireGuardEndpoint::new(
        ir,
        ctx.dns.clone(),
        #[cfg(feature = "router")]
        ctx.router.clone(),
    ) {
        Ok(ep) => Some(Arc::new(ep)),
        Err(e) => {
            tracing::error!(target: "sb_core::endpoint", error = %e, "failed to build WireGuard endpoint");
            None
        }
    }
}
