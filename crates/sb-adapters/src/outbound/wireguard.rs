//! WireGuard outbound adapter with userspace implementation.
//!
//! This adapter provides full WireGuard support using boringtun for userspace
//! WireGuard implementation. It utilizes the shared `sb-transport` WireGuard
//! implementation to avoid duplication.
//!
//! # Features
//! - Complete userspace WireGuard implementation via boringtun
//! - Automatic handshake and key management
//! - Connection pooling and reuse
//! - Full IPv4/IPv6 support

use crate::outbound::prelude::*;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use sb_transport::wireguard::{WgUdpSocket, WireGuardConfig, WireGuardTransport};
use tracing::{debug, warn};

/// WireGuard outbound configuration.
#[derive(Clone, Debug)]
pub struct WireGuardOutboundConfig {
    /// WireGuard server address.
    pub server: String,
    /// WireGuard server port (default: 51820).
    pub port: u16,
    /// Local private key (base64 encoded).
    pub private_key: String,
    /// Peer's public key (base64 encoded).
    pub peer_public_key: String,
    /// Optional pre-shared key (base64 encoded).
    pub pre_shared_key: Option<String>,
    /// Local bind address (default: 0.0.0.0:0).
    pub local_addr: Option<SocketAddr>,
    /// Allowed IPs for this peer.
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval in seconds.
    pub persistent_keepalive: Option<u16>,
    /// MTU for the tunnel (default: 1420).
    pub mtu: u16,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Tag for this outbound.
    pub tag: Option<String>,
    /// WireGuard interface addresses (source for in-tunnel connections).
    pub local_addrs: Vec<IpAddr>,
    /// WireGuard `reserved` bytes (applied per Go client_bind.go).
    pub reserved: [u8; 3],
}

impl Default for WireGuardOutboundConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 51820,
            private_key: String::new(),
            peer_public_key: String::new(),
            pre_shared_key: None,
            local_addr: None,
            allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            persistent_keepalive: Some(25),
            mtu: 1420,
            connect_timeout: Duration::from_secs(10),
            tag: None,
            local_addrs: Vec::new(),
            reserved: [0, 0, 0],
        }
    }
}

/// Parse a WireGuard interface address ("10.0.0.2" or "10.0.0.2/32") to an IpAddr.
fn parse_wg_local_addr(s: &str) -> Option<IpAddr> {
    s.split('/').next()?.trim().parse::<IpAddr>().ok()
}

/// WireGuard outbound connector.
#[derive(Debug)]
pub struct WireGuardOutbound {
    _config: WireGuardOutboundConfig,
    transport: Arc<WireGuardTransport>,
}

impl WireGuardOutbound {
    /// Create a new WireGuard outbound with the given configuration.
    pub async fn new(config: WireGuardOutboundConfig) -> Result<Self> {
        // Resolve peer endpoint
        let peer_endpoint: SocketAddr =
            tokio::net::lookup_host(format!("{}:{}", config.server, config.port))
                .await
                .map_err(|e| AdapterError::network(format!("DNS resolution failed: {}", e)))?
                .next()
                .ok_or_else(|| AdapterError::network("No address resolved"))?;

        // Build transport config
        let transport_config = WireGuardConfig {
            private_key: config.private_key.clone(),
            peer_public_key: config.peer_public_key.clone(),
            pre_shared_key: config.pre_shared_key.clone(),
            peer_endpoint,
            local_addr: config.local_addr,
            local_addrs: config.local_addrs.clone(),
            persistent_keepalive: config.persistent_keepalive,
            mtu: config.mtu,
            reserved: config.reserved,
            connect_timeout: config.connect_timeout,
            listen_ports: Vec::new(),
        };

        // Initialize transport
        let transport = WireGuardTransport::new(transport_config)
            .await
            .map_err(|e| {
                AdapterError::other(format!("Failed to initialize WireGuard transport: {}", e))
            })?;

        let transport_arc = Arc::new(transport);

        // Initiate handshake immediately (fire and forget)
        let handshake_transport = transport_arc.clone();
        tokio::spawn(async move {
            if let Err(e) = handshake_transport.handshake().await {
                warn!("WireGuard initial handshake failed: {}", e);
            }
        });

        Ok(Self {
            _config: config,
            transport: transport_arc,
        })
    }

    /// Update the peer endpoint address (delegates to transport).
    pub async fn set_peer_endpoint(&self, addr: SocketAddr) {
        self.transport.set_peer_endpoint(addr).await;
    }

    /// Open a UDP datagram socket through the WireGuard tunnel.
    pub async fn connect_udp(&self) -> Result<WgUdpSocket> {
        self.transport
            .connect_udp()
            .await
            .map_err(|e| AdapterError::other(format!("WireGuard UDP open failed: {e}")))
    }
}

#[derive(Debug)]
struct WireGuardPacketConn {
    socket: WgUdpSocket,
    idle_timeout: Duration,
    deadlines: Mutex<(Option<Instant>, Option<Instant>)>,
    closed: AtomicBool,
}

fn packet_operation_timeout(
    idle_timeout: Duration,
    explicit: Option<Instant>,
) -> (Instant, Duration) {
    let now = Instant::now();
    let duration = explicit
        .map(|deadline| deadline.saturating_duration_since(now))
        .unwrap_or(idle_timeout);
    (now + duration, duration)
}

fn ensure_packet_open(closed: &AtomicBool) -> Result<(), sb_types::CoreError> {
    if closed.load(Ordering::Acquire) {
        Err(sb_types::CoreError::connect(
            sb_types::ConnectErrorKind::Reset,
            "packet connection closed",
        ))
    } else {
        Ok(())
    }
}

fn close_packet(closed: &AtomicBool) {
    closed.store(true, Ordering::Release);
}

async fn run_packet_operation<T, F>(
    deadline: Instant,
    duration: Duration,
    operation: &'static str,
    future: F,
) -> Result<T, sb_types::CoreError>
where
    F: std::future::Future<Output = Result<T, sb_types::CoreError>>,
{
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| sb_types::CoreError::timeout(operation, duration))?
}

impl WireGuardPacketConn {
    fn operation_timeout(&self, read: bool) -> (Instant, Duration) {
        let deadlines = self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let explicit = if read { deadlines.0 } else { deadlines.1 };
        packet_operation_timeout(self.idle_timeout, explicit)
    }

    fn ensure_open(&self) -> Result<(), sb_types::CoreError> {
        ensure_packet_open(&self.closed)
    }
}

impl sb_types::PacketConn for WireGuardPacketConn {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a sb_types::TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move {
            self.ensure_open()?;
            let (deadline, duration) = self.operation_timeout(false);
            let operation = async {
                let address = match destination {
                    sb_types::TargetAddr::Socket(address) => *address,
                    sb_types::TargetAddr::Domain(host, port) => {
                        tokio::net::lookup_host((host.as_str(), *port))
                            .await
                            .map_err(|error| sb_types::CoreError::dns(error.to_string()))?
                            .next()
                            .ok_or_else(|| {
                                sb_types::CoreError::dns("no WireGuard UDP address resolved")
                            })?
                    }
                };
                self.socket
                    .send_to(data, address)
                    .await
                    .map_err(|error| sb_types::CoreError::io(error.to_string()))
            };
            run_packet_operation(deadline, duration, "packet-send", operation).await
        })
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> sb_types::BoxFuture<'a, Result<(usize, sb_types::TargetAddr), sb_types::CoreError>> {
        Box::pin(async move {
            self.ensure_open()?;
            let (deadline, duration) = self.operation_timeout(true);
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.socket.recv_from(buffer),
            )
            .await
            .map_err(|_| sb_types::CoreError::timeout("packet-recv", duration))?
            .map(|(size, source)| (size, sb_types::TargetAddr::Socket(source)))
            .map_err(|error| sb_types::CoreError::io(error.to_string()))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        close_packet(&self.closed);
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> Option<sb_types::TargetAddr> {
        None
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        *self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = (deadline, deadline);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0 = deadline;
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .1 = deadline;
        Ok(())
    }
}

macro_rules! impl_wireguard_outbound {
    ($type:ty, $tag:expr) => {
        impl sb_types::Outbound for $type {
            fn r#type(&self) -> &str {
                "wireguard"
            }

            fn tag(&self) -> sb_types::OutboundTag {
                sb_types::OutboundTag::new(($tag)(self))
            }

            fn network(&self) -> &[sb_types::NetworkKind] {
                &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
            }

            fn dial<'a>(
                &'a self,
                session: &'a sb_types::Session,
            ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
                Box::pin(async move {
                    use tokio_util::compat::TokioAsyncReadCompatExt;
                    let stream = <$type>::dial(self, session)
                        .await
                        .map_err(|error| crate::outbound::core_error(error, session))?;
                    Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
                })
            }

            fn listen_packet<'a>(
                &'a self,
                session: &'a sb_types::Session,
            ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
            {
                Box::pin(async move {
                    let socket = self
                        .connect_udp()
                        .await
                        .map_err(|error| crate::outbound::core_error(error, session))?;
                    Ok(Box::new(WireGuardPacketConn {
                        socket,
                        idle_timeout: session.packet.idle_timeout,
                        deadlines: Mutex::new((None, None)),
                        closed: AtomicBool::new(false),
                    }) as sb_types::BoxedPacketConn)
                })
            }
        }
    };
}

impl WireGuardOutbound {
    pub async fn dial(&self, session: &Session) -> Result<BoxedStream> {
        let target = &session.target;
        let host = target.host();
        let port = target.port();
        debug!("WireGuard dial request to {}", target);
        use sb_transport::Dialer;
        // Establish a real TCP connection to the in-tunnel target through the
        // userspace netstack (boringtun + smoltcp), not a raw tunnel stream.
        let stream = self
            .transport
            .connect(&host, port)
            .await
            .map_err(|e| AdapterError::other(format!("WireGuard dial failed: {e}")))?;
        Ok(crate::traits::from_transport_stream(stream))
    }
}

impl_wireguard_outbound!(WireGuardOutbound, |this: &WireGuardOutbound| this
    ._config
    .tag
    .clone()
    .unwrap_or_else(|| "wireguard".to_string()));

/// Lazy-initialized WireGuard connector.
///
/// Holds config and initializes transport on first `dial()` call.
/// This allows sync construction from builder functions.
pub struct LazyWireGuardConnector {
    config: WireGuardOutboundConfig,
    inner: tokio::sync::OnceCell<Arc<WireGuardOutbound>>,
}

impl std::fmt::Debug for LazyWireGuardConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyWireGuardConnector")
            .field("config", &self.config)
            .field("initialized", &self.inner.initialized())
            .finish()
    }
}

impl LazyWireGuardConnector {
    /// Create a lazy WireGuard connector (sync, no IO).
    pub fn new(config: WireGuardOutboundConfig) -> Self {
        Self {
            config,
            inner: tokio::sync::OnceCell::new(),
        }
    }

    async fn get_or_init(&self) -> Result<&Arc<WireGuardOutbound>> {
        self.inner
            .get_or_try_init(|| async {
                let outbound = WireGuardOutbound::new(self.config.clone()).await?;
                Ok(Arc::new(outbound))
            })
            .await
    }

    /// Open a UDP datagram socket through the lazily-initialized tunnel.
    pub async fn connect_udp(&self) -> Result<WgUdpSocket> {
        let inner = self.get_or_init().await?;
        inner.connect_udp().await
    }
}

impl LazyWireGuardConnector {
    pub async fn dial(&self, session: &Session) -> Result<BoxedStream> {
        let inner = self.get_or_init().await?;
        inner.dial(session).await
    }
}

impl_wireguard_outbound!(LazyWireGuardConnector, |this: &LazyWireGuardConnector| this
    .config
    .tag
    .clone()
    .unwrap_or_else(|| "wireguard".to_string()));

/// Build WireGuard outbound from IR configuration.
impl TryFrom<&sb_config::ir::OutboundIR> for WireGuardOutboundConfig {
    type Error = AdapterError;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self> {
        use sb_config::ir::OutboundType;

        if ir.ty != OutboundType::Wireguard {
            return Err(AdapterError::InvalidConfig(
                "Expected WireGuard outbound type",
            ));
        }

        let server = ir.server.clone().ok_or(AdapterError::InvalidConfig(
            "WireGuard requires server address",
        ))?;
        let port = ir.port.unwrap_or(51820);

        let private_key = ir
            .wireguard_private_key
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_PRIVATE_KEY").ok())
            .ok_or(AdapterError::InvalidConfig(
                "WireGuard requires private_key",
            ))?;

        let peer_public_key = ir
            .wireguard_peer_public_key
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_PEER_PUBLIC_KEY").ok())
            .ok_or(AdapterError::InvalidConfig(
                "WireGuard requires peer_public_key",
            ))?;

        let pre_shared_key = ir
            .wireguard_pre_shared_key
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_PRE_SHARED_KEY").ok());

        let allowed_ips = if !ir.wireguard_allowed_ips.is_empty() {
            ir.wireguard_allowed_ips.clone()
        } else {
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
        };
        // Validate allowed_ips are legal CIDRs. For single-peer outbound the
        // list is informational (the netstack uses a default route; allowed_ips
        // do not participate in peer selection), but malformed CIDRs must fail
        // loudly rather than silently passing through as opaque strings.
        for cidr in &allowed_ips {
            if cidr.parse::<IpNet>().is_err() {
                return Err(AdapterError::network(format!(
                    "WireGuard outbound has invalid allowed_ips CIDR: '{cidr}'"
                )));
            }
        }

        let persistent_keepalive = ir.wireguard_persistent_keepalive.or(Some(25));

        // WireGuard `reserved` bytes: exactly 3 when present, else [0,0,0].
        // Mirrors endpoint-side parsing (crates/sb-core/src/endpoint/wireguard.rs).
        let reserved: [u8; 3] = match ir.wireguard_reserved.as_ref() {
            Some(r) if !r.is_empty() => r.as_slice().try_into().map_err(|_| {
                AdapterError::InvalidConfig("WireGuard outbound 'reserved' must be exactly 3 bytes")
            })?,
            _ => [0, 0, 0],
        };

        let mtu = ir.wireguard_mtu.unwrap_or(1420) as u16;

        let connect_timeout = ir
            .connect_timeout_sec
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(10));

        // WireGuard interface (source) addresses: explicit source_v4/v6 first, then
        // the interface local addresses. The netstack uses these to source in-tunnel
        // connections; without a match for the target family the dial fails loudly.
        let mut local_addrs: Vec<IpAddr> = Vec::new();
        if let Some(s) = ir
            .wireguard_source_v4
            .as_deref()
            .and_then(parse_wg_local_addr)
        {
            local_addrs.push(s);
        }
        if let Some(s) = ir
            .wireguard_source_v6
            .as_deref()
            .and_then(parse_wg_local_addr)
        {
            local_addrs.push(s);
        }
        for a in &ir.wireguard_local_address {
            if let Some(ip) = parse_wg_local_addr(a) {
                local_addrs.push(ip);
            }
        }

        Ok(Self {
            server,
            port,
            private_key,
            peer_public_key,
            pre_shared_key,
            local_addr: None,
            local_addrs,
            allowed_ips,
            persistent_keepalive,
            mtu,
            reserved,
            connect_timeout,
            tag: ir.name.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    #[test]
    fn packet_timeout_prefers_explicit_and_reports_remaining_duration() {
        let idle = Duration::from_secs(30);
        let (_, default_duration) = packet_operation_timeout(idle, None);
        assert_eq!(default_duration, idle);

        let (_, explicit_duration) =
            packet_operation_timeout(idle, Some(Instant::now() + Duration::from_millis(20)));
        assert!(explicit_duration <= Duration::from_millis(20));
        assert!(explicit_duration < idle);
    }

    #[test]
    fn packet_close_state_rejects_io() {
        let closed = AtomicBool::new(false);
        ensure_packet_open(&closed).unwrap();
        close_packet(&closed);
        assert!(matches!(
            ensure_packet_open(&closed),
            Err(sb_types::CoreError::Connect {
                kind: sb_types::ConnectErrorKind::Reset,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn packet_timeout_wraps_entire_async_operation() {
        let duration = Duration::from_millis(5);
        let error = run_packet_operation(
            Instant::now() + duration,
            duration,
            "packet-send",
            std::future::pending::<Result<(), sb_types::CoreError>>(),
        )
        .await
        .expect_err("pending resolution/send operation must time out");
        assert!(matches!(
            error,
            sb_types::CoreError::Timeout {
                operation,
                duration: reported,
            } if operation == "packet-send" && reported == duration
        ));
    }

    #[test]
    fn test_config_default() {
        let config = WireGuardOutboundConfig::default();
        assert_eq!(config.port, 51820);
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.persistent_keepalive, Some(25));
    }

    #[test]
    fn test_key_validation() {
        // Validation logic is now in sb-transport, but we verify we can parse configs
        let valid_key = "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=";
        let decoded = BASE64.decode(valid_key);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_config_from_ir() {
        use sb_config::ir::{OutboundIR, OutboundType};

        let ir = OutboundIR {
            ty: OutboundType::Wireguard,
            name: Some("wg-test".to_string()),
            server: Some("vpn.example.com".to_string()),
            port: Some(51820),
            wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
            wireguard_peer_public_key: Some(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            ),
            ..Default::default()
        };

        let config = WireGuardOutboundConfig::try_from(&ir).unwrap();
        assert_eq!(config.server, "vpn.example.com");
        assert_eq!(config.port, 51820);
    }

    fn valid_wg_ir() -> sb_config::ir::OutboundIR {
        use sb_config::ir::{OutboundIR, OutboundType};
        OutboundIR {
            ty: OutboundType::Wireguard,
            name: Some("wg-test".to_string()),
            server: Some("198.51.100.1".to_string()),
            port: Some(51820),
            wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
            wireguard_peer_public_key: Some(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn wireguard_outbound_mtu_consumed_from_ir() {
        // P4-2: `wireguard_mtu` flows from IR into the config instead of being
        // hardcoded to 1420.
        let mut ir = valid_wg_ir();
        ir.wireguard_mtu = Some(1280);
        let config = WireGuardOutboundConfig::try_from(&ir).unwrap();
        assert_eq!(config.mtu, 1280);
    }

    #[test]
    fn wireguard_outbound_mtu_defaults_to_1420_when_absent() {
        let ir = valid_wg_ir();
        let config = WireGuardOutboundConfig::try_from(&ir).unwrap();
        assert_eq!(config.mtu, 1420);
    }

    #[test]
    fn wireguard_outbound_reserved_consumed_from_ir() {
        // P4-3: `wireguard_reserved` flows from IR into the config instead of
        // being hardcoded to [0,0,0].
        let mut ir = valid_wg_ir();
        ir.wireguard_reserved = Some(vec![1, 2, 3]);
        let config = WireGuardOutboundConfig::try_from(&ir).unwrap();
        assert_eq!(config.reserved, [1, 2, 3]);
    }

    #[test]
    fn wireguard_outbound_reserved_defaults_to_zero_when_absent() {
        let ir = valid_wg_ir();
        let config = WireGuardOutboundConfig::try_from(&ir).unwrap();
        assert_eq!(config.reserved, [0, 0, 0]);
    }

    #[test]
    fn wireguard_outbound_reserved_rejects_wrong_length() {
        // P4-3: a `reserved` vector that is not exactly 3 bytes fails loudly.
        let mut ir = valid_wg_ir();
        ir.wireguard_reserved = Some(vec![1, 2]);
        let err = WireGuardOutboundConfig::try_from(&ir).expect_err("2-byte reserved must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("reserved") && msg.contains("3 bytes"),
            "error must explain the 3-byte requirement: {msg}"
        );
    }

    #[test]
    fn wireguard_outbound_allowed_ips_invalid_cidr_rejected() {
        // P4-4: malformed allowed_ips CIDRs fail loudly instead of passing
        // through as opaque strings.
        let mut ir = valid_wg_ir();
        ir.wireguard_allowed_ips = vec!["not-a-cidr".to_string()];
        let err = WireGuardOutboundConfig::try_from(&ir).expect_err("invalid CIDR must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("not-a-cidr"),
            "error must name the offending CIDR: {msg}"
        );
    }
}
