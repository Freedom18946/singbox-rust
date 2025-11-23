//! WireGuard outbound implementation backed by a system interface.
//!
//! This MVP does not embed a WireGuard stack. Instead, it binds outgoing
//! sockets to an existing system interface (e.g. `wg0`) so that traffic is
//! forwarded through a WireGuard tunnel configured outside of singbox-rust.

#[cfg(feature = "out_wireguard")]
use async_trait::async_trait;
#[cfg(feature = "out_wireguard")]
use sb_config::ir::OutboundIR;
#[cfg(feature = "out_wireguard")]
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(feature = "out_wireguard")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(feature = "out_wireguard")]
use std::{io, sync::Arc, time::Duration};
#[cfg(feature = "out_wireguard")]
use tokio::net::{lookup_host, TcpStream, UdpSocket};
#[cfg(feature = "out_wireguard")]
use tokio::time::timeout;

#[cfg(feature = "out_wireguard")]
use super::crypto_types::{HostPort, OutboundTcp};
#[cfg(feature = "out_wireguard")]
use crate::adapter::{UdpOutboundFactory, UdpOutboundSession};

/// WireGuard outbound configuration.
#[cfg(feature = "out_wireguard")]
#[derive(Clone, Debug)]
pub struct WireGuardConfig {
    /// Optional remote server (reserved for future parity work).
    pub server: Option<String>,
    /// Optional remote port (reserved for future parity work).
    pub port: Option<u16>,
    /// Private key (base64) if provided via env.
    pub private_key: Option<String>,
    /// Public key derived from private key (optional).
    pub public_key: Option<String>,
    /// Remote peer public key (optional).
    pub peer_public_key: Option<String>,
    /// Optional pre-shared key for peers.
    pub pre_shared_key: Option<String>,
    /// Allowed IPs advertised by remote peer.
    pub allowed_ips: Vec<String>,
    /// Explicit endpoint override for peer.
    pub endpoint: Option<String>,
    /// Persistent keep-alive value negotiated with remote peer.
    pub persistent_keepalive: Option<u16>,
    /// System interface to bind sockets to (e.g., `wg0`).
    pub interface: Option<String>,
    /// Source IPv4 address to bind outbound sockets to.
    pub source_ipv4: Option<Ipv4Addr>,
    /// Source IPv6 address to bind outbound sockets to.
    pub source_ipv6: Option<Ipv6Addr>,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// TCP keepalive interval.
    pub tcp_keepalive: Option<Duration>,
}

#[cfg(feature = "out_wireguard")]
impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            server: None,
            port: None,
            private_key: None,
            public_key: None,
            peer_public_key: None,
            pre_shared_key: None,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            endpoint: None,
            persistent_keepalive: None,
            interface: None,
            source_ipv4: None,
            source_ipv6: None,
            connect_timeout: Duration::from_secs(10),
            tcp_keepalive: Some(Duration::from_secs(25)),
        }
    }
}

#[cfg(feature = "out_wireguard")]
impl WireGuardConfig {
    /// Build configuration from IR + environment variables.
    pub fn from_ir(ir: &OutboundIR) -> Result<Self, String> {
        let server = ir
            .server
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_SERVER").ok());
        let port = ir.port.or_else(|| {
            std::env::var("SB_WIREGUARD_PORT")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
        });

        let interface = ir
            .wireguard_interface
            .clone()
            .or_else(|| std::env::var("SB_WIREGUARD_INTERFACE").ok())
            .ok_or_else(|| {
                "WireGuard outbound requires `interface_name` or SB_WIREGUARD_INTERFACE to reference a system interface"
                    .to_string()
            })?;

        let mut allowed_ips = if !ir.wireguard_allowed_ips.is_empty() {
            ir.wireguard_allowed_ips.clone()
        } else if let Some(raw) = std::env::var("SB_WIREGUARD_ALLOWED_IPS").ok() {
            raw.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
        } else {
            vec!["0.0.0.0/0".to_string()]
        };
        if allowed_ips.is_empty() {
            allowed_ips.push("0.0.0.0/0".to_string());
        }

        let endpoint = std::env::var("SB_WIREGUARD_ENDPOINT").ok();
        let persistent_keepalive = ir.wireguard_persistent_keepalive.or_else(|| {
            std::env::var("SB_WIREGUARD_KEEPALIVE_SECS")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
        });

        let mut source_ipv4 = ir.wireguard_source_v4.as_ref().and_then(|s| parse_ipv4(s));
        if source_ipv4.is_none() {
            source_ipv4 = first_ipv4(&ir.wireguard_local_address);
        }
        if source_ipv4.is_none() {
            source_ipv4 = std::env::var("SB_WIREGUARD_SOURCE_V4")
                .ok()
                .and_then(|v| parse_ipv4(&v));
        }

        let mut source_ipv6 = ir.wireguard_source_v6.as_ref().and_then(|s| parse_ipv6(s));
        if source_ipv6.is_none() {
            source_ipv6 = first_ipv6(&ir.wireguard_local_address);
        }
        if source_ipv6.is_none() {
            source_ipv6 = std::env::var("SB_WIREGUARD_SOURCE_V6")
                .ok()
                .and_then(|v| parse_ipv6(&v));
        }

        let connect_timeout = if let Some(secs) = ir.connect_timeout_sec {
            Duration::from_secs(secs as u64)
        } else {
            std::env::var("SB_WIREGUARD_CONNECT_TIMEOUT_MS")
                .ok()
                .map(|v| {
                    v.parse::<u64>()
                        .map(Duration::from_millis)
                        .map_err(|e| format!("invalid SB_WIREGUARD_CONNECT_TIMEOUT_MS: {e}"))
                })
                .transpose()?
                .unwrap_or_else(|| Duration::from_secs(10))
        };

        let tcp_keepalive = std::env::var("SB_WIREGUARD_TCP_KEEPALIVE_SECS")
            .ok()
            .map(|v| {
                v.parse::<u64>()
                    .map(|secs| Duration::from_secs(secs.max(1)))
                    .map_err(|e| format!("invalid SB_WIREGUARD_TCP_KEEPALIVE_SECS: {e}"))
            })
            .transpose()?;

        Ok(Self {
            server,
            port,
            private_key: ir
                .wireguard_private_key
                .clone()
                .or_else(|| std::env::var("SB_WIREGUARD_PRIVATE_KEY").ok()),
            public_key: std::env::var("SB_WIREGUARD_PUBLIC_KEY").ok(),
            peer_public_key: ir
                .wireguard_peer_public_key
                .clone()
                .or_else(|| std::env::var("SB_WIREGUARD_PEER_PUBLIC_KEY").ok()),
            allowed_ips,
            endpoint,
            persistent_keepalive,
            interface: Some(interface),
            source_ipv4,
            source_ipv6,
            connect_timeout,
            tcp_keepalive,
            pre_shared_key: ir
                .wireguard_pre_shared_key
                .clone()
                .or_else(|| std::env::var("SB_WIREGUARD_PRE_SHARED_KEY").ok()),
        })
    }
}

/// Outbound implementation that binds sockets to a WireGuard interface.
#[cfg(feature = "out_wireguard")]
#[derive(Debug)]
pub struct WireGuardOutbound {
    config: WireGuardConfig,
}

#[cfg(feature = "out_wireguard")]
impl WireGuardOutbound {
    pub fn new(config: WireGuardConfig) -> anyhow::Result<Self> {
        Ok(Self { config })
    }

    fn interface_name(&self) -> Option<&str> {
        self.config.interface.as_deref()
    }

    fn source_addr_for(&self, addr: &SocketAddr) -> Option<SocketAddr> {
        match addr {
            SocketAddr::V4(_) => self
                .config
                .source_ipv4
                .map(|ip| SocketAddr::new(IpAddr::V4(ip), 0)),
            SocketAddr::V6(_) => self
                .config
                .source_ipv6
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), 0)),
        }
    }

    async fn connect_addr(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let domain = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        socket.set_tcp_nodelay(true)?;

        if let Some(duration) = self.config.tcp_keepalive {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(duration)
                .with_interval(duration);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let keepalive = keepalive.with_retries(5);
            socket.set_tcp_keepalive(&keepalive)?;
        }

        if let Some(bind_addr) = self.source_addr_for(&addr) {
            socket.bind(&SockAddr::from(bind_addr))?;
        }

        if let Some(iface) = self.interface_name() {
            bind_socket_to_device(&socket, iface)?;
        }

        match socket.connect(&SockAddr::from(addr)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        std_stream.set_nonblocking(true)?;
        std_stream.set_nodelay(true)?;
        let stream = TcpStream::from_std(std_stream)?;

        timeout(self.config.connect_timeout, wait_stream_connected(&stream)).await??;
        Ok(stream)
    }

    fn record_connect_metrics(&self, result: &'static str) {
        #[cfg(feature = "metrics")]
        {
            use metrics::counter;
            counter!("wireguard_connect_total", "result" => result).increment(1);
        }
        let _ = result;
    }

    async fn ensure_udp_socket(&self) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        if let Some(ip) = self.config.source_ipv4 {
            let bind_addr = SocketAddr::new(IpAddr::V4(ip), 0);
            socket.bind(&SockAddr::from(bind_addr))?;
        } else {
            let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            socket.bind(&SockAddr::from(bind_addr))?;
        }
        if let Some(iface) = self.interface_name() {
            bind_socket_to_device(&socket, iface)?;
        }
        let std_sock: std::net::UdpSocket = socket.into();
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }
}

#[cfg(feature = "out_wireguard")]
#[async_trait]
impl OutboundTcp for WireGuardOutbound {
    type IO = TcpStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        let mut last_err = None;
        let lookup = format!("{}:{}", target.host, target.port);
        let mut iter = lookup_host(lookup).await?;
        while let Some(addr) = iter.next() {
            match self.connect_addr(addr).await {
                Ok(stream) => {
                    self.record_connect_metrics("ok");
                    return Ok(stream);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        let err = last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses resolved")
        });
        let kind = err.kind();
        self.record_connect_metrics(if kind == io::ErrorKind::TimedOut {
            "timeout"
        } else {
            "error"
        });
        Err(err)
    }

    fn protocol_name(&self) -> &'static str {
        "wireguard"
    }
}

#[cfg(feature = "out_wireguard")]
impl UdpOutboundFactory for WireGuardOutbound {
    fn open_session(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<Arc<dyn UdpOutboundSession>>> + Send>,
    > {
        let cfg = self.config.clone();
        Box::pin(async move {
            let socket = WireGuardOutbound { config: cfg }
                .ensure_udp_socket()
                .await?;
            Ok(Arc::new(WireGuardUdpSession { socket }) as Arc<dyn UdpOutboundSession>)
        })
    }
}

/// UDP session implementation backed by a single IPv4 socket.
#[cfg(feature = "out_wireguard")]
#[derive(Debug)]
struct WireGuardUdpSession {
    socket: UdpSocket,
}

#[cfg(feature = "out_wireguard")]
#[async_trait]
impl UdpOutboundSession for WireGuardUdpSession {
    async fn send_to(&self, data: &[u8], host: &str, port: u16) -> io::Result<()> {
        let mut iter = lookup_host((host, port)).await?;
        while let Some(addr) = iter.next() {
            if addr.is_ipv4() {
                let _ = self.socket.send_to(data, addr).await?;
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no IPv4 address resolved for UDP session",
        ))
    }

    async fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 64 * 1024];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, addr))
    }
}

#[cfg(feature = "out_wireguard")]
async fn wait_stream_connected(stream: &TcpStream) -> io::Result<()> {
    loop {
        stream.writable().await?;
        match stream.take_error()? {
            Some(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Some(err) => return Err(err),
            None => return Ok(()),
        }
    }
}

#[cfg(feature = "out_wireguard")]
fn bind_socket_to_device(socket: &Socket, iface: &str) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;

        let c_iface = CString::new(iface).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name contains interior null byte",
            )
        })?;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                c_iface.as_ptr() as *const libc::c_void,
                c_iface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = socket;
        tracing::warn!(
            target: "wireguard",
            interface = %iface,
            "binding to interface is not supported on this platform"
        );
        Ok(())
    }
}

#[cfg(feature = "out_wireguard")]
fn extract_ip_component(spec: &str) -> &str {
    spec.split('/').next().unwrap_or(spec)
}

#[cfg(feature = "out_wireguard")]
fn parse_ipv4(spec: &str) -> Option<Ipv4Addr> {
    extract_ip_component(spec).parse::<Ipv4Addr>().ok()
}

#[cfg(feature = "out_wireguard")]
fn parse_ipv6(spec: &str) -> Option<Ipv6Addr> {
    extract_ip_component(spec).parse::<Ipv6Addr>().ok()
}

#[cfg(feature = "out_wireguard")]
fn first_ipv4(entries: &[String]) -> Option<Ipv4Addr> {
    entries.iter().find_map(|entry| parse_ipv4(entry))
}

#[cfg(feature = "out_wireguard")]
fn first_ipv6(entries: &[String]) -> Option<Ipv6Addr> {
    entries.iter().find_map(|entry| parse_ipv6(entry))
}

#[cfg(not(feature = "out_wireguard"))]
#[derive(Default)]
pub struct WireGuardConfig;

#[cfg(not(feature = "out_wireguard"))]
impl WireGuardConfig {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(test, feature = "out_wireguard"))]
mod tests {
    use super::*;
    use sb_config::ir::{OutboundIR, OutboundType};

    fn base_ir() -> OutboundIR {
        OutboundIR {
            ty: OutboundType::Wireguard,
            name: Some("wg-test".to_string()),
            server: Some("wg.example".to_string()),
            port: Some(51820),
            ..Default::default()
        }
    }

    #[test]
    fn config_requires_interface_env() {
        std::env::remove_var("SB_WIREGUARD_INTERFACE");
        let ir = base_ir();
        let err = WireGuardConfig::from_ir(&ir).unwrap_err();
        assert!(err.contains("SB_WIREGUARD_INTERFACE"));
    }

    #[test]
    fn config_reads_optional_envs() {
        std::env::set_var("SB_WIREGUARD_INTERFACE", "wg0");
        std::env::set_var("SB_WIREGUARD_SOURCE_V4", "10.0.0.2");
        std::env::set_var("SB_WIREGUARD_CONNECT_TIMEOUT_MS", "2500");
        std::env::set_var("SB_WIREGUARD_TCP_KEEPALIVE_SECS", "15");

        let ir = base_ir();
        let cfg = WireGuardConfig::from_ir(&ir).expect("cfg");
        assert_eq!(cfg.interface.as_deref(), Some("wg0"));
        assert_eq!(cfg.source_ipv4, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(cfg.connect_timeout, Duration::from_millis(2500));
        assert_eq!(cfg.tcp_keepalive, Some(Duration::from_secs(15)));

        std::env::remove_var("SB_WIREGUARD_INTERFACE");
        std::env::remove_var("SB_WIREGUARD_SOURCE_V4");
        std::env::remove_var("SB_WIREGUARD_CONNECT_TIMEOUT_MS");
        std::env::remove_var("SB_WIREGUARD_TCP_KEEPALIVE_SECS");
    }

    #[test]
    fn config_prefers_ir_interface_and_addresses() {
        std::env::remove_var("SB_WIREGUARD_INTERFACE");
        std::env::remove_var("SB_WIREGUARD_SOURCE_V4");
        std::env::remove_var("SB_WIREGUARD_SOURCE_V6");
        std::env::remove_var("SB_WIREGUARD_ALLOWED_IPS");

        let mut ir = base_ir();
        ir.wireguard_interface = Some("wg-config".to_string());
        ir.wireguard_local_address = vec!["10.10.0.5/24".to_string(), "fd00::5/64".to_string()];
        ir.wireguard_allowed_ips = vec!["192.168.0.0/16".to_string()];
        ir.wireguard_persistent_keepalive = Some(42);

        let cfg = WireGuardConfig::from_ir(&ir).expect("cfg");
        assert_eq!(cfg.interface.as_deref(), Some("wg-config"));
        assert_eq!(cfg.source_ipv4, Some(Ipv4Addr::new(10, 10, 0, 5)));
        assert_eq!(cfg.source_ipv6, Some("fd00::5".parse().unwrap()));
        assert_eq!(cfg.allowed_ips, vec!["192.168.0.0/16".to_string()]);
        assert_eq!(cfg.persistent_keepalive, Some(42));
    }
}
