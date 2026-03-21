use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::debug;

use sb_core::outbound::{Endpoint, OutboundKind, OutboundRegistryHandle, RouteTarget};
use sb_core::router::rules::Decision;
use sb_core::router::{RouteCtx, RouterHandle, Transport};
use sb_platform::tun::{create_platform_device, TunConfig, TunError};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use tokio::io::Interest;
#[cfg(unix)]
use tokio::io::unix::AsyncFd;

use crate::inbound::tun::TunInboundConfig;
use crate::inbound::tun_session::{
    build_tcp_response_packet, FourTuple, TcpSession, TcpSessionManager, TunWriter,
};

const INITIAL_SERVER_SEQ: u32 = 1000;

/// Compile-clean smoltcp backend skeleton.
///
/// The previous prototype in this file targeted older outbound and smoltcp APIs.
/// This version keeps the configuration surface alive under the current runtime
/// contracts so the backend can be wired incrementally without reviving dead code.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EnhancedTunConfig {
    pub name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout_ms: u64,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_ms: u64,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
}

fn default_mtu() -> u32 {
    1500
}

fn default_tcp_timeout() -> u64 {
    30_000
}

fn default_udp_timeout() -> u64 {
    60_000
}

fn default_buffer_size() -> usize {
    65_536
}

fn default_max_tcp_connections() -> usize {
    1024
}

impl Default for EnhancedTunConfig {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            mtu: default_mtu(),
            ipv4: None,
            ipv6: None,
            auto_route: false,
            tcp_timeout_ms: default_tcp_timeout(),
            udp_timeout_ms: default_udp_timeout(),
            buffer_size: default_buffer_size(),
            max_tcp_connections: default_max_tcp_connections(),
        }
    }
}

impl EnhancedTunConfig {
    pub fn from_legacy_config(cfg: &TunInboundConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            mtu: cfg.mtu,
            ipv4: cfg
                .inet4_address
                .as_ref()
                .and_then(|value| value.split('/').next())
                .and_then(|value| value.parse().ok()),
            ipv6: cfg
                .inet6_address
                .as_ref()
                .and_then(|value| value.split('/').next())
                .and_then(|value| value.parse().ok()),
            auto_route: cfg.auto_route,
            tcp_timeout_ms: cfg.timeout_ms,
            udp_timeout_ms: cfg
                .udp_timeout
                .as_deref()
                .and_then(parse_duration_ms)
                .unwrap_or_else(default_udp_timeout),
            buffer_size: default_buffer_size(),
            max_tcp_connections: default_max_tcp_connections(),
        }
    }
}

fn parse_duration_ms(value: &str) -> Option<u64> {
    humantime::parse_duration(value)
        .ok()
        .and_then(|duration| duration.as_millis().try_into().ok())
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedTcpPacket<'a> {
    pub tuple: FourTuple,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

#[allow(dead_code)]
impl ParsedTcpPacket<'_> {
    pub(crate) fn is_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    pub(crate) fn is_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    pub(crate) fn is_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    pub(crate) fn is_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }

    pub(crate) fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }

    pub(crate) fn sequence_advance(&self) -> u32 {
        (self.payload.len() as u32) + u32::from(self.is_syn()) + u32::from(self.is_fin())
    }

    pub(crate) fn next_client_seq(&self) -> u32 {
        self.sequence_number.wrapping_add(self.sequence_advance())
    }
}

#[allow(dead_code)]
pub(crate) fn parse_raw_tcp(packet: &[u8]) -> Option<ParsedTcpPacket<'_>> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0f;
    match version {
        4 => parse_ipv4_tcp(packet),
        6 => parse_ipv6_tcp(packet),
        _ => None,
    }
}

#[allow(dead_code)]
fn parse_ipv4_tcp(packet: &[u8]) -> Option<ParsedTcpPacket<'_>> {
    if packet.len() < 20 {
        return None;
    }
    if packet[9] != 6 {
        return None;
    }

    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 20 {
        return None;
    }

    let tcp_offset = ihl;
    let tcp_header_len = ((packet[tcp_offset + 12] >> 4) as usize) * 4;
    if tcp_header_len < 20 || packet.len() < tcp_offset + tcp_header_len {
        return None;
    }

    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
    let sequence_number = u32::from_be_bytes([
        packet[tcp_offset + 4],
        packet[tcp_offset + 5],
        packet[tcp_offset + 6],
        packet[tcp_offset + 7],
    ]);
    let acknowledgment_number = u32::from_be_bytes([
        packet[tcp_offset + 8],
        packet[tcp_offset + 9],
        packet[tcp_offset + 10],
        packet[tcp_offset + 11],
    ]);
    let flags = packet[tcp_offset + 13];
    let payload_offset = tcp_offset + tcp_header_len;

    Some(ParsedTcpPacket {
        tuple: FourTuple::new(src_ip, src_port, dst_ip, dst_port),
        sequence_number,
        acknowledgment_number,
        flags,
        payload: &packet[payload_offset..],
    })
}

#[allow(dead_code)]
fn parse_ipv6_tcp(packet: &[u8]) -> Option<ParsedTcpPacket<'_>> {
    if packet.len() < 60 {
        return None;
    }
    if packet[6] != 6 {
        return None;
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);

    let tcp_offset = 40;
    let tcp_header_len = ((packet[tcp_offset + 12] >> 4) as usize) * 4;
    if tcp_header_len < 20 || packet.len() < tcp_offset + tcp_header_len {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[tcp_offset], packet[tcp_offset + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp_offset + 2], packet[tcp_offset + 3]]);
    let sequence_number = u32::from_be_bytes([
        packet[tcp_offset + 4],
        packet[tcp_offset + 5],
        packet[tcp_offset + 6],
        packet[tcp_offset + 7],
    ]);
    let acknowledgment_number = u32::from_be_bytes([
        packet[tcp_offset + 8],
        packet[tcp_offset + 9],
        packet[tcp_offset + 10],
        packet[tcp_offset + 11],
    ]);
    let flags = packet[tcp_offset + 13];
    let payload_offset = tcp_offset + tcp_header_len;

    Some(ParsedTcpPacket {
        tuple: FourTuple::new(
            IpAddr::V6(Ipv6Addr::from(src)),
            src_port,
            IpAddr::V6(Ipv6Addr::from(dst)),
            dst_port,
        ),
        sequence_number,
        acknowledgment_number,
        flags,
        payload: &packet[payload_offset..],
    })
}

#[derive(Debug, Clone)]
pub struct EnhancedTunInbound {
    config: EnhancedTunConfig,
    outbounds: Arc<OutboundRegistryHandle>,
    router: Option<Arc<RouterHandle>>,
    session_manager: Arc<TcpSessionManager>,
}

#[cfg(unix)]
struct AsyncTunFd {
    inner: Box<dyn sb_platform::tun::TunDevice>,
}

#[cfg(unix)]
impl AsRawFd for AsyncTunFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}

#[async_trait::async_trait]
trait PacketIo {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}

#[cfg(unix)]
struct UnixPacketIo {
    device: AsyncFd<AsyncTunFd>,
}

#[cfg(unix)]
#[async_trait::async_trait]
impl PacketIo for UnixPacketIo {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.device
            .async_io_mut(Interest::READABLE, |inner| inner.inner.read(buf).map_err(tun_error_to_io))
            .await
    }

    async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < packet.len() {
            let n = self
                .device
                .async_io_mut(Interest::WRITABLE, |inner| {
                    inner.inner.write(&packet[written..]).map_err(tun_error_to_io)
                })
                .await?;
            written += n;
        }
        Ok(())
    }
}

impl EnhancedTunInbound {
    pub fn new(config: EnhancedTunConfig, outbounds: Arc<OutboundRegistryHandle>) -> Self {
        Self {
            config,
            outbounds,
            router: None,
            session_manager: Arc::new(TcpSessionManager::new()),
        }
    }

    pub fn with_router(
        config: EnhancedTunConfig,
        outbounds: Arc<OutboundRegistryHandle>,
        router: Arc<RouterHandle>,
    ) -> Self {
        Self {
            config,
            outbounds,
            router: Some(router),
            session_manager: Arc::new(TcpSessionManager::new()),
        }
    }

    pub fn from_tun_config(
        cfg: &TunInboundConfig,
        outbounds: Arc<OutboundRegistryHandle>,
        router: Option<Arc<RouterHandle>>,
    ) -> Self {
        let config = EnhancedTunConfig::from_legacy_config(cfg);
        Self {
            config,
            outbounds,
            router,
            session_manager: Arc::new(TcpSessionManager::new()),
        }
    }

    pub async fn start(&self) -> io::Result<()> {
        let device = create_platform_device(&self.to_platform_config()).map_err(tun_error_to_io)?;
        let (tx, rx) = mpsc::channel(128);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });

        #[cfg(unix)]
        {
            return self.run_packet_loop_unix(device, rx, writer).await;
        }

        #[cfg(not(unix))]
        {
            let _ = device;
            let _ = rx;
            let _ = writer;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tun: smoltcp backend runtime loop currently requires unix-style TUN fd support",
            ))
        }
    }

    pub fn config(&self) -> &EnhancedTunConfig {
        &self.config
    }

    fn to_platform_config(&self) -> TunConfig {
        TunConfig {
            name: self.config.name.clone(),
            mtu: self.config.mtu,
            ipv4: self.config.ipv4,
            ipv6: self.config.ipv6,
            auto_route: self.config.auto_route,
            table: None,
        }
    }

    async fn process_packet(
        &self,
        packet: &[u8],
        writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> io::Result<()> {
        if let Some(tcp) = parse_raw_tcp(packet) {
            if let Err(err) = self.bootstrap_tcp_session(&tcp, writer).await {
                debug!(error = %err, tuple = ?tcp.tuple, "tun enhanced: tcp packet handling failed");
            }
        }

        Ok(())
    }

    #[cfg(unix)]
    async fn run_packet_loop_unix(
        &self,
        device: Box<dyn sb_platform::tun::TunDevice>,
        mut writer_rx: mpsc::Receiver<Vec<u8>>,
        writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> io::Result<()> {
        set_nonblocking(device.as_raw_fd())?;

        let mut io = UnixPacketIo {
            device: AsyncFd::new(AsyncTunFd { inner: device })?,
        };
        self.run_packet_loop(&mut io, &mut writer_rx, writer).await
    }

    async fn run_packet_loop<I: PacketIo + Send>(
        &self,
        io: &mut I,
        writer_rx: &mut mpsc::Receiver<Vec<u8>>,
        writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; self.config.buffer_size.max(self.config.mtu as usize)];

        loop {
            tokio::select! {
                biased;
                maybe_packet = writer_rx.recv() => {
                    let Some(packet) = maybe_packet else {
                        return Ok(());
                    };
                    io.write_packet(&packet).await?;
                }
                read_result = io.read_packet(&mut buf) => {
                    let n = read_result?;
                    if n == 0 {
                        return Ok(());
                    }
                    self.process_packet(&buf[..n], Arc::clone(&writer)).await?;
                }
            }
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn bootstrap_tcp_session(
        &self,
        packet: &ParsedTcpPacket<'_>,
        writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> io::Result<()> {
        if let Some(session) = self.session_manager.get(&packet.tuple) {
            if packet.sequence_advance() > 0 {
                session.observe_client_segment(packet.next_client_seq());
            }
            if packet.is_ack() {
                session.observe_server_ack(packet.acknowledgment_number);
            }
            if packet.is_rst() {
                session.initiate_close();
                self.session_manager.remove(&packet.tuple);
                return Ok(());
            }
            if packet.has_payload() {
                session
                    .send_to_outbound(Bytes::copy_from_slice(packet.payload))
                    .await
                    .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
            }
            if packet.is_fin() {
                self.send_tcp_control_packet(&session, Arc::clone(&writer), 0x11, 1)
                    .await?;
                session.initiate_close();
                self.session_manager.remove(&packet.tuple);
                return Ok(());
            }
            if packet.has_payload() {
                self.send_tcp_control_packet(&session, writer, 0x10, 0).await?;
            }
            return Ok(());
        }

        if packet.is_rst() {
            return Ok(());
        }

        if packet.is_fin() && !packet.has_payload() {
            self.send_tcp_reset_packet(packet, writer).await?;
            return Ok(());
        }

        if !packet.is_syn() && !packet.has_payload() && !packet.is_fin() {
            debug!(tuple = ?packet.tuple, "tun enhanced: ignoring tcp control packet without active session");
            return Ok(());
        }

        let decision = self.route_tcp_tuple(packet);
        let (target, _tag) = match route_target_from_decision(&decision) {
            Ok(target) => target,
            Err(err) => {
                self.send_tcp_reset_packet(packet, writer).await?;
                debug!(error = %err, tuple = ?packet.tuple, "tun enhanced: routing rejected tcp packet");
                return Ok(());
            }
        };
        let endpoint = match packet.tuple.dst_ip {
            IpAddr::V4(ip) => Endpoint::Ip(std::net::SocketAddr::new(IpAddr::V4(ip), packet.tuple.dst_port)),
            IpAddr::V6(ip) => Endpoint::Ip(std::net::SocketAddr::new(IpAddr::V6(ip), packet.tuple.dst_port)),
        };

        let stream = match self.outbounds.connect_tcp(&target, endpoint).await {
            Ok(stream) => stream,
            Err(err) => {
                self.send_tcp_reset_packet(packet, writer).await?;
                debug!(error = %err, tuple = ?packet.tuple, "tun enhanced: outbound connect failed");
                return Ok(());
            }
        };
        let session = self
            .session_manager
            .create_session_with_state(
                packet.tuple,
                stream,
                Arc::clone(&writer),
                None,
                packet.next_client_seq(),
                INITIAL_SERVER_SEQ,
            );

        if packet.is_syn() {
            self.send_tcp_control_packet(&session, Arc::clone(&writer), 0x12, 1)
                .await?;
        }

        if packet.has_payload() {
            session
                .send_to_outbound(Bytes::copy_from_slice(packet.payload))
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
            if !packet.is_syn() {
                self.send_tcp_control_packet(&session, writer, 0x10, 0).await?;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn session_count(&self) -> usize {
        self.session_manager.count()
    }

    fn route_tcp_tuple(&self, packet: &ParsedTcpPacket<'_>) -> Decision {
        let host = packet.tuple.dst_ip.to_string();
        let ctx = RouteCtx {
            host: Some(&host),
            ip: Some(packet.tuple.dst_ip),
            port: Some(packet.tuple.dst_port),
            transport: Transport::Tcp,
            ..Default::default()
        };

        self.router
            .as_ref()
            .map(|router| router.decide(&ctx))
            .unwrap_or(Decision::Direct)
    }

    async fn send_tcp_control_packet(
        &self,
        session: &Arc<TcpSession>,
        writer: Arc<dyn TunWriter + Send + Sync>,
        flags: u8,
        server_seq_advance: u32,
    ) -> io::Result<()> {
        let seq = session.reserve_server_seq(server_seq_advance);
        let ack = session.client_next_seq();
        let packet = build_tcp_response_packet(session.tuple.reverse(), &[], seq, ack, flags)?;
        writer.write_packet(&packet).await
    }

    async fn send_tcp_reset_packet(
        &self,
        packet: &ParsedTcpPacket<'_>,
        writer: Arc<dyn TunWriter + Send + Sync>,
    ) -> io::Result<()> {
        let reply = build_tcp_response_packet(
            packet.tuple.reverse(),
            &[],
            0,
            packet.next_client_seq(),
            0x14,
        )?;
        writer.write_packet(&reply).await
    }
}

struct ChannelTunWriter {
    tx: mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl TunWriter for ChannelTunWriter {
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.tx
            .send(packet.to_vec())
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))
    }
}

fn tun_error_to_io(err: TunError) -> io::Error {
    match err {
        TunError::IoError(inner) => inner,
        TunError::PermissionDenied => io::Error::new(io::ErrorKind::PermissionDenied, err.to_string()),
        TunError::InvalidConfig(_) => io::Error::new(io::ErrorKind::InvalidInput, err.to_string()),
        TunError::UnsupportedPlatform => io::Error::new(io::ErrorKind::Unsupported, err.to_string()),
        other => io::Error::other(other.to_string()),
    }
}

#[cfg(unix)]
fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn route_target_from_decision(decision: &Decision) -> io::Result<(RouteTarget, String)> {
    match decision {
        Decision::Direct => Ok((RouteTarget::Kind(OutboundKind::Direct), "direct".to_string())),
        Decision::Proxy(Some(tag)) => Ok((RouteTarget::Named(tag.clone()), tag.clone())),
        Decision::Proxy(None) => Ok((RouteTarget::Kind(OutboundKind::Direct), "direct".to_string())),
        Decision::Reject | Decision::RejectDrop => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "blocked by routing rule",
        )),
        Decision::Sniff { .. } => Ok((RouteTarget::Kind(OutboundKind::Direct), "direct".to_string())),
        Decision::Hijack { .. } | Decision::Resolve | Decision::HijackDns => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("tun: unsupported routing decision {:?}", decision),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_udp_timeout, parse_raw_tcp, ChannelTunWriter, EnhancedTunConfig,
        EnhancedTunInbound, PacketIo,
        INITIAL_SERVER_SEQ,
    };
    use crate::inbound::tun::TunInboundConfig;
    use crate::inbound::tun_session::{FourTuple, TunWriter};
    use sb_core::outbound::{OutboundImpl, OutboundKind, OutboundRegistry, OutboundRegistryHandle};
    use sb_core::router::{Router, RouterHandle};
    use std::collections::VecDeque;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};

    #[test]
    fn enhanced_config_maps_legacy_tun_options() {
        let cfg = TunInboundConfig {
            name: "utun9".to_string(),
            mtu: 1400,
            timeout_ms: 8_000,
            auto_route: true,
            inet4_address: Some("172.19.0.1/30".to_string()),
            inet6_address: Some("fd00::1/64".to_string()),
            udp_timeout: Some("45s".to_string()),
            ..TunInboundConfig::default()
        };

        let enhanced = EnhancedTunConfig::from_legacy_config(&cfg);
        assert_eq!(enhanced.name, "utun9");
        assert_eq!(enhanced.mtu, 1400);
        assert_eq!(enhanced.tcp_timeout_ms, 8_000);
        assert_eq!(enhanced.udp_timeout_ms, 45_000);
        assert!(enhanced.auto_route);
        assert_eq!(
            enhanced.ipv4.map(|ip| ip.to_string()).as_deref(),
            Some("172.19.0.1")
        );
        assert_eq!(
            enhanced.ipv6.map(|ip| ip.to_string()).as_deref(),
            Some("fd00::1")
        );
    }

    #[test]
    fn enhanced_config_uses_default_udp_timeout_on_invalid_value() {
        let cfg = TunInboundConfig {
            udp_timeout: Some("not-a-duration".to_string()),
            ..TunInboundConfig::default()
        };

        let enhanced = EnhancedTunConfig::from_legacy_config(&cfg);
        assert_eq!(enhanced.udp_timeout_ms, default_udp_timeout());
    }

    #[test]
    fn parse_raw_tcp_ipv4_payload() {
        let payload = b"ping";
        let total_len = 20 + 20 + payload.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(payload);

        let parsed = parse_raw_tcp(&packet).expect("should parse ipv4 tcp");
        assert_eq!(parsed.tuple.src_ip.to_string(), "10.0.0.2");
        assert_eq!(parsed.tuple.src_port, 12345);
        assert_eq!(parsed.tuple.dst_ip.to_string(), "93.184.216.34");
        assert_eq!(parsed.tuple.dst_port, 80);
        assert_eq!(parsed.sequence_number, 0);
        assert_eq!(parsed.acknowledgment_number, 0);
        assert_eq!(parsed.flags, 0x18);
        assert!(parsed.has_payload());
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_raw_tcp_ipv4_syn_without_payload() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(40u16).to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 168, 1, 10]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..28].copy_from_slice(&123u32.to_be_bytes());
        packet[28..32].copy_from_slice(&456u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x02;

        let parsed = parse_raw_tcp(&packet).expect("should parse syn packet");
        assert!(parsed.is_syn());
        assert_eq!(parsed.sequence_number, 123);
        assert_eq!(parsed.acknowledgment_number, 456);
        assert_eq!(parsed.next_client_seq(), 124);
        assert!(!parsed.has_payload());
    }

    #[test]
    fn parse_raw_tcp_rejects_udp_packet() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[127, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
        assert!(parse_raw_tcp(&packet).is_none());
    }

    struct NoopTunWriter;

    #[async_trait::async_trait]
    impl TunWriter for NoopTunWriter {
        async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingTunWriter {
        packets: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl TunWriter for RecordingTunWriter {
        async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
            self.packets.lock().expect("lock packets").push(packet.to_vec());
            Ok(())
        }
    }

    enum FakeRead {
        Packet(Vec<u8>),
        DelayedEof(std::time::Duration),
    }

    struct FakePacketIo {
        reads: VecDeque<FakeRead>,
        writes: Vec<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl PacketIo for FakePacketIo {
        async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.reads.pop_front() {
                Some(FakeRead::Packet(packet)) => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                Some(FakeRead::DelayedEof(delay)) => {
                    tokio::time::sleep(delay).await;
                    Ok(0)
                }
                None => Ok(0),
            }
        }

        async fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.writes.push(packet.to_vec());
            Ok(())
        }
    }

    fn make_direct_inbound() -> EnhancedTunInbound {
        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        EnhancedTunInbound::with_router(EnhancedTunConfig::default(), outbounds, router)
    }

    fn build_ipv4_tcp_packet_for_test(
        dst: SocketAddr,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let dst_ip = match dst.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("test helper expects IPv4 socket"),
        };
        let total_len = 20 + 20 + payload.len();
        let mut raw = vec![0u8; total_len];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        raw[9] = 6;
        raw[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        raw[16..20].copy_from_slice(&dst_ip);
        raw[20..22].copy_from_slice(&34567u16.to_be_bytes());
        raw[22..24].copy_from_slice(&dst.port().to_be_bytes());
        raw[24..28].copy_from_slice(&seq.to_be_bytes());
        raw[28..32].copy_from_slice(&ack.to_be_bytes());
        raw[32] = 0x50;
        raw[33] = flags;
        if !payload.is_empty() {
            raw[40..].copy_from_slice(payload);
        }
        raw
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_connects_and_forwards_initial_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            let _ = payload_tx.send(buf[..n].to_vec());
        });

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );

        let payload = b"ping";
        let total_len = 20 + 20 + payload.len();
        let mut raw = vec![0u8; total_len];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        raw[9] = 6;
        raw[12..16].copy_from_slice(&[10, 0, 0, 2]);
        raw[16..20].copy_from_slice(&addr.ip().to_string().parse::<std::net::Ipv4Addr>().expect("ipv4").octets());
        raw[20..22].copy_from_slice(&34567u16.to_be_bytes());
        raw[22..24].copy_from_slice(&addr.port().to_be_bytes());
        raw[32] = 0x50;
        raw[33] = 0x18;
        raw[40..].copy_from_slice(payload);

        let packet = parse_raw_tcp(&raw).expect("parse tcp packet");
        inbound
            .bootstrap_tcp_session(&packet, Arc::new(NoopTunWriter))
            .await
            .expect("bootstrap session");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn packet_loop_flushes_syn_ack_before_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let _ = listener.accept().await.expect("accept");
        });

        let inbound = make_direct_inbound();
        let raw = build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[]);

        let (tx, mut rx) = mpsc::channel(8);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });
        let mut io = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(raw),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io, &mut rx, writer)
            .await
            .expect("packet loop");

        assert!(!io.writes.is_empty());
        let reply = parse_raw_tcp(&io.writes[0]).expect("parse syn-ack");
        assert_eq!(reply.flags, 0x12);
        assert_eq!(reply.sequence_number, INITIAL_SERVER_SEQ);
        assert_eq!(reply.acknowledgment_number, 43);
    }

    #[tokio::test]
    async fn packet_loop_continues_after_connect_failure() {
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind dead listener");
        let dead_addr = dead_listener.local_addr().expect("dead addr");
        drop(dead_listener);

        let live_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind live listener");
        let live_addr = live_listener.local_addr().expect("live addr");
        tokio::spawn(async move {
            let _ = live_listener.accept().await.expect("accept");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let inbound = make_direct_inbound();
        let (tx, mut rx) = mpsc::channel(8);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });
        let mut io = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(dead_addr, 0x02, 10, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(live_addr, 0x02, 42, 0, &[])),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io, &mut rx, writer)
            .await
            .expect("packet loop");

        assert!(io.writes.len() >= 2);
        let first = parse_raw_tcp(&io.writes[0]).expect("parse rst");
        let second = parse_raw_tcp(&io.writes[1]).expect("parse syn-ack");
        assert_eq!(first.flags, 0x14);
        assert_eq!(first.acknowledgment_number, 11);
        assert_eq!(second.flags, 0x12);
        assert_eq!(second.acknowledgment_number, 43);
    }

    #[tokio::test]
    async fn packet_loop_forwards_fin_payload_and_cleans_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            let _ = payload_tx.send(buf[..n].to_vec());
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let inbound = make_direct_inbound();
        let (tx, mut rx) = mpsc::channel(8);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });
        let payload = b"bye";
        let mut io = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x11,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io, &mut rx, writer)
            .await
            .expect("packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);
        assert!(io.writes.len() >= 2);
        let first = parse_raw_tcp(&io.writes[0]).expect("parse syn-ack");
        let second = parse_raw_tcp(&io.writes[1]).expect("parse fin-ack");
        assert_eq!(first.flags, 0x12);
        assert_eq!(second.flags, 0x11);
        assert_eq!(second.acknowledgment_number, 47);
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn packet_loop_relays_outbound_payload_back_to_tun() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            payload_tx.send(buf[..n].to_vec()).expect("send payload");
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .expect("write reply");
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        });

        let inbound = make_direct_inbound();
        let (tx, mut rx) = mpsc::channel(8);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });
        let payload = b"ping";
        let mut io = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x18,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(80)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io, &mut rx, writer)
            .await
            .expect("packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let packets: Vec<_> = io
            .writes
            .iter()
            .map(|packet| parse_raw_tcp(packet).expect("parse reply packet"))
            .collect();

        assert!(packets.iter().any(|packet| packet.flags == 0x12));
        assert!(packets.iter().any(|packet| packet.flags == 0x10 && packet.payload.is_empty()));

        let reply = packets
            .iter()
            .find(|packet| packet.flags == 0x18 && packet.payload == b"pong")
            .expect("outbound payload should be relayed back to tun");
        assert_eq!(reply.sequence_number, INITIAL_SERVER_SEQ + 1);
        assert_eq!(reply.acknowledgment_number, 47);
    }

    #[tokio::test]
    async fn packet_loop_emits_fin_ack_on_outbound_eof_and_cleans_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            payload_tx.send(buf[..n].to_vec()).expect("send payload");
            drop(stream);
        });

        let inbound = make_direct_inbound();
        let (tx, mut rx) = mpsc::channel(8);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });
        let payload = b"ping";
        let mut io = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x18,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(80)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io, &mut rx, writer)
            .await
            .expect("packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let packets: Vec<_> = io
            .writes
            .iter()
            .map(|packet| parse_raw_tcp(packet).expect("parse reply packet"))
            .collect();
        assert!(packets.iter().any(|packet| packet.flags == 0x12));
        assert!(packets.iter().any(|packet| packet.flags == 0x10 && packet.payload.is_empty()));
        let fin = packets
            .iter()
            .find(|packet| packet.flags == 0x11)
            .expect("outbound eof should emit fin-ack");
        assert_eq!(fin.sequence_number, INITIAL_SERVER_SEQ + 1);
        assert_eq!(fin.acknowledgment_number, 47);
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn packet_loop_ack_only_updates_session_state_without_extra_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            payload_tx.send(buf[..n].to_vec()).expect("send payload");
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .expect("write reply");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let inbound = make_direct_inbound();
        let payload = b"ping";
        let (tx1, mut rx1) = mpsc::channel(8);
        let writer1: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx1 });
        let mut io1 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x18,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(80)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io1, &mut rx1, writer1)
            .await
            .expect("first packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let packets: Vec<_> = io1
            .writes
            .iter()
            .map(|packet| parse_raw_tcp(packet).expect("parse reply packet"))
            .collect();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].flags, 0x12);
        assert_eq!(packets[1].flags, 0x10);
        assert_eq!(packets[2].flags, 0x18);
        assert_eq!(packets[2].payload, b"pong");

        let tuple = FourTuple::new(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            34567,
            addr.ip(),
            addr.port(),
        );
        let session = inbound
            .session_manager
            .get(&tuple)
            .expect("session should remain active after ack-only");
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 1);

        let (tx2, mut rx2) = mpsc::channel(8);
        let writer2: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx2 });
        let mut io2 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x10,
                    47,
                    INITIAL_SERVER_SEQ + 5,
                    &[],
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io2, &mut rx2, writer2)
            .await
            .expect("second packet loop");

        assert!(io2.writes.is_empty());
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 5);
    }

    #[tokio::test]
    async fn packet_loop_stale_or_duplicate_ack_does_not_regress_state_or_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            payload_tx.send(buf[..n].to_vec()).expect("send payload");
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .expect("write reply");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let inbound = make_direct_inbound();
        let payload = b"ping";

        let (tx1, mut rx1) = mpsc::channel(8);
        let writer1: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx1 });
        let mut io1 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x18,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(80)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io1, &mut rx1, writer1)
            .await
            .expect("first packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let tuple = FourTuple::new(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            34567,
            addr.ip(),
            addr.port(),
        );
        let session = inbound
            .session_manager
            .get(&tuple)
            .expect("session should remain active");
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 1);

        let (tx2, mut rx2) = mpsc::channel(8);
        let writer2: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx2 });
        let mut io2 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x10,
                    47,
                    INITIAL_SERVER_SEQ + 5,
                    &[],
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io2, &mut rx2, writer2)
            .await
            .expect("second packet loop");

        assert!(io2.writes.is_empty());
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 5);

        let (tx3, mut rx3) = mpsc::channel(8);
        let writer3: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx3 });
        let mut io3 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x10,
                    47,
                    INITIAL_SERVER_SEQ + 3,
                    &[],
                )),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x10,
                    47,
                    INITIAL_SERVER_SEQ + 5,
                    &[],
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io3, &mut rx3, writer3)
            .await
            .expect("third packet loop");

        assert!(io3.writes.is_empty());
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 5);
    }

    #[tokio::test]
    async fn packet_loop_future_ack_is_capped_to_emitted_server_seq() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            payload_tx.send(buf[..n].to_vec()).expect("send payload");
            tokio::io::AsyncWriteExt::write_all(&mut stream, b"pong")
                .await
                .expect("write reply");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let inbound = make_direct_inbound();
        let payload = b"ping";

        let (tx1, mut rx1) = mpsc::channel(8);
        let writer1: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx1 });
        let mut io1 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x18,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(80)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io1, &mut rx1, writer1)
            .await
            .expect("first packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let tuple = FourTuple::new(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            34567,
            addr.ip(),
            addr.port(),
        );
        let session = inbound
            .session_manager
            .get(&tuple)
            .expect("session should remain active");
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 1);
        assert_eq!(session.server_next_seq(), INITIAL_SERVER_SEQ + 5);

        let (tx2, mut rx2) = mpsc::channel(8);
        let writer2: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx2 });
        let mut io2 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x10,
                    47,
                    INITIAL_SERVER_SEQ + 500,
                    &[],
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io2, &mut rx2, writer2)
            .await
            .expect("second packet loop");

        assert!(io2.writes.is_empty());
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 5);
    }

    #[tokio::test]
    async fn packet_loop_rst_closes_existing_session_without_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            payload_tx.send(buf[..n].to_vec()).expect("send payload");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = stream.read(&mut buf).await;
        });

        let inbound = make_direct_inbound();
        let payload = b"ping";

        let (tx1, mut rx1) = mpsc::channel(8);
        let writer1: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx1 });
        let mut io1 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[])),
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x18,
                    43,
                    INITIAL_SERVER_SEQ + 1,
                    payload,
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(80)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io1, &mut rx1, writer1)
            .await
            .expect("first packet loop");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let tuple = FourTuple::new(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            34567,
            addr.ip(),
            addr.port(),
        );
        assert!(inbound.session_manager.get(&tuple).is_some());

        let (tx2, mut rx2) = mpsc::channel(8);
        let writer2: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx: tx2 });
        let mut io2 = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x14,
                    47,
                    INITIAL_SERVER_SEQ + 1,
                    &[],
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io2, &mut rx2, writer2)
            .await
            .expect("second packet loop");

        assert!(io2.writes.is_empty());
        assert!(inbound.session_manager.get(&tuple).is_none());
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn packet_loop_stray_rst_without_session_is_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let inbound = make_direct_inbound();
        let (tx, mut rx) = mpsc::channel(8);
        let writer: Arc<dyn TunWriter + Send + Sync> = Arc::new(ChannelTunWriter { tx });
        let mut io = FakePacketIo {
            reads: VecDeque::from([
                FakeRead::Packet(build_ipv4_tcp_packet_for_test(
                    addr,
                    0x14,
                    77,
                    INITIAL_SERVER_SEQ + 1,
                    &[],
                )),
                FakeRead::DelayedEof(std::time::Duration::from_millis(10)),
            ]),
            writes: Vec::new(),
        };

        inbound
            .run_packet_loop(&mut io, &mut rx, writer)
            .await
            .expect("packet loop");

        assert!(io.writes.is_empty());
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_syn_sends_syn_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let _ = listener.accept().await.expect("accept");
        });

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut raw = vec![0u8; 40];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&(40u16).to_be_bytes());
        raw[9] = 6;
        raw[12..16].copy_from_slice(&[10, 0, 0, 2]);
        raw[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        raw[20..22].copy_from_slice(&34567u16.to_be_bytes());
        raw[22..24].copy_from_slice(&addr.port().to_be_bytes());
        raw[24..28].copy_from_slice(&42u32.to_be_bytes());
        raw[32] = 0x50;
        raw[33] = 0x02;

        let packet = parse_raw_tcp(&raw).expect("parse tcp packet");
        inbound
            .bootstrap_tcp_session(&packet, writer.clone())
            .await
            .expect("bootstrap session");

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 1);
        let reply = parse_raw_tcp(&packets[0]).expect("parse syn-ack");
        assert_eq!(reply.tuple.src_ip, packet.tuple.dst_ip);
        assert_eq!(reply.tuple.dst_ip, packet.tuple.src_ip);
        assert_eq!(reply.flags, 0x12);
        assert_eq!(reply.sequence_number, INITIAL_SERVER_SEQ);
        assert_eq!(reply.acknowledgment_number, 43);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_connect_failure_sends_rst_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut raw = vec![0u8; 40];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&(40u16).to_be_bytes());
        raw[9] = 6;
        raw[12..16].copy_from_slice(&[10, 0, 0, 2]);
        raw[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        raw[20..22].copy_from_slice(&34567u16.to_be_bytes());
        raw[22..24].copy_from_slice(&addr.port().to_be_bytes());
        raw[24..28].copy_from_slice(&77u32.to_be_bytes());
        raw[32] = 0x50;
        raw[33] = 0x02;

        let packet = parse_raw_tcp(&raw).expect("parse tcp packet");
        inbound
            .bootstrap_tcp_session(&packet, writer.clone())
            .await
            .expect("bootstrap should degrade to rst");

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 1);
        let reply = parse_raw_tcp(&packets[0]).expect("parse rst");
        assert_eq!(reply.flags, 0x14);
        assert_eq!(reply.sequence_number, 0);
        assert_eq!(reply.acknowledgment_number, 78);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_fin_sends_fin_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut syn = vec![0u8; 40];
        syn[0] = 0x45;
        syn[2..4].copy_from_slice(&(40u16).to_be_bytes());
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[10, 0, 0, 2]);
        syn[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        syn[20..22].copy_from_slice(&34567u16.to_be_bytes());
        syn[22..24].copy_from_slice(&addr.port().to_be_bytes());
        syn[24..28].copy_from_slice(&42u32.to_be_bytes());
        syn[32] = 0x50;
        syn[33] = 0x02;

        let syn_packet = parse_raw_tcp(&syn).expect("parse syn");
        inbound
            .bootstrap_tcp_session(&syn_packet, writer.clone())
            .await
            .expect("bootstrap syn");

        let mut fin = vec![0u8; 40];
        fin[0] = 0x45;
        fin[2..4].copy_from_slice(&(40u16).to_be_bytes());
        fin[9] = 6;
        fin[12..16].copy_from_slice(&[10, 0, 0, 2]);
        fin[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        fin[20..22].copy_from_slice(&34567u16.to_be_bytes());
        fin[22..24].copy_from_slice(&addr.port().to_be_bytes());
        fin[24..28].copy_from_slice(&43u32.to_be_bytes());
        fin[28..32].copy_from_slice(&(INITIAL_SERVER_SEQ + 1).to_be_bytes());
        fin[32] = 0x50;
        fin[33] = 0x11;

        let fin_packet = parse_raw_tcp(&fin).expect("parse fin");
        inbound
            .bootstrap_tcp_session(&fin_packet, writer.clone())
            .await
            .expect("bootstrap fin");

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 2);
        let reply = parse_raw_tcp(&packets[1]).expect("parse fin-ack");
        assert_eq!(reply.flags, 0x11);
        assert_eq!(reply.sequence_number, INITIAL_SERVER_SEQ + 1);
        assert_eq!(reply.acknowledgment_number, 44);
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_fin_without_session_sends_rst_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut fin = vec![0u8; 40];
        fin[0] = 0x45;
        fin[2..4].copy_from_slice(&(40u16).to_be_bytes());
        fin[9] = 6;
        fin[12..16].copy_from_slice(&[10, 0, 0, 2]);
        fin[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        fin[20..22].copy_from_slice(&34567u16.to_be_bytes());
        fin[22..24].copy_from_slice(&addr.port().to_be_bytes());
        fin[24..28].copy_from_slice(&77u32.to_be_bytes());
        fin[32] = 0x50;
        fin[33] = 0x11;

        let packet = parse_raw_tcp(&fin).expect("parse fin");
        inbound
            .bootstrap_tcp_session(&packet, writer.clone())
            .await
            .expect("stray fin should rst");

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 1);
        let reply = parse_raw_tcp(&packets[0]).expect("parse rst");
        assert_eq!(reply.flags, 0x14);
        assert_eq!(reply.sequence_number, 0);
        assert_eq!(reply.acknowledgment_number, 78);
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_fin_with_payload_forwards_then_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (payload_tx, payload_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.expect("read payload");
            let _ = payload_tx.send(buf[..n].to_vec());
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut syn = vec![0u8; 40];
        syn[0] = 0x45;
        syn[2..4].copy_from_slice(&(40u16).to_be_bytes());
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[10, 0, 0, 2]);
        syn[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        syn[20..22].copy_from_slice(&34567u16.to_be_bytes());
        syn[22..24].copy_from_slice(&addr.port().to_be_bytes());
        syn[24..28].copy_from_slice(&42u32.to_be_bytes());
        syn[32] = 0x50;
        syn[33] = 0x02;

        let syn_packet = parse_raw_tcp(&syn).expect("parse syn");
        inbound
            .bootstrap_tcp_session(&syn_packet, writer.clone())
            .await
            .expect("bootstrap syn");

        let payload = b"bye";
        let total_len = 20 + 20 + payload.len();
        let mut fin = vec![0u8; total_len];
        fin[0] = 0x45;
        fin[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        fin[9] = 6;
        fin[12..16].copy_from_slice(&[10, 0, 0, 2]);
        fin[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        fin[20..22].copy_from_slice(&34567u16.to_be_bytes());
        fin[22..24].copy_from_slice(&addr.port().to_be_bytes());
        fin[24..28].copy_from_slice(&43u32.to_be_bytes());
        fin[28..32].copy_from_slice(&(INITIAL_SERVER_SEQ + 1).to_be_bytes());
        fin[32] = 0x50;
        fin[33] = 0x11;
        fin[40..].copy_from_slice(payload);

        let fin_packet = parse_raw_tcp(&fin).expect("parse fin payload");
        inbound
            .bootstrap_tcp_session(&fin_packet, writer.clone())
            .await
            .expect("bootstrap fin payload");

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), payload_rx)
            .await
            .expect("receive within timeout")
            .expect("payload sent");
        assert_eq!(received, payload);

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 2);
        let reply = parse_raw_tcp(&packets[1]).expect("parse fin-ack");
        assert_eq!(reply.flags, 0x11);
        assert_eq!(reply.acknowledgment_number, 47);
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_ack_without_session_is_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut ack = vec![0u8; 40];
        ack[0] = 0x45;
        ack[2..4].copy_from_slice(&(40u16).to_be_bytes());
        ack[9] = 6;
        ack[12..16].copy_from_slice(&[10, 0, 0, 2]);
        ack[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        ack[20..22].copy_from_slice(&34567u16.to_be_bytes());
        ack[22..24].copy_from_slice(&addr.port().to_be_bytes());
        ack[24..28].copy_from_slice(&100u32.to_be_bytes());
        ack[28..32].copy_from_slice(&200u32.to_be_bytes());
        ack[32] = 0x50;
        ack[33] = 0x10;

        let packet = parse_raw_tcp(&ack).expect("parse ack");
        inbound
            .bootstrap_tcp_session(&packet, writer.clone())
            .await
            .expect("ignore ack without session");

        assert!(writer.packets.lock().expect("lock packets").is_empty());
        assert_eq!(inbound.session_count(), 0);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_ack_updates_existing_session_state_without_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let syn_raw = build_ipv4_tcp_packet_for_test(addr, 0x02, 42, 0, &[]);
        let syn = parse_raw_tcp(&syn_raw).expect("parse syn");
        inbound
            .bootstrap_tcp_session(&syn, writer.clone())
            .await
            .expect("bootstrap syn");

        let tuple = syn.tuple;
        let session = inbound
            .session_manager
            .get(&tuple)
            .expect("session should exist after syn");
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ);

        let ack_raw = build_ipv4_tcp_packet_for_test(
            addr,
            0x10,
            43,
            INITIAL_SERVER_SEQ + 1,
            &[],
        );
        let ack = parse_raw_tcp(&ack_raw).expect("parse ack");
        inbound
            .bootstrap_tcp_session(&ack, writer.clone())
            .await
            .expect("process ack");

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 1);
        assert_eq!(session.server_acked_seq(), INITIAL_SERVER_SEQ + 1);
    }

    #[tokio::test]
    async fn bootstrap_tcp_session_rst_closes_existing_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut map = std::collections::HashMap::new();
        map.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = Arc::new(OutboundRegistryHandle::new(OutboundRegistry::new(map)));
        let router = Arc::new(RouterHandle::new(Router::with_default(OutboundKind::Direct)));
        let inbound = EnhancedTunInbound::with_router(
            EnhancedTunConfig::default(),
            outbounds,
            router,
        );
        let writer = Arc::new(RecordingTunWriter::default());

        let mut syn = vec![0u8; 40];
        syn[0] = 0x45;
        syn[2..4].copy_from_slice(&(40u16).to_be_bytes());
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[10, 0, 0, 2]);
        syn[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        syn[20..22].copy_from_slice(&34567u16.to_be_bytes());
        syn[22..24].copy_from_slice(&addr.port().to_be_bytes());
        syn[24..28].copy_from_slice(&42u32.to_be_bytes());
        syn[32] = 0x50;
        syn[33] = 0x02;

        let syn_packet = parse_raw_tcp(&syn).expect("parse syn");
        inbound
            .bootstrap_tcp_session(&syn_packet, writer.clone())
            .await
            .expect("bootstrap syn");

        let mut rst = vec![0u8; 40];
        rst[0] = 0x45;
        rst[2..4].copy_from_slice(&(40u16).to_be_bytes());
        rst[9] = 6;
        rst[12..16].copy_from_slice(&[10, 0, 0, 2]);
        rst[16..20].copy_from_slice(
            &addr.ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        rst[20..22].copy_from_slice(&34567u16.to_be_bytes());
        rst[22..24].copy_from_slice(&addr.port().to_be_bytes());
        rst[24..28].copy_from_slice(&43u32.to_be_bytes());
        rst[28..32].copy_from_slice(&(INITIAL_SERVER_SEQ + 1).to_be_bytes());
        rst[32] = 0x50;
        rst[33] = 0x14;

        let rst_packet = parse_raw_tcp(&rst).expect("parse rst");
        inbound
            .bootstrap_tcp_session(&rst_packet, writer.clone())
            .await
            .expect("bootstrap rst");

        let packets = writer.packets.lock().expect("lock packets");
        assert_eq!(packets.len(), 1);
        assert_eq!(inbound.session_count(), 0);
    }
}
