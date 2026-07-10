use std::{
    io,
    net::SocketAddr,
    sync::{atomic::AtomicBool, atomic::Ordering, Mutex},
    time::Duration,
    time::Instant,
};

use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// 直连出站：直接向目标地址发起 TCP 连接。
/// Direct outbound with Happy Eyeballs (RFC 8305) support for dual-stack connections.
#[derive(Clone, Debug)]
pub struct DirectOutbound {
    tag: sb_types::OutboundTag,
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectOutbound {
    /// Create a new direct outbound instance
    #[inline]
    pub fn new() -> Self {
        Self::with_tag("direct")
    }

    #[inline]
    pub fn with_tag(tag: impl Into<String>) -> Self {
        Self {
            tag: sb_types::OutboundTag::new(tag),
        }
    }

    /// Per-attempt connection timeout
    fn per_attempt_timeout() -> Duration {
        Duration::from_secs(2)
    }

    /// Happy Eyeballs IPv6 stagger delay (RFC 8305 recommends 250-300ms)
    fn ipv6_stagger_delay() -> Duration {
        Duration::from_millis(300)
    }

    /// Implement Happy Eyeballs algorithm for dual-stack connection attempts
    async fn happy_eyeballs_connect(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
        if addrs.is_empty() {
            return Err(io::Error::other("no addresses to connect"));
        }

        // Separate IPv4 and IPv6 addresses
        let (ipv6_addrs, ipv4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());

        // If only one address family, use simple sequential fallback
        if ipv6_addrs.is_empty() {
            return Self::sequential_connect(ipv4_addrs).await;
        }
        if ipv4_addrs.is_empty() {
            return Self::sequential_connect(ipv6_addrs).await;
        }

        // Happy Eyeballs: race IPv4 and IPv6 with stagger
        tokio::select! {
            // Try IPv4 immediately
            result = Self::sequential_connect(ipv4_addrs.clone()) => {
                result
            }
            // Try IPv6 after stagger delay
            result = async {
                sleep(Self::ipv6_stagger_delay()).await;
                Self::sequential_connect(ipv6_addrs.clone()).await
            } => {
                result
            }
        }
    }

    /// Sequential connection attempts with timeout per address
    async fn sequential_connect(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
        let mut last_err: Option<io::Error> = None;
        for addr in addrs {
            match timeout(Self::per_attempt_timeout(), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(io::Error::other("connect timeout")),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no address resolved")))
    }
}

#[derive(Debug)]
struct DirectPacketConn {
    socket: tokio::net::UdpSocket,
    idle_timeout: Duration,
    deadlines: Mutex<PacketDeadlines>,
    closed: AtomicBool,
}

#[derive(Debug, Default)]
struct PacketDeadlines {
    read: Option<Instant>,
    write: Option<Instant>,
}

impl DirectPacketConn {
    fn operation_timeout(&self, read: bool) -> (Instant, Duration) {
        let now = Instant::now();
        let explicit = self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let explicit = if read { explicit.read } else { explicit.write };
        let duration = explicit
            .map(|deadline| deadline.saturating_duration_since(now))
            .unwrap_or(self.idle_timeout);
        (now + duration, duration)
    }

    fn ensure_open(&self) -> Result<(), sb_types::CoreError> {
        if self.closed.load(Ordering::Acquire) {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Reset,
                "packet connection closed",
            ))
        } else {
            Ok(())
        }
    }
}

impl sb_types::PacketConn for DirectPacketConn {
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a sb_types::TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move {
            self.ensure_open()?;
            let (deadline, duration) = self.operation_timeout(false);
            let send = async {
                if self.socket.peer_addr().is_ok() {
                    self.socket.send(data).await
                } else {
                    let address = match destination {
                        sb_types::TargetAddr::Socket(address) => *address,
                        sb_types::TargetAddr::Domain(host, port) => {
                            tokio::net::lookup_host((host.as_str(), *port))
                                .await?
                                .next()
                                .ok_or_else(|| io::Error::other("no UDP destination resolved"))?
                        }
                    };
                    self.socket.send_to(data, address).await
                }
            };
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), send)
                .await
                .map_err(|_| sb_types::CoreError::timeout("packet-send", duration))?
                .map_err(|error| sb_types::CoreError::io(error.to_string()))
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
            .map(|(size, address)| (size, sb_types::TargetAddr::Socket(address)))
            .map_err(|error| sb_types::CoreError::io(error.to_string()))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        self.closed.store(true, Ordering::Release);
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> Option<sb_types::TargetAddr> {
        self.socket
            .local_addr()
            .ok()
            .map(sb_types::TargetAddr::Socket)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        let mut deadlines = self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deadlines.read = deadline;
        deadlines.write = deadline;
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read = deadline;
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .write = deadline;
        Ok(())
    }
}

impl DirectOutbound {
    async fn connect(&self, target: sb_types::TargetAddr) -> io::Result<TcpStream> {
        match target {
            sb_types::TargetAddr::Socket(sock) => {
                // Direct IP connection
                timeout(Self::per_attempt_timeout(), TcpStream::connect(sock))
                    .await
                    .map_err(|_| io::Error::other("connect timeout"))?
            }
            sb_types::TargetAddr::Domain(host, port) => {
                // Resolve all addresses and use Happy Eyeballs
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                    .await?
                    .collect();
                Self::happy_eyeballs_connect(addrs).await
            }
        }
    }
}

impl sb_types::Outbound for DirectOutbound {
    fn r#type(&self) -> &str {
        "direct"
    }
    fn tag(&self) -> sb_types::OutboundTag {
        self.tag.clone()
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
            let stream = self
                .connect(session.target.clone())
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }
    fn listen_packet<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            let bind_address = match session.target {
                sb_types::TargetAddr::Socket(address) if address.is_ipv6() => "[::]:0",
                _ => "0.0.0.0:0",
            };
            let socket = tokio::net::UdpSocket::bind(bind_address)
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            if session.packet.udp_connect {
                let destination = match &session.target {
                    sb_types::TargetAddr::Socket(address) => address.to_string(),
                    sb_types::TargetAddr::Domain(host, port) => format!("{host}:{port}"),
                };
                socket
                    .connect(destination)
                    .await
                    .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            }
            Ok(Box::new(DirectPacketConn {
                socket,
                idle_timeout: session.packet.idle_timeout,
                deadlines: Mutex::new(PacketDeadlines::default()),
                closed: AtomicBool::new(false),
            }) as sb_types::BoxedPacketConn)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_types::Outbound;

    #[tokio::test]
    async fn test_direct_outbound_creation() {
        let outbound = DirectOutbound::new();
        assert_eq!(sb_types::Outbound::tag(&outbound).as_str(), "direct");
    }

    #[tokio::test]
    async fn packet_timeout_reports_idle_then_explicit_duration() {
        let mut session = sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("127.0.0.1", 9),
        );
        session.packet.idle_timeout = Duration::from_millis(30);
        let packet = DirectOutbound::new().listen_packet(&session).await.unwrap();
        let mut buffer = [0_u8; 1];

        let error = packet
            .recv_from(&mut buffer)
            .await
            .expect_err("idle timeout");
        assert!(
            matches!(error, sb_types::CoreError::Timeout { duration, .. } if duration == Duration::from_millis(30))
        );

        packet
            .set_read_deadline(Some(Instant::now() + Duration::from_millis(10)))
            .unwrap();
        let error = packet
            .recv_from(&mut buffer)
            .await
            .expect_err("explicit timeout");
        assert!(
            matches!(error, sb_types::CoreError::Timeout { duration, .. } if duration <= Duration::from_millis(10) && duration < session.packet.idle_timeout)
        );
    }

    #[tokio::test]
    async fn packet_close_rejects_later_io() {
        let session = sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("127.0.0.1", 9),
        );
        let packet = DirectOutbound::new().listen_packet(&session).await.unwrap();
        packet.close().await.unwrap();
        let error = packet
            .send_to(b"x", &session.target)
            .await
            .expect_err("closed packet connection");
        assert!(matches!(
            error,
            sb_types::CoreError::Connect {
                kind: sb_types::ConnectErrorKind::Reset,
                ..
            }
        ));
    }
}
