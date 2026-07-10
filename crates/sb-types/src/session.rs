//! Session types for cross-crate data plane communication.
//!
//! # Strategic Purpose
//! `Session` is the unified request context passed through the data plane.
//! It MUST remain lightweight (cheap to clone, no heavy allocations).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Unique session identifier (monotonically increasing per process).
pub type SessionId = u64;

/// Inbound connection tag (identifies which listener accepted the connection).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct InboundTag(pub String);

impl InboundTag {
    #[inline]
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InboundTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Outbound route tag (identifies which outbound handler should process).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OutboundTag(pub String);

impl OutboundTag {
    #[inline]
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OutboundTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Target address supporting both resolved IPs and unresolved domains.
/// Supports "lazy resolution" - domains are kept as-is until routing decides to resolve.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TargetAddr {
    /// Domain name (not yet resolved).
    Domain(String, u16),
    /// IPv4/IPv6 socket address.
    Socket(SocketAddr),
}

impl TargetAddr {
    /// Create from domain and port.
    #[inline]
    pub fn domain(host: impl Into<String>, port: u16) -> Self {
        Self::Domain(host.into(), port)
    }

    /// Create from socket address.
    #[inline]
    pub fn socket(addr: SocketAddr) -> Self {
        Self::Socket(addr)
    }

    /// Create from IP and port.
    #[inline]
    pub fn ip(ip: IpAddr, port: u16) -> Self {
        Self::Socket(SocketAddr::new(ip, port))
    }

    /// Create socket target for an IP literal, otherwise preserve domain target.
    #[inline]
    pub fn from_host_port(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        match host.parse::<IpAddr>() {
            Ok(ip) => Self::ip(ip, port),
            Err(_) => Self::domain(host, port),
        }
    }

    /// Get the port.
    #[inline]
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, port) => *port,
            Self::Socket(addr) => addr.port(),
        }
    }

    /// Get the host as a string (domain or IP).
    #[inline]
    pub fn host(&self) -> String {
        match self {
            Self::Domain(domain, _) => domain.clone(),
            Self::Socket(addr) => addr.ip().to_string(),
        }
    }

    /// Check if this is a domain (needs resolution).
    #[inline]
    pub fn is_domain(&self) -> bool {
        matches!(self, Self::Domain(..))
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(host, port) => write!(f, "{}:{}", host, port),
            Self::Socket(addr) => write!(f, "{}", addr),
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Socket(addr)
    }
}

impl From<(String, u16)> for TargetAddr {
    fn from((host, port): (String, u16)) -> Self {
        Self::Domain(host, port)
    }
}

impl From<(&str, u16)> for TargetAddr {
    fn from((host, port): (&str, u16)) -> Self {
        Self::Domain(host.to_string(), port)
    }
}

/// Optional user identifier for multi-user scenarios.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

/// Session metadata (sniffed protocol info, marks, etc.).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SessionMeta {
    /// Sniffed protocol (e.g., "http", "tls", "quic").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// TLS SNI (if detected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// ALPN values (if detected).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub alpn: Vec<String>,
    /// Socket mark for policy routing.
    pub mark: u32,
}

/// DNS resolution policy carried with an outbound connection request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolveMode {
    /// Resolve names before connecting to the outbound.
    Local,
    /// Let the outbound resolve names itself.
    #[default]
    Remote,
}

/// Bounded retry policy for establishing an outbound stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Number of retries after the initial attempt.
    pub max_retries: u32,
    /// Initial retry delay in milliseconds.
    pub base_delay_ms: u64,
    /// Random delay range as a fraction of the base delay.
    pub jitter: f32,
    /// Maximum retry delay in milliseconds.
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_delay_ms: 100,
            jitter: 0.1,
            max_delay_ms: 5_000,
        }
    }
}

impl RetryPolicy {
    /// Construct default retry policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set retry count after initial attempt.
    #[must_use]
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set exponential-backoff base delay in milliseconds.
    #[must_use]
    pub fn with_base_delay(mut self, base_delay_ms: u64) -> Self {
        self.base_delay_ms = base_delay_ms;
        self
    }

    /// Set jitter fraction, clamped to `0.0..=1.0`.
    #[must_use]
    pub fn with_jitter(mut self, jitter: f32) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Set maximum retry delay in milliseconds.
    #[must_use]
    pub fn with_max_delay(mut self, max_delay_ms: u64) -> Self {
        self.max_delay_ms = max_delay_ms;
        self
    }

    /// Calculate randomized exponential-backoff delay for zero-based attempt.
    #[must_use]
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        self.calculate_delay_with_sample(attempt, 0.5)
    }

    /// Calculate delay with caller-supplied jitter sample for deterministic tests.
    #[must_use]
    pub fn calculate_delay_with_sample(&self, attempt: u32, jitter_sample: f32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let exponent = attempt.saturating_sub(1).min(63);
        let base = self.base_delay_ms.saturating_mul(1_u64 << exponent);
        let jitter = self.jitter.clamp(0.0, 1.0);
        let sample = jitter_sample.clamp(0.0, 1.0);
        let factor = 1.0 + (sample - 0.5) * 2.0 * jitter;
        let delayed = (base as f64 * f64::from(factor)) as u64;
        Duration::from_millis(delayed.min(self.max_delay_ms))
    }
}

/// Options that govern a single outbound stream connection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectOptions {
    /// Maximum time for the initial connection and handshake.
    #[serde(with = "duration_serde")]
    pub connect_timeout: Duration,
    /// Maximum idle/read operation time requested by the caller.
    #[serde(with = "duration_serde")]
    pub read_timeout: Duration,
    /// Retry policy applied by adapters that support retries.
    pub retry_policy: RetryPolicy,
    /// Where domain names are resolved.
    pub resolve_mode: ResolveMode,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            retry_policy: RetryPolicy::default(),
            resolve_mode: ResolveMode::Remote,
        }
    }
}

impl ConnectOptions {
    /// Construct default connection options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connection establishment timeout.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set read timeout.
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Set retry policy.
    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Set DNS resolution policy.
    #[must_use]
    pub fn with_resolve_mode(mut self, resolve_mode: ResolveMode) -> Self {
        self.resolve_mode = resolve_mode;
        self
    }
}

/// Final UDP route options captured when an outbound packet association opens.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketOptions {
    /// Whether the outbound should create a connected UDP socket.
    #[serde(default)]
    pub udp_connect: bool,
    /// Effective idle timeout after route/inbound/protocol precedence resolution.
    #[serde(with = "duration_serde")]
    pub idle_timeout: Duration,
    /// Whether reverse domain mapping is disabled for this association.
    #[serde(default)]
    pub udp_disable_domain_unmapping: bool,
}

impl Default for PacketOptions {
    fn default() -> Self {
        Self {
            udp_connect: false,
            idle_timeout: Duration::from_secs(5 * 60),
            udp_disable_domain_unmapping: false,
        }
    }
}

/// Unified session context for data plane.
///
/// This is the core request context passed through inbound → router → outbound.
/// It MUST be cheap to clone (use Arc for large fields if needed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID.
    pub sid: SessionId,
    /// Which inbound accepted this connection.
    pub inbound: InboundTag,
    /// Optional authenticated user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserId>,
    /// Target address (may be domain or resolved IP).
    pub target: TargetAddr,
    /// Additional metadata.
    #[serde(default)]
    pub meta: SessionMeta,
    /// Connection controls finalized by routing before `Outbound::dial`.
    #[serde(default)]
    pub connect: ConnectOptions,
    /// Packet controls finalized by routing before `Outbound::listen_packet`.
    #[serde(default)]
    pub packet: PacketOptions,
}

impl Session {
    /// Create a minimal session.
    #[inline]
    pub fn new(sid: SessionId, inbound: InboundTag, target: TargetAddr) -> Self {
        Self {
            sid,
            inbound,
            user: None,
            target,
            meta: SessionMeta::default(),
            connect: ConnectOptions::default(),
            packet: PacketOptions::default(),
        }
    }

    /// Create detached outbound session for direct adapter use and tests.
    #[inline]
    pub fn outbound(target: TargetAddr) -> Self {
        Self::new(0, InboundTag::new("outbound"), target)
    }

    /// Replace connection controls.
    #[must_use]
    pub fn with_connect(mut self, connect: ConnectOptions) -> Self {
        self.connect = connect;
        self
    }

    /// Replace packet controls.
    #[must_use]
    pub fn with_packet(mut self, packet: PacketOptions) -> Self {
        self.packet = packet;
        self
    }
}

/// Serde codec used by the canonical contract for duration values in milliseconds.
pub mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn target_addr_display() {
        let domain = TargetAddr::domain("example.com", 443);
        assert_eq!(domain.to_string(), "example.com:443");

        let socket = TargetAddr::ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(socket.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn session_serialization() -> Result<(), Box<dyn Error>> {
        let session = Session::new(
            1,
            InboundTag::new("socks"),
            TargetAddr::domain("google.com", 443),
        );
        let json = serde_json::to_string(&session)?;
        assert!(json.contains("google.com"));
        let decoded: Session = serde_json::from_str(&json)?;
        assert_eq!(decoded.connect.connect_timeout, Duration::from_secs(10));
        assert_eq!(decoded.packet.idle_timeout, Duration::from_secs(5 * 60));
        Ok(())
    }
}
