//! Session types for cross-crate data plane communication.
//!
//! # Strategic Purpose
//! `Session` is the unified request context passed through the data plane.
//! It MUST remain lightweight (cheap to clone, no heavy allocations).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_addr_display() {
        let domain = TargetAddr::domain("example.com", 443);
        assert_eq!(domain.to_string(), "example.com:443");

        let socket = TargetAddr::ip("127.0.0.1".parse().unwrap(), 8080);
        assert_eq!(socket.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn session_serialization() {
        let session = Session::new(
            1,
            InboundTag::new("socks"),
            TargetAddr::domain("google.com", 443),
        );
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("google.com"));
    }
}
