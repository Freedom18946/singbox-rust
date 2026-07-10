//! Canonical core-owned fallback outbounds.
//!
//! WP06 removes these direct/block fallbacks after scaffold retirement. Adapter
//! registry entries already use the same canonical contract, so no legacy trait
//! bridge is retained here.

use sb_types::{
    BoxFuture, BoxedPacketConn, BoxedStream, ConnectErrorKind, CoreError, NetworkKind, Outbound,
    OutboundTag, Session,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

const TCP: &[NetworkKind] = &[NetworkKind::Tcp];
const TCP_UDP: &[NetworkKind] = &[NetworkKind::Tcp, NetworkKind::Udp];

#[derive(Debug)]
pub struct DirectOutbound {
    tag: OutboundTag,
}

impl DirectOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: OutboundTag::new(tag),
        }
    }
}

impl Outbound for DirectOutbound {
    fn r#type(&self) -> &str {
        "direct"
    }

    fn tag(&self) -> OutboundTag {
        self.tag.clone()
    }

    fn network(&self) -> &[NetworkKind] {
        TCP_UDP
    }

    fn dial<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
        Box::pin(async move {
            let target = match &session.target {
                sb_types::TargetAddr::Socket(address) => address.to_string(),
                sb_types::TargetAddr::Domain(host, port) => format!("{host}:{port}"),
            };
            let stream = tokio::time::timeout(
                session.connect.connect_timeout,
                tokio::net::TcpStream::connect(target),
            )
            .await
            .map_err(|_| CoreError::timeout("outbound-dial", session.connect.connect_timeout))?
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::ConnectionRefused => {
                    CoreError::connect(ConnectErrorKind::Refused, error.to_string())
                }
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                    CoreError::connect(ConnectErrorKind::Reset, error.to_string())
                }
                std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::NetworkUnreachable => {
                    CoreError::connect(ConnectErrorKind::Unreachable, error.to_string())
                }
                _ => CoreError::io(error.to_string()),
            })?;
            Ok(Box::new(stream.compat()) as BoxedStream)
        })
    }

    fn listen_packet<'a>(
        &'a self,
        session: &'a Session,
    ) -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>> {
        Box::pin(async move {
            let connector = crate::outbound::direct_connector::DirectConnector::new();
            connector.listen_packet(session).await
        })
    }
}

#[derive(Debug)]
pub struct BlockOutbound {
    tag: OutboundTag,
}

impl BlockOutbound {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: OutboundTag::new(tag),
        }
    }
}

impl Outbound for BlockOutbound {
    fn r#type(&self) -> &str {
        "block"
    }

    fn tag(&self) -> OutboundTag {
        self.tag.clone()
    }

    fn network(&self) -> &[NetworkKind] {
        TCP_UDP
    }

    fn dial<'a>(&'a self, _session: &'a Session) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
        Box::pin(async { Err(CoreError::policy("blocked by outbound policy")) })
    }

    fn listen_packet<'a>(
        &'a self,
        _session: &'a Session,
    ) -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>> {
        Box::pin(async { Err(CoreError::policy("blocked by outbound policy")) })
    }
}

/// Explicit fallback for a configured but unsupported core-owned protocol.
#[derive(Debug)]
pub struct UnsupportedOutbound {
    tag: OutboundTag,
    protocol: String,
    reason: String,
}

impl UnsupportedOutbound {
    pub fn new(
        tag: impl Into<String>,
        protocol: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            tag: OutboundTag::new(tag),
            protocol: protocol.into(),
            reason: reason.into(),
        }
    }
}

impl Outbound for UnsupportedOutbound {
    fn r#type(&self) -> &str {
        &self.protocol
    }

    fn tag(&self) -> OutboundTag {
        self.tag.clone()
    }

    fn network(&self) -> &[NetworkKind] {
        TCP
    }

    fn dial<'a>(&'a self, _session: &'a Session) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
        Box::pin(async move {
            Err(CoreError::connect(
                ConnectErrorKind::Unsupported,
                self.reason.clone(),
            ))
        })
    }

    fn listen_packet<'a>(
        &'a self,
        _session: &'a Session,
    ) -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>> {
        Box::pin(async move {
            Err(CoreError::connect(
                ConnectErrorKind::Unsupported,
                self.reason.clone(),
            ))
        })
    }
}
