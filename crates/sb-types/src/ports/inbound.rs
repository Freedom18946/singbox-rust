//! Inbound acceptor port.

use crate::errors::CoreError;
use crate::session::{InboundTag, Session};

/// Boxed async stream (placeholder - actual impl in sb-transport).
pub type BoxedStream = Box<dyn AsyncStream>;

/// Async stream trait (Send + Sync wrapper).
pub trait AsyncStream: Send + Sync + 'static {
    // This is a marker trait; actual I/O methods are on the concrete type.
    // We define this here to avoid depending on tokio in sb-types.
}

/// Datagram packet for UDP handling.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub src: Option<std::net::SocketAddr>,
}

/// Handler that sb-core provides to process accepted connections.
///
/// Implementations of `InboundAcceptor` call these methods when connections arrive.
pub trait InboundHandler: Send + Sync + 'static {
    /// Called when a new TCP/stream connection is accepted.
    fn on_stream(
        &self,
        session: Session,
        stream: BoxedStream,
    ) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;

    /// Called when a UDP packet is received.
    fn on_datagram(
        &self,
        session: Session,
        packet: Datagram,
    ) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;
}

/// Inbound acceptor port.
///
/// Implementations listen on a socket and call the handler when connections arrive.
/// The acceptor owns the listening socket; the handler is provided by sb-core.
pub trait InboundAcceptor: Send + Sync + 'static {
    /// Get the tag for this inbound.
    fn tag(&self) -> InboundTag;

    /// Start accepting connections, calling handler for each.
    fn accept_loop<H: InboundHandler>(
        &self,
        handler: H,
    ) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;
}
