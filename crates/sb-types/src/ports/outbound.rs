//! Outbound connector port.

use crate::errors::CoreError;
use crate::ports::{BoxFuture, BoxedStream};
use crate::session::{OutboundTag, Session, TargetAddr};

/// Outbound connector port.
///
/// Implementations establish connections to remote targets.
/// sb-core calls these methods based on routing decisions.
pub trait OutboundConnector: Send + Sync + std::fmt::Debug + 'static {
    /// Get the tag for this outbound.
    fn tag(&self) -> OutboundTag;

    /// Establish a TCP/stream connection to the target.
    fn connect_stream(
        &self,
        session: &Session,
        target: &TargetAddr,
    ) -> BoxFuture<'_, Result<BoxedStream, CoreError>>;

    /// Send a UDP datagram to the target.
    fn send_datagram(
        &self,
        session: &Session,
        target: &TargetAddr,
        data: &[u8],
    ) -> BoxFuture<'_, Result<(), CoreError>>;
}
