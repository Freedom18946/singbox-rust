//! Canonical outbound and packet contracts.

use crate::errors::CoreError;
use crate::ports::{BoxFuture, BoxedStream};
use crate::session::{OutboundTag, Session, TargetAddr};
use std::time::Instant;

/// One bidirectional UDP association owned by an outbound.
///
/// A packet connection snapshots the finalized `Session.connect` and
/// `Session.packet` controls at creation.  Every future is cancellation-safe:
/// dropping it cancels only that operation, not the association.  Implementers
/// convert transport errors to [`CoreError`] at this boundary.
pub trait PacketConn: Send + Sync + std::fmt::Debug + 'static {
    /// Send one datagram to `destination`; returns the payload byte count.
    fn send_to<'a>(
        &'a self,
        data: &'a [u8],
        destination: &'a TargetAddr,
    ) -> BoxFuture<'a, Result<usize, CoreError>>;

    /// Receive one datagram and its source address into `buffer`.
    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, TargetAddr), CoreError>>;

    /// Close the association and release its transport resources.
    fn close(&self) -> BoxFuture<'_, Result<(), CoreError>>;

    /// Local socket address if it is known to the transport.
    fn local_addr(&self) -> Option<TargetAddr>;

    /// Set a combined read/write deadline. `None` clears the explicit deadline.
    fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), CoreError>;

    /// Set a read deadline. `None` clears the explicit deadline.
    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), CoreError>;

    /// Set a write deadline. `None` clears the explicit deadline.
    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), CoreError>;
}

/// Erased canonical UDP association.
pub type BoxedPacketConn = Box<dyn PacketConn>;

/// Canonical outbound contract.
///
/// The routed destination and all connection controls are carried by
/// [`Session`]; callers must finalize it before calling either operation.  A
/// cancelled dial/listen future must not leak a live association.  Errors are
/// normalized to [`CoreError`] at the adapter boundary.
pub trait Outbound: Send + Sync + std::fmt::Debug + 'static {
    /// Stable protocol type (for example, `"trojan"`).
    fn r#type(&self) -> &str;

    /// Configured outbound tag.
    fn tag(&self) -> OutboundTag;

    /// Networks supported by this outbound.
    fn network(&self) -> &[crate::ports::NetworkKind];

    /// Outbounds that must start before this outbound.
    fn dependencies(&self) -> &[OutboundTag] {
        &[]
    }

    /// Establish a byte stream to `session.target`.
    fn dial<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, Result<BoxedStream, CoreError>>;

    /// Open one bidirectional packet association for `session.target`.
    fn listen_packet<'a>(
        &'a self,
        session: &'a Session,
    ) -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>>;

    /// Expose group capability without a general downcast hook.
    fn as_group(&self) -> Option<&dyn OutboundGroup> {
        None
    }
}

/// Outbound that selects among member outbounds.
pub trait OutboundGroup: Outbound {
    /// Currently selected member tag.
    fn now(&self) -> OutboundTag;

    /// All member tags in configured order.
    fn all(&self) -> Vec<OutboundTag>;

    /// Explicit selector mutation capability when this group is selectable.
    fn as_selector_control(&self) -> Option<&dyn SelectorControl> {
        None
    }
}

/// Optional control surface for selector groups.
pub trait SelectorControl: Send + Sync + std::fmt::Debug + 'static {
    /// Select `tag`; cancellation leaves the previously committed selection intact.
    fn select<'a>(&'a self, tag: &'a str) -> BoxFuture<'a, Result<(), CoreError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Inbound, InboundTag, StartStage};

    #[derive(Debug)]
    struct FixturePacket;

    impl PacketConn for FixturePacket {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _destination: &'a TargetAddr,
        ) -> BoxFuture<'a, Result<usize, CoreError>> {
            Box::pin(async move { Ok(data.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, TargetAddr), CoreError>> {
            Box::pin(async { Err(CoreError::internal("fixture has no packet")) })
        }

        fn close(&self) -> BoxFuture<'_, Result<(), CoreError>> {
            Box::pin(async { Ok(()) })
        }

        fn local_addr(&self) -> Option<TargetAddr> {
            None
        }

        fn set_deadline(&self, _deadline: Option<Instant>) -> Result<(), CoreError> {
            Ok(())
        }

        fn set_read_deadline(&self, _deadline: Option<Instant>) -> Result<(), CoreError> {
            Ok(())
        }

        fn set_write_deadline(&self, _deadline: Option<Instant>) -> Result<(), CoreError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FixtureOutbound;

    impl Outbound for FixtureOutbound {
        fn r#type(&self) -> &str {
            "fixture"
        }

        fn tag(&self) -> OutboundTag {
            OutboundTag::new("fixture")
        }

        fn network(&self) -> &[crate::ports::NetworkKind] {
            &[
                crate::ports::NetworkKind::Tcp,
                crate::ports::NetworkKind::Udp,
            ]
        }

        fn dial<'a>(
            &'a self,
            _session: &'a Session,
        ) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
            Box::pin(async { Err(CoreError::internal("fixture has no stream")) })
        }

        fn listen_packet<'a>(
            &'a self,
            _session: &'a Session,
        ) -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>> {
            Box::pin(async { Ok(Box::new(FixturePacket) as BoxedPacketConn) })
        }
    }

    #[derive(Debug)]
    struct FixtureGroup;

    impl Outbound for FixtureGroup {
        fn r#type(&self) -> &str {
            "selector"
        }

        fn tag(&self) -> OutboundTag {
            OutboundTag::new("group")
        }

        fn network(&self) -> &[crate::ports::NetworkKind] {
            &[crate::ports::NetworkKind::Tcp]
        }

        fn dial<'a>(
            &'a self,
            session: &'a Session,
        ) -> BoxFuture<'a, Result<BoxedStream, CoreError>> {
            FixtureOutbound.dial(session)
        }

        fn listen_packet<'a>(
            &'a self,
            session: &'a Session,
        ) -> BoxFuture<'a, Result<BoxedPacketConn, CoreError>> {
            FixtureOutbound.listen_packet(session)
        }

        fn as_group(&self) -> Option<&dyn OutboundGroup> {
            Some(self)
        }
    }

    impl OutboundGroup for FixtureGroup {
        fn now(&self) -> OutboundTag {
            OutboundTag::new("fixture")
        }

        fn all(&self) -> Vec<OutboundTag> {
            vec![OutboundTag::new("fixture")]
        }
    }

    #[derive(Debug)]
    struct FixtureInbound;

    impl Inbound for FixtureInbound {
        fn r#type(&self) -> &str {
            "fixture"
        }

        fn tag(&self) -> InboundTag {
            InboundTag::new("fixture")
        }

        fn start(&self, _stage: StartStage) -> Result<(), CoreError> {
            Ok(())
        }

        fn close(&self) -> Result<(), CoreError> {
            Ok(())
        }
    }

    #[test]
    fn canonical_contracts_are_object_safe() {
        let _outbound: Box<dyn Outbound> = Box::new(FixtureOutbound);
        let _packet: Box<dyn PacketConn> = Box::new(FixturePacket);
        let _group: Box<dyn OutboundGroup> = Box::new(FixtureGroup);
        let _inbound: Box<dyn Inbound> = Box::new(FixtureInbound);
    }
}
