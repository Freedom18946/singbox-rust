//! Canonical inbound lifecycle and stream contracts.

use crate::errors::CoreError;
use crate::ports::StartStage;
use crate::session::InboundTag;

/// Runtime-neutral asynchronous byte stream.
///
/// Implementations must remain usable after cancellation of the future that
/// created them.  Ownership is transferred to the caller, which is responsible
/// for shutdown.  Runtime adapters belong outside `sb-types`.
pub trait AsyncStream:
    futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send + 'static
{
}

impl<T> AsyncStream for T where
    T: futures::io::AsyncRead + futures::io::AsyncWrite + Unpin + Send + 'static
{
}

/// Erased canonical stream returned by an outbound dial.
pub type BoxedStream = Box<dyn AsyncStream>;

/// Canonical inbound lifecycle contract.
///
/// `start(StartStage::Start)` must not return success until the listener has
/// bound and made its readiness state observable.  `close` requests shutdown
/// and releases resources owned by the inbound.  Both methods return
/// [`CoreError`] rather than implementation-specific errors; neither operation
/// is cancellation-sensitive because both are synchronous lifecycle requests.
pub trait Inbound: Send + Sync + std::fmt::Debug + 'static {
    /// Stable protocol type (for example, `"socks"`).
    fn r#type(&self) -> &str;

    /// Configured inbound tag.
    fn tag(&self) -> InboundTag;

    /// Start this inbound at the requested supervisor lifecycle stage.
    fn start(&self, stage: StartStage) -> Result<(), CoreError>;

    /// Request orderly shutdown and release listener resources.
    fn close(&self) -> Result<(), CoreError>;

    /// Whether this inbound publishes startup readiness.
    fn supports_startup_readiness(&self) -> bool {
        false
    }

    /// Current active stream count when the implementation can measure it.
    fn active_connections(&self) -> Option<u64> {
        None
    }

    /// Current UDP association estimate when the implementation can measure it.
    fn udp_sessions_estimate(&self) -> Option<u64> {
        None
    }
}
