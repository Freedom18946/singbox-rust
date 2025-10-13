pub mod error;
pub mod inbound;
pub mod outbound;
pub mod traits;
pub mod transport_config;
// 对外导出 util，供 examples/tests 复用
#[cfg(any(test, feature = "e2e"))]
pub mod testsupport;
pub mod util;

// Re-export commonly used types
pub use error::{AdapterError, Result};
pub use traits::{BoxedStream, OutboundConnector, OutboundDatagram, Target, TransportKind};
pub use transport_config::{TransportConfig, TransportType};
