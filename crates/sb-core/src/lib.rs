pub mod adapter;
pub mod error;
pub mod error_map;
pub mod errors;
pub mod health;
pub mod inbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod log;
pub mod metrics;
pub mod net;
pub mod udp_nat_instrument;
pub mod outbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod pipeline; // <— 新增导出，供适配器使用
#[cfg(feature = "router")]
pub mod routing;
// Expose legacy router module for compatibility with external crates
#[cfg(feature = "router")]
pub mod router;
pub mod runtime;
pub mod session;
pub mod socks5;
pub mod subscribe;
pub mod telemetry;
pub mod transport;
pub mod types;
pub mod util;
pub mod admin {
    pub mod http;
}
pub mod dns;
pub mod geoip;
pub mod http;

pub mod obs;

// 别名模块：为兼容性提供简短的模块名
pub mod observe {
    pub use crate::outbound::observe::*;
}

// TLS utilities
pub mod tls;

pub use adapter::*; // 兼容 re-export
