//! Core protocol implementations and routing engine for SingBox
//!
//! This is the heart of SingBox, providing:
//!
//! ## Protocol Support
//!
//! ### Inbound Protocols ([`inbound`])
//! - HTTP CONNECT proxy
//! - SOCKS5 (TCP/UDP)
//! - TUN device (Layer 3 VPN)
//! - Mixed (auto-detect HTTP/SOCKS5)
//!
//! ### Outbound Protocols ([`outbound`])
//! - Direct connection
//! - HTTP proxy
//! - SOCKS5
//! - VMess
//! - VLESS
//! - Hysteria2
//! - TUIC
//! - Shadowsocks
//! - Trojan
//! - SSH tunnel
//! - Selector (load balancing/failover)
//!
//! ## Routing & Traffic Management
//!
//! - Rule-based routing engine (domain, IP, GeoIP, process-based)
//! - [`dns`]: DNS resolution with DoH/DoT support
//! - [`geoip`]: GeoIP database integration
//! - [`session`]: Connection session tracking
//!
//! ## Runtime & Health
//!
//! - [`runtime`]: Async runtime management and supervisor
//! - [`health`]: Health check system for outbound endpoints
//! - [`metrics`]: Prometheus metrics collection
//!
//! ## Network Utilities
//!
//! - [`net`]: Network address utilities
//! - [`transport`]: TLS, TCP, UDP transport abstractions
//! - [`udp_nat_instrument`]: UDP NAT session tracking
//!
//! ## Admin & Observability
//!
//! - [`admin::http`]: HTTP admin API
//! - [`telemetry`]: Logging and tracing configuration
//!
//! # Example
//!
//! ```rust,no_run
//! use sb_core::runtime::Supervisor;
//! use sb_config::Config;
//!
//! # tokio_test::block_on(async {
//! // Load config
//! let config = Config::from_file("config.json").unwrap();
//!
//! // Start runtime supervisor
//! let supervisor = Supervisor::new(config).await.unwrap();
//! supervisor.run().await.unwrap();
//! # });
//! ```

pub mod adapter;
pub mod error;
pub mod error_map;
pub mod errors;
pub mod health;
pub mod inbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod log;
pub mod metrics;
pub mod net;
pub mod outbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod pipeline; // <— 新增导出，供适配器使用
#[cfg(feature = "router")]
pub mod routing;
pub mod udp_nat_instrument;
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
