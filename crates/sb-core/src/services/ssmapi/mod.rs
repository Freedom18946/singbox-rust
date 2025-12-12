//! Shadowsocks Manager API (SSMAPI) service implementation.
//!
//! Provides HTTP REST API for managing Shadowsocks users and traffic statistics.
//! Compatible with sing-box Go implementation.
//!
//! ## Endpoints
//! - GET  `/server/v1` - Server info
//! - GET  `/server/v1/users` - List all users
//! - POST `/server/v1/users` - Add new user
//! - GET  `/server/v1/users/{username}` - Get user info with stats
//! - PUT  `/server/v1/users/{username}` - Update user password
//! - DELETE `/server/v1/users/{username}` - Delete user
//! - GET  `/server/v1/stats?clear=true` - Get global and per-user stats

use std::sync::Arc;

pub mod api;
pub mod server;
pub mod traffic;
pub mod user;

pub use server::{build_ssmapi_service, SsmapiService};
pub use traffic::TrafficManager;
pub use user::UserManager;

/// Traffic tracker trait for recording traffic statistics.
///
/// This trait allows Shadowsocks inbound adapters to report traffic
/// to the SSMAPI service without direct coupling.
pub trait TrafficTracker: Send + Sync + 'static {
    /// Record uplink (client -> proxy) traffic for a user.
    fn record_uplink(&self, username: &str, bytes: i64, packets: i64);

    /// Record downlink (proxy -> client) traffic for a user.
    fn record_downlink(&self, username: &str, bytes: i64, packets: i64);

    /// Increment TCP session count for a user.
    fn increment_tcp_sessions(&self, username: &str, delta: i64);

    /// Increment UDP session count for a user.
    fn increment_udp_sessions(&self, username: &str, delta: i64);
}

/// Trait for Shadowsocks inbounds that can be managed by SSMAPI.
///
/// Inbound adapters that implement this trait can be automatically
/// bound to SSMAPI for traffic tracking and user management.
pub trait ManagedSSMServer: Send + Sync {
    /// Set the traffic tracker for this inbound.
    fn set_tracker(&self, tracker: Arc<dyn TrafficTracker>);

    /// Get the inbound tag.
    fn tag(&self) -> &str;

    /// Get the inbound type (e.g., "shadowsocks").
    fn inbound_type(&self) -> &str;
}
