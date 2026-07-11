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

pub mod api;
pub mod server;
pub mod traffic;
pub mod user;

/// Process-local registry for SSM servers managed by protocol adapters.
pub mod registry {
    pub use sb_core::service::ssm::{
        get_managed_ssm_server, register_managed_ssm_server, unregister_managed_ssm_server,
    };
}

pub use sb_core::service::ssm::{ManagedSSMServer, TrafficTracker};

pub use server::{build_ssmapi_service, SsmapiService};
pub use traffic::TrafficManager;
pub use user::UserManager;
