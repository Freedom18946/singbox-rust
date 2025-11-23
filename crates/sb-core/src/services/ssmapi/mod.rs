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

pub use server::{build_ssmapi_service, SsmapiService};
