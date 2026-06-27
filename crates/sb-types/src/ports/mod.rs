//! Ports (traits) for cross-crate abstractions.
//!
//! # Strategic Purpose
//! Ports are the interface contracts between sb-core and its adapters.
//! sb-core depends ONLY on these traits; adapters implement them.
//!
//! # Note on async traits
//! Ports are object-safe so they can be passed through adapter registries and
//! runtime contexts as `dyn Trait`. Async methods return [`BoxFuture`] instead
//! of using `async fn` in traits.

use std::future::Future;
use std::pin::Pin;

/// Boxed future used by object-safe port traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub mod adapter;
pub mod admin;
pub mod dns;
pub mod http;
pub mod inbound;
pub mod metrics;
pub mod outbound;
pub mod service;

pub use adapter::*;
pub use admin::*;
pub use dns::*;
pub use http::*;
pub use inbound::*;
pub use metrics::*;
pub use outbound::*;
pub use service::*;
