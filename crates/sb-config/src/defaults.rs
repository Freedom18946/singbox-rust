//! Default configuration values for listeners.
//!
//! Provides standard defaults for HTTP and SOCKS proxy listeners,
//! commonly used with `#[serde(default = "...")]` attributes.

use crate::model::ListenAddr;

/// Default listen address for both HTTP and SOCKS proxies (localhost).
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1";

/// Default port for HTTP proxy listener.
pub const DEFAULT_HTTP_PORT: u16 = 28090;

/// Default port for SOCKS proxy listener.
pub const DEFAULT_SOCKS_PORT: u16 = 28091;

/// Returns the default [`ListenAddr`] for HTTP proxy: `127.0.0.1:28090`.
///
/// Used with `#[serde(default = "default_http_listen")]`.
#[must_use]
pub fn default_http_listen() -> ListenAddr {
    ListenAddr {
        addr: DEFAULT_LISTEN_ADDR.to_owned(),
        port: DEFAULT_HTTP_PORT,
    }
}

/// Returns the default [`ListenAddr`] for SOCKS proxy: `127.0.0.1:28091`.
///
/// Used with `#[serde(default = "default_socks_listen")]`.
#[must_use]
pub fn default_socks_listen() -> ListenAddr {
    ListenAddr {
        addr: DEFAULT_LISTEN_ADDR.to_owned(),
        port: DEFAULT_SOCKS_PORT,
    }
}
