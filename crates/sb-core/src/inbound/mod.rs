#[cfg(feature = "scaffold")]
pub mod direct;
#[cfg(feature = "scaffold")]
pub mod http;
#[cfg(feature = "scaffold")]
pub mod http_connect;
#[cfg(feature = "scaffold")]
pub mod mixed;
#[cfg(feature = "scaffold")]
pub mod socks5;
#[cfg(feature = "scaffold")]
pub mod tun;

pub mod manager;
#[cfg(feature = "scaffold")]
pub mod unsupported;

pub use manager::InboundManager;
