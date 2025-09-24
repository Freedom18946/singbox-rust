use crate::model::ListenAddr;

pub const DEFAULT_HTTP_ADDR: &str = "127.0.0.1";
pub const DEFAULT_SOCKS_ADDR: &str = "127.0.0.1";
pub const DEFAULT_HTTP_PORT: u16 = 28090;
pub const DEFAULT_SOCKS_PORT: u16 = 28091;

pub fn default_http_listen() -> ListenAddr {
    ListenAddr {
        addr: DEFAULT_HTTP_ADDR.to_string(),
        port: DEFAULT_HTTP_PORT,
    }
}

pub fn default_socks_listen() -> ListenAddr {
    ListenAddr {
        addr: DEFAULT_SOCKS_ADDR.to_string(),
        port: DEFAULT_SOCKS_PORT,
    }
}
