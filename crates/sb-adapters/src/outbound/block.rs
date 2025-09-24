use std::io;

use sb_core::{net::Address, pipeline::Outbound};
use tokio::net::TcpStream;

/// 阻断出站：任何连接请求都返回错误。
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockOutbound;

impl BlockOutbound {
    #[inline]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Outbound for BlockOutbound {
    async fn connect(&self, _target: Address) -> io::Result<TcpStream> {
        Err(io::Error::other("blocked by BlockOutbound"))
    }
}
