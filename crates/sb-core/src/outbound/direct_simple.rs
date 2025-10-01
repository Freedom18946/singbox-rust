//! DIRECT outbound using async tokio TcpStream.
//! feature = "scaffold"
use crate::adapter::OutboundConnector;

#[derive(Debug, Default)]
pub struct Direct;

impl Clone for Direct {
    fn clone(&self) -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl OutboundConnector for Direct {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        tokio::net::TcpStream::connect((host, port)).await
    }
}
