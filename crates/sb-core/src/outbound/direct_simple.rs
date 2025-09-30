//! DIRECT outbound using TcpDialer.
//! feature = "scaffold"
use crate::adapter::OutboundConnector;
use crate::transport::tcp::{DialResult, TcpDialer};
use std::net::TcpStream;

#[derive(Debug, Default)]
pub struct Direct {
    dialer: TcpDialer,
}

impl Clone for Direct {
    fn clone(&self) -> Self {
        Self {
            dialer: TcpDialer::default(),
        }
    }
}

impl Direct {
    pub fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", host, port);
        let r: DialResult = self.dialer.dial(&addr);
        match (r.stream, r.error) {
            (Some(s), _) => Ok(s),
            (None, Some(e)) => Err(std::io::Error::other(
                format!("direct connect fail: {}", e.class),
            )),
            (None, None) => Err(std::io::Error::other(
                "unknown connect fail",
            )),
        }
    }
}

impl OutboundConnector for Direct {
    fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", host, port);
        let r: DialResult = self.dialer.dial(&addr);
        match (r.stream, r.error) {
            (Some(s), _) => Ok(s),
            (None, Some(e)) => Err(std::io::Error::other(
                format!("direct connect fail: {}", e.class),
            )),
            (None, None) => Err(std::io::Error::other(
                "unknown connect fail",
            )),
        }
    }
}
