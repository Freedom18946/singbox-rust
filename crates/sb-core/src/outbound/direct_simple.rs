//! DIRECT outbound using TcpDialer.
//! feature = "scaffold"
use crate::adapter::OutboundConnector;
use crate::transport::tcp::{DialResult, TcpDialer};
use std::net::TcpStream;

#[derive(Debug)]
pub struct Direct {
    dialer: TcpDialer,
}

impl Default for Direct {
    fn default() -> Self {
        Self {
            dialer: TcpDialer::default(),
        }
    }
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
            (None, Some(e)) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("direct connect fail: {}", e.class),
            )),
            (None, None) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
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
            (None, Some(e)) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("direct connect fail: {}", e.class),
            )),
            (None, None) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unknown connect fail",
            )),
        }
    }
}
