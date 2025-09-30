//! Block outbound connector
//! This module provides a blocking outbound connector that rejects all connections

use std::net::TcpStream;
use crate::adapter::OutboundConnector;

/// Block connector that rejects all connections
#[derive(Debug, Clone)]
pub struct BlockConnector;

impl BlockConnector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for BlockConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundConnector for BlockConnector {
    fn connect(&self, _host: &str, _port: u16) -> std::io::Result<TcpStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "blocked by policy"
        ))
    }
}