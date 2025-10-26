use std::io;
use std::net::ToSocketAddrs;

use sb_core::net::Address;

// TODO: Define Connector trait or import it from the correct location
// TODO: Define AUTH_USER if needed for task-local user context
// Note: The following imports are commented out until needed:
// use std::sync::Arc;
// use async_trait::async_trait;
// use sb_core::session::{ConnectParams, Transport};
// use tokio::net::TcpStream;

/// A connector that uses the router to select an outbound and establish a connection.
#[derive(Clone)]
pub struct RouterConnector {
    // TODO: Router integration can be added later when the Router trait is defined
    // pub router: Arc<dyn Router>,
}

impl Default for RouterConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterConnector {
    /// Create a new RouterConnector
    #[allow(dead_code)]
    pub const fn new() -> Self {
        Self {}
    }

    // NOTE: This implementation is currently incomplete and needs:
    // 1. A Connector trait definition
    // 2. Router trait or RouterHandle integration
    // 3. AUTH_USER task-local setup if needed
    //
    // The following methods are commented out until these dependencies are available:

    /*
    /// 新增：带完整会话上下文的拨号（不改 Connector trait，避免连锁修改）
    pub async fn connect_with(&self, p: &ConnectParams) -> std::io::Result<TcpStream> {
        // TODO: Implement router-based connection
        todo!("Router-based connection not yet implemented")
    }
    */
}

/*
#[async_trait]
impl Connector for RouterConnector {
    async fn connect(&self, target: &str) -> io::Result<TcpStream> {
        // TODO: Implement Connector trait
        todo!("Connector trait not yet implemented")
    }

    async fn connect_ex(&self, p: &ConnectParams) -> io::Result<TcpStream> {
        // TODO: Implement Connector trait
        todo!("Connector trait not yet implemented")
    }
}
*/

#[allow(dead_code)]
fn parse_target(target: &str) -> io::Result<Address> {
    // Try to parse as a socket address first (e.g., "1.2.3.4:80" or "[::1]:80")
    if let Ok(mut addrs) = target.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(Address::Ip(addr));
        }
    }

    // Fallback to parsing as "host:port"
    let Some((host, port_str)) = target.rsplit_once(':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid target format, expected host:port",
        ));
    };

    let port = port_str
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;

    // Handle IPv6 literal addresses like "[::1]"
    let host = host.trim_start_matches('[').trim_end_matches(']');

    Ok(Address::Domain(host.to_string(), port))
}
