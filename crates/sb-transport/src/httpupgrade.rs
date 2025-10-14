//! HTTPUpgrade Transport Layer
//!
//! Minimal HTTP/1.1 Upgrade handshake to establish a raw byte stream
//! over an HTTP connection. Useful for environments where WebSocket is not desired
//! but an upgrade-based tunnel is acceptable.
//!
//! ## Features
//! - Client: GET request with `Upgrade` header, validates `101 Switching Protocols`
//! - Server: Accepts HTTP Upgrade requests and returns raw TCP stream
//! - Simpler than WebSocket (no framing, just raw bytes after handshake)
//!
//! ## Client Usage
//! ```rust,no_run
//! use sb_transport::httpupgrade::{HttpUpgradeDialer, HttpUpgradeConfig};
//! use sb_transport::Dialer;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = HttpUpgradeConfig::default();
//!     let inner = Box::new(sb_transport::TcpDialer);
//!     let dialer = HttpUpgradeDialer::new(config, inner);
//!     let stream = dialer.connect("example.com", 80).await?;
//!     // Use stream for raw TCP communication
//!     Ok(())
//! }
//! ```
//!
//! ## Server Usage
//! ```rust,no_run
//! use sb_transport::httpupgrade::{HttpUpgradeListener, HttpUpgradeServerConfig};
//! use tokio::net::TcpListener;
//!
//! async fn server_example() -> Result<(), Box<dyn std::error::Error>> {
//!     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
//!     let config = HttpUpgradeServerConfig::default();
//!     let listener = HttpUpgradeListener::new(tcp_listener, config);
//!
//!     loop {
//!         let stream = listener.accept().await?;
//!         tokio::spawn(async move {
//!             // Handle upgraded TCP stream
//!         });
//!     }
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            headers: Vec::new(),
        }
    }
}

pub struct HttpUpgradeDialer {
    config: HttpUpgradeConfig,
    inner: Box<dyn Dialer>,
}

impl HttpUpgradeDialer {
    pub fn new(config: HttpUpgradeConfig, inner: Box<dyn Dialer>) -> Self {
        Self { config, inner }
    }
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(HttpUpgradeConfig::default(), inner)
    }
}

#[async_trait]
impl Dialer for HttpUpgradeDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing HTTPUpgrade: {}:{}{}", host, port, self.config.path);
        let mut stream = self.inner.connect(host, port).await?;

        // Compose request
        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
            self.config.path, host, port
        );
        for (k, v) in &self.config.headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        req.push_str("\r\n");

        // Send request
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| DialError::Other(format!("HTTPUpgrade write failed: {}", e)))?;

        // Read response headers until CRLFCRLF
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 256];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| DialError::Other(format!("HTTPUpgrade read failed: {}", e)))?;
            if n == 0 {
                return Err(DialError::Other("HTTPUpgrade: EOF before headers".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                return Err(DialError::Other("HTTPUpgrade: header too large".into()));
            }
        }

        // Validate status line contains 101
        let header_str = String::from_utf8_lossy(&buf);
        let ok = header_str
            .lines()
            .next()
            .map(|line| {
                line.contains(" 101 ")
                    || line.starts_with("HTTP/1.1 101")
                    || line.starts_with("HTTP/1.0 101")
            })
            .unwrap_or(false);
        if !ok {
            return Err(DialError::Other(format!(
                "HTTPUpgrade: bad status line: {}",
                header_str.lines().next().unwrap_or("")
            )));
        }

        Ok(stream)
    }
}

/// HTTPUpgrade server configuration
#[derive(Debug, Clone)]
pub struct HttpUpgradeServerConfig {
    /// Expected upgrade protocol (default: "websocket" for compatibility)
    pub upgrade_protocol: String,
    /// Require specific path match (default: false, accepts any path)
    pub require_path_match: bool,
    /// Expected path (default: "/")
    pub path: String,
}

impl Default for HttpUpgradeServerConfig {
    fn default() -> Self {
        Self {
            upgrade_protocol: "websocket".to_string(),
            require_path_match: false,
            path: "/".to_string(),
        }
    }
}

/// HTTPUpgrade server listener
///
/// This listener accepts incoming HTTPUpgrade connections by:
/// 1. Accepting TCP connections from the underlying listener
/// 2. Reading HTTP request headers
/// 3. Validating Upgrade and Connection headers
/// 4. Sending `101 Switching Protocols` response
/// 5. Returning the raw TCP stream for data transfer
///
/// ## Usage
/// ```rust,no_run
/// use sb_transport::httpupgrade::{HttpUpgradeListener, HttpUpgradeServerConfig};
/// use tokio::net::TcpListener;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
///     let config = HttpUpgradeServerConfig::default();
///     let listener = HttpUpgradeListener::new(tcp_listener, config);
///
///     loop {
///         let stream = listener.accept().await?;
///         tokio::spawn(async move {
///             // Handle upgraded stream (raw TCP, no framing)
///         });
///     }
/// }
/// ```
pub struct HttpUpgradeListener {
    tcp_listener: tokio::net::TcpListener,
    config: HttpUpgradeServerConfig,
}

impl HttpUpgradeListener {
    /// Create a new HTTPUpgrade listener from a TCP listener
    pub fn new(tcp_listener: tokio::net::TcpListener, config: HttpUpgradeServerConfig) -> Self {
        Self {
            tcp_listener,
            config,
        }
    }

    /// Create an HTTPUpgrade listener with default configuration
    pub fn with_default_config(tcp_listener: tokio::net::TcpListener) -> Self {
        Self::new(tcp_listener, HttpUpgradeServerConfig::default())
    }

    /// Accept a new HTTPUpgrade connection
    ///
    /// This method:
    /// 1. Accepts a TCP connection
    /// 2. Reads HTTP request headers
    /// 3. Validates Upgrade request
    /// 4. Sends 101 Switching Protocols
    /// 5. Returns raw TCP stream
    pub async fn accept(&self) -> Result<IoStream, DialError> {
        // Accept TCP connection
        let (mut stream, peer_addr) = self
            .tcp_listener
            .accept()
            .await
            .map_err(|e| DialError::Other(format!("TCP accept failed: {}", e)))?;

        debug!("Accepted TCP connection from {} for HTTPUpgrade", peer_addr);

        // Read HTTP request headers until CRLFCRLF
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 256];
        loop {
            let n = stream
                .read(&mut tmp)
                .await
                .map_err(|e| DialError::Other(format!("HTTPUpgrade read failed: {}", e)))?;
            if n == 0 {
                return Err(DialError::Other(
                    "HTTPUpgrade: client closed before headers".into(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                return Err(DialError::Other(
                    "HTTPUpgrade: request header too large".into(),
                ));
            }
        }

        // Parse and validate request
        let header_str = String::from_utf8_lossy(&buf);
        let lines: Vec<&str> = header_str.lines().collect();

        if lines.is_empty() {
            return Err(DialError::Other("HTTPUpgrade: empty request".into()));
        }

        // Validate request line (GET /path HTTP/1.1)
        let request_line = lines[0];
        if !request_line.starts_with("GET ") {
            return Err(DialError::Other(format!(
                "HTTPUpgrade: expected GET, got: {}",
                request_line
            )));
        }

        // Check Upgrade and Connection headers
        let mut has_upgrade = false;
        let mut has_connection_upgrade = false;

        for line in &lines[1..] {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("upgrade:") {
                has_upgrade = true;
            }
            if line_lower.starts_with("connection:") && line_lower.contains("upgrade") {
                has_connection_upgrade = true;
            }
        }

        if !has_upgrade || !has_connection_upgrade {
            return Err(DialError::Other(
                "HTTPUpgrade: missing Upgrade or Connection: Upgrade headers".into(),
            ));
        }

        debug!("HTTPUpgrade handshake validated for {}", peer_addr);

        // Send 101 Switching Protocols response
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: {}\r\n\
             Connection: Upgrade\r\n\
             \r\n",
            self.config.upgrade_protocol
        );

        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| DialError::Other(format!("HTTPUpgrade response write failed: {}", e)))?;

        debug!("HTTPUpgrade handshake successful for {}", peer_addr);

        // Return raw TCP stream (no framing, just raw bytes from now on)
        Ok(Box::new(stream))
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.tcp_listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_httpupgrade_config_default() {
        let config = HttpUpgradeConfig::default();
        assert_eq!(config.path, "/");
        assert!(config.headers.is_empty());
    }

    #[tokio::test]
    async fn test_httpupgrade_server_config_default() {
        let config = HttpUpgradeServerConfig::default();
        assert_eq!(config.upgrade_protocol, "websocket");
        assert_eq!(config.path, "/");
        assert!(!config.require_path_match);
    }
}
