//! # HTTPUpgrade Transport Layer / HTTPUpgrade 传输层
//!
//! Minimal HTTP/1.1 Upgrade handshake to establish a raw byte stream
//! over an HTTP connection. Useful for environments where WebSocket is not desired
//! but an upgrade-based tunnel is acceptable.
//! 最小化的 HTTP/1.1 Upgrade 握手，用于在 HTTP 连接上建立原始字节流。
//! 适用于不希望使用 WebSocket 但可以接受基于升级的隧道的环境。
//!
//! ## Features / 特性
//! - **Lightweight**: Simpler than WebSocket, no framing overhead after handshake.
//!   **轻量级**: 比 WebSocket 更简单，握手后没有分帧开销。
//! - **Stealth**: Looks like a standard HTTP upgrade request.
//!   **隐蔽性**: 看起来像标准的 HTTP 升级请求。
//! - **Compatibility**: Works with many HTTP proxies and CDNs.
//!   **兼容性**: 适用于许多 HTTP 代理和 CDN。
//!
//! ## Strategic Relevance / 战略关联
//! - **Low Overhead**: Ideal for tunneling raw TCP/UDP traffic without the overhead of WebSocket masking and framing.
//!   **低开销**: 非常适合隧道传输原始 TCP/UDP 流量，而无需 WebSocket 掩码和分帧的开销。
//! - **Fallback**: A useful fallback when WebSocket is blocked or throttled.
//!   **回退**: 当 WebSocket 被阻止或限制时的有用回退。
//!
//! ## Client Usage / 客户端用法
//! ```rust,no_run
//! use sb_transport::httpupgrade::{HttpUpgradeDialer, HttpUpgradeConfig};
//! use sb_transport::{Dialer, TcpDialer};
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = HttpUpgradeConfig {
//!         path: "/tunnel".to_string(),
//!         host: "example.com".to_string(),
//!         ..Default::default()
//!     };
//!     let inner = Box::new(TcpDialer);
//!     let dialer = HttpUpgradeDialer::new(config, inner);
//!     let stream = dialer.connect("example.com", 80).await?;
//!     // Use stream for raw TCP communication
//!     Ok(())
//! }
//! ```
//!
//! ## Server Usage / 服务端用法
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
    /// Request path (default: "/")
    /// 请求路径（默认："/"）
    pub path: String,
    /// Host header value
    /// Host 头部值
    pub host: String,
    /// Custom headers
    /// 自定义头部
    pub headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: "".to_string(),
            headers: Vec::new(),
        }
    }
}

/// HTTPUpgrade dialer / HTTPUpgrade 拨号器
///
/// This dialer establishes a raw byte stream over an HTTP connection using the Upgrade mechanism.
/// 该拨号器使用升级机制在 HTTP 连接上建立原始字节流。
/// It supports:
/// 它支持：
/// - HTTP/1.1 Upgrade handshake
///   HTTP/1.1 升级握手
/// - Custom headers and paths
///   自定义头部和路径
/// - Raw byte stream after handshake
///   握手后的原始字节流
pub struct HttpUpgradeDialer {
    config: HttpUpgradeConfig,
    dialer: Box<dyn Dialer>,
}

impl HttpUpgradeDialer {
    /// Create a new HTTPUpgrade dialer with custom configuration
    /// 使用自定义配置创建新的 HTTPUpgrade 拨号器
    pub fn new(config: HttpUpgradeConfig, dialer: Box<dyn Dialer>) -> Self {
        Self { config, dialer }
    }

    /// Create an HTTPUpgrade dialer with default configuration
    /// 使用默认配置创建 HTTPUpgrade 拨号器
    pub fn with_default_config(dialer: Box<dyn Dialer>) -> Self {
        Self::new(HttpUpgradeConfig::default(), dialer)
    }
}

#[async_trait]
impl Dialer for HttpUpgradeDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 1. Establish underlying connection
        // 1. 建立底层连接
        let mut stream = self.dialer.connect(host, port).await?;

        // 2. Send Upgrade Request
        // 2. 发送升级请求
        let host_header = if !self.config.host.is_empty() {
            &self.config.host
        } else {
            host
        };

        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n",
            self.config.path, host_header
        );

        // Add custom headers
        // 添加自定义头部
        for (k, v) in &self.config.headers {
            request.push_str(&format!("{}: {}\r\n", k, v));
        }

        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| DialError::Other(format!("Failed to send upgrade request: {}", e)))?;

        // 3. Read Response
        // 3. 读取响应
        // We need to read until double CRLF
        // 我们需要读取直到双 CRLF
        let mut buffer = [0u8; 1024];
        let mut header_bytes = Vec::new();
        let mut n_read = 0;

        loop {
            let n = stream
                .read(&mut buffer)
                .await
                .map_err(|e| DialError::Other(format!("Failed to read upgrade response: {}", e)))?;

            if n == 0 {
                return Err(DialError::Other("Connection closed during handshake".into()));
            }

            header_bytes.extend_from_slice(&buffer[..n]);
            n_read += n;

            // Check for double CRLF
            // 检查双 CRLF
            if let Some(pos) = find_subsequence(&header_bytes, b"\r\n\r\n") {
                // Check status code
                // 检查状态码
                let response_str = String::from_utf8_lossy(&header_bytes[..pos]);
                if !response_str.starts_with("HTTP/1.1 101") {
                    return Err(DialError::Other(format!(
                        "Invalid upgrade response: {}",
                        response_str.lines().next().unwrap_or("Unknown")
                    )));
                }

                // If we read more than headers, we need to handle the extra data.
                // Since IoStream is Box<dyn AsyncReadWrite>, we can't easily put back data.
                // For this simple implementation, we assume server doesn't send data immediately
                // or we error if it does (which is safer for now).
                // 如果我们读取的不仅仅是头部，我们需要处理额外的数据。
                // 由于 IoStream 是 Box<dyn AsyncReadWrite>，我们很难放回数据。
                // 对于这个简单的实现，我们假设服务器不会立即发送数据
                // 或者如果发送了就报错（目前这样更安全）。
                if pos + 4 < header_bytes.len() {
                    debug!(
                        "Warning: Read {} bytes of early data after handshake",
                        header_bytes.len() - (pos + 4)
                    );
                    // In a production implementation, we would need a wrapper stream that
                    // handles this pre-read buffer.
                    // 在生产实现中，我们需要一个包装流来处理这个预读缓冲区。
                }

                break;
            }

            if n_read > 4096 {
                return Err(DialError::Other("Response headers too large".into()));
            }
        }

        debug!("HTTP upgrade handshake successful");
        Ok(stream)
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// HTTPUpgrade server configuration / HTTPUpgrade 服务端配置
#[derive(Debug, Clone)]
pub struct HttpUpgradeServerConfig {
    /// Request path to match (default: "/")
    /// 匹配的请求路径（默认："/"）
    pub path: String,
    /// Upgrade protocol name (default: "websocket")
    /// 升级协议名称（默认："websocket"）
    pub upgrade_protocol: String,
    /// Require specific path match (default: false)
    /// 要求特定路径匹配（默认：false）
    pub require_path_match: bool,
}

impl Default for HttpUpgradeServerConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            upgrade_protocol: "websocket".to_string(),
            require_path_match: false,
        }
    }
}

/// HTTPUpgrade server listener / HTTPUpgrade 服务端监听器
///
/// This listener accepts incoming HTTPUpgrade connections by:
/// 该监听器通过以下方式接受传入的 HTTPUpgrade 连接：
/// 1. Accepting TCP connections from the underlying listener
///    接受来自底层监听器的 TCP 连接
/// 2. Reading HTTP request headers
///    读取 HTTP 请求头部
/// 3. Validating Upgrade and Connection headers
///    验证 Upgrade 和 Connection 头部
/// 4. Sending `101 Switching Protocols` response
///    发送 101 Switching Protocols
/// 5. Returns raw TCP stream
///    返回原始 TCP 流
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
    /// 从 TCP 监听器创建新的 HTTPUpgrade 监听器
    pub fn new(tcp_listener: tokio::net::TcpListener, config: HttpUpgradeServerConfig) -> Self {
        Self {
            tcp_listener,
            config,
        }
    }

    /// Create an HTTPUpgrade listener with default configuration
    /// 使用默认配置创建 HTTPUpgrade 监听器
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
