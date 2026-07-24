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
//!     let inner = Box::new(TcpDialer::default());
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
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

const MAX_HEADER_SIZE: usize = 8192;

struct CachedStream {
    inner: IoStream,
    cached: Vec<u8>,
    position: usize,
}

impl CachedStream {
    fn wrap(inner: IoStream, cached: Vec<u8>) -> IoStream {
        if cached.is_empty() {
            inner
        } else {
            Box::new(Self {
                inner,
                cached,
                position: 0,
            })
        }
    }
}

impl AsyncRead for CachedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.position < self.cached.len() {
            let read = (self.cached.len() - self.position).min(buf.remaining());
            buf.put_slice(&self.cached[self.position..self.position + read]);
            self.position += read;
            if self.position == self.cached.len() {
                self.cached.clear();
                self.position = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CachedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn validate_request_component(label: &str, value: &str) -> Result<(), DialError> {
    if value.contains(['\r', '\n']) {
        return Err(DialError::Other(format!(
            "HTTPUpgrade: invalid {label} contains a line break"
        )));
    }
    Ok(())
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

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
        let default_host;
        let host_header = if !self.config.host.is_empty() {
            self.config.host.as_str()
        } else {
            default_host = authority(host, port);
            &default_host
        };
        validate_request_component("path", &self.config.path)?;
        validate_request_component("Host", host_header)?;

        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n",
            self.config.path, host_header
        );

        // Add custom headers
        // 添加自定义头部
        for (k, v) in &self.config.headers {
            if k.eq_ignore_ascii_case("host") {
                continue;
            }
            validate_request_component("header name", k)?;
            validate_request_component("header value", v)?;
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
        loop {
            let n = stream
                .read(&mut buffer)
                .await
                .map_err(|e| DialError::Other(format!("Failed to read upgrade response: {}", e)))?;

            if n == 0 {
                return Err(DialError::Other(
                    "Connection closed during handshake".into(),
                ));
            }

            header_bytes.extend_from_slice(&buffer[..n]);

            // Check for double CRLF
            // 检查双 CRLF
            if let Some(pos) = find_subsequence(&header_bytes, b"\r\n\r\n") {
                if pos + 4 > MAX_HEADER_SIZE {
                    return Err(DialError::Other("Response headers too large".into()));
                }
                // Check status code
                // 检查状态码
                let response_str = String::from_utf8_lossy(&header_bytes[..pos]);
                let mut lines = response_str.lines();
                let status = lines.next().unwrap_or_default();
                if status.split_whitespace().take(2).collect::<Vec<_>>() != ["HTTP/1.1", "101"] {
                    return Err(DialError::Other(format!(
                        "Invalid upgrade response: {}",
                        status
                    )));
                }
                let mut connection_upgrade = false;
                let mut websocket_upgrade = false;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    if name.eq_ignore_ascii_case("connection")
                        && value.trim().eq_ignore_ascii_case("upgrade")
                    {
                        connection_upgrade = true;
                    }
                    if name.eq_ignore_ascii_case("upgrade")
                        && value.trim().eq_ignore_ascii_case("websocket")
                    {
                        websocket_upgrade = true;
                    }
                }
                if !connection_upgrade || !websocket_upgrade {
                    return Err(DialError::Other(
                        "Invalid upgrade response headers".to_string(),
                    ));
                }

                let cached = header_bytes.split_off(pos + 4);
                stream = CachedStream::wrap(stream, cached);
                break;
            }

            if header_bytes.len() > MAX_HEADER_SIZE {
                return Err(DialError::Other("Response headers too large".into()));
            }
        }

        debug!("HTTP upgrade handshake successful");
        Ok(stream)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
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
    /// Optional exact Host header.
    pub host: Option<String>,
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
            host: None,
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
        let (stream, peer_addr) = self
            .tcp_listener
            .accept()
            .await
            .map_err(|e| DialError::Other(format!("TCP accept failed: {}", e)))?;

        debug!("Accepted TCP connection from {} for HTTPUpgrade", peer_addr);
        accept_stream(Box::new(stream), &self.config).await
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.tcp_listener.local_addr()
    }
}

/// Perform HTTPUpgrade over an already-established stream. V2Ray server
/// transports use this after optional TLS termination.
pub async fn accept_stream(
    mut stream: IoStream,
    config: &HttpUpgradeServerConfig,
) -> Result<IoStream, DialError> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 256];
    let header_end = loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|error| DialError::Other(format!("HTTPUpgrade read failed: {error}")))?;
        if n == 0 {
            return Err(DialError::Other(
                "HTTPUpgrade: client closed before headers".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(position) = find_subsequence(&buf, b"\r\n\r\n") {
            if position + 4 > MAX_HEADER_SIZE {
                return Err(DialError::Other(
                    "HTTPUpgrade: request header too large".into(),
                ));
            }
            break position;
        }
        if buf.len() > MAX_HEADER_SIZE {
            return Err(DialError::Other(
                "HTTPUpgrade: request header too large".into(),
            ));
        }
    };

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let lines: Vec<&str> = header_str.lines().collect();
    let Some(request_line) = lines.first() else {
        return Err(DialError::Other("HTTPUpgrade: empty request".into()));
    };
    let mut request_parts = request_line.split_whitespace();
    if request_parts.next() != Some("GET") {
        return Err(DialError::Other(format!(
            "HTTPUpgrade: expected GET, got: {request_line}"
        )));
    }
    let request_path = request_parts.next().unwrap_or_default();
    if request_parts.next() != Some("HTTP/1.1") || request_parts.next().is_some() {
        return Err(DialError::Other(format!(
            "HTTPUpgrade: invalid request line: {request_line}"
        )));
    }
    if config.require_path_match && request_path != config.path {
        return Err(DialError::Other(format!(
            "HTTPUpgrade: path mismatch: {request_path}"
        )));
    }

    let mut has_upgrade = false;
    let mut has_connection_upgrade = false;
    let mut host = None;
    let mut real_websocket = false;
    for line in &lines[1..] {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade")
            && value.eq_ignore_ascii_case(&config.upgrade_protocol)
        {
            has_upgrade = true;
        }
        if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("upgrade") {
            has_connection_upgrade = true;
        }
        if name.eq_ignore_ascii_case("host") {
            host = Some(value);
        }
        if name.eq_ignore_ascii_case("sec-websocket-key") && !value.is_empty() {
            real_websocket = true;
        }
    }

    if !has_upgrade || !has_connection_upgrade {
        return Err(DialError::Other(
            "HTTPUpgrade: missing Upgrade or Connection: Upgrade headers".into(),
        ));
    }
    if real_websocket {
        return Err(DialError::Other(
            "HTTPUpgrade: real WebSocket request received".into(),
        ));
    }
    if config
        .host
        .as_deref()
        .is_some_and(|expected| host != Some(expected))
    {
        return Err(DialError::Other("HTTPUpgrade: host mismatch".into()));
    }

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: {}\r\n\
         Connection: Upgrade\r\n\
         \r\n",
        config.upgrade_protocol
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| DialError::Other(format!("HTTPUpgrade response write failed: {error}")))?;
    debug!("HTTPUpgrade handshake successful");
    Ok(CachedStream::wrap(stream, buf[header_end + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OneShotDialer(std::sync::Mutex<Option<IoStream>>);

    #[async_trait]
    impl Dialer for OneShotDialer {
        async fn connect(&self, _host: &str, _port: u16) -> Result<IoStream, DialError> {
            self.0
                .lock()
                .expect("stream lock")
                .take()
                .ok_or_else(|| DialError::Other("stream already taken".to_string()))
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }

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

    #[tokio::test]
    async fn server_preserves_bytes_pipelined_after_upgrade_request() {
        let (mut client, server) = tokio::io::duplex(4096);
        let client_task = tokio::spawn(async move {
            client
                .write_all(
                    b"GET /tunnel HTTP/1.1\r\nHost: virtual.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nearly-data",
                )
                .await
                .expect("write request and early data");
            let mut response = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                client.read_exact(&mut byte).await.expect("read response");
                response.push(byte[0]);
                if response.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(response.starts_with(b"HTTP/1.1 101"));
        });
        let mut upgraded = accept_stream(
            Box::new(server),
            &HttpUpgradeServerConfig {
                path: "/tunnel".to_string(),
                host: Some("virtual.test".to_string()),
                require_path_match: true,
                ..Default::default()
            },
        )
        .await
        .expect("accept upgrade");
        let mut early = [0_u8; 10];
        upgraded
            .read_exact(&mut early)
            .await
            .expect("read pipelined bytes");
        assert_eq!(&early, b"early-data");
        client_task.await.expect("client task");
    }

    #[tokio::test]
    async fn server_rejects_real_websocket_key() {
        let (mut client, server) = tokio::io::duplex(4096);
        let client_task = tokio::spawn(async move {
            client
                .write_all(
                    b"GET / HTTP/1.1\r\nHost: virtual.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: key\r\n\r\n",
                )
                .await
                .expect("write request");
        });
        let error = match accept_stream(Box::new(server), &HttpUpgradeServerConfig::default()).await
        {
            Ok(_) => panic!("real WebSocket request must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("real WebSocket"));
        client_task.await.expect("client task");
    }

    #[tokio::test]
    async fn client_validates_headers_and_preserves_early_response_bytes() {
        let (client, mut server) = tokio::io::duplex(4096);
        let dialer = OneShotDialer(std::sync::Mutex::new(Some(Box::new(client) as IoStream)));
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let mut byte = [0_u8; 1];
                server.read_exact(&mut byte).await.expect("read request");
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request).contains("Host: localhost:443\r\n"));
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nearly-response",
                )
                .await
                .expect("write response");
        });
        let mut upgraded = HttpUpgradeDialer::new(HttpUpgradeConfig::default(), Box::new(dialer))
            .connect("localhost", 443)
            .await
            .expect("client upgrade");
        let mut early = [0_u8; 14];
        upgraded
            .read_exact(&mut early)
            .await
            .expect("read early response");
        assert_eq!(&early, b"early-response");
        server_task.await.expect("server task");
    }
}
