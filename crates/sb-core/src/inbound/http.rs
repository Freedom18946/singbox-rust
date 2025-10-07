//! HTTP inbound service
//!
//! Provides HTTP CONNECT proxy functionality for tunneling TCP connections.
//! This implementation handles HTTP CONNECT requests and establishes tunnels
//! to target destinations.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use crate::adapter::InboundService;

/// HTTP proxy configuration
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Enable authentication
    pub auth_enabled: bool,
    /// Username for basic auth
    pub username: Option<String>,
    /// Password for basic auth
    pub password: Option<String>,
    /// Enable Host sniff to override CONNECT target
    pub sniff_enabled: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            max_connections: 1000,
            auth_enabled: false,
            username: None,
            password: None,
            sniff_enabled: false,
        }
    }
}

/// HTTP CONNECT proxy inbound service
#[derive(Debug)]
pub struct HttpInboundService {
    addr: SocketAddr,
    config: HttpConfig,
    shutdown: Arc<AtomicBool>,
    active_connections: Arc<AtomicU64>,
}

impl HttpInboundService {
    /// Create new HTTP inbound service with default configuration
    pub fn new(addr: SocketAddr) -> Self {
        Self::with_config(addr, HttpConfig::default())
    }

    /// Create new HTTP inbound service with custom configuration
    pub fn with_config(addr: SocketAddr, config: HttpConfig) -> Self {
        Self {
            addr,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get listening address
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Get current active connection count
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Request graceful shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Parse HTTP request line and extract method and target
    async fn parse_request_line(reader: &mut BufReader<&mut TcpStream>) -> io::Result<(String, String)> {
        let mut line = String::new();
        reader.read_line(&mut line).await?;

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid HTTP request line",
            ));
        }

        Ok((parts[0].to_string(), parts[1].to_string()))
    }

    /// Parse host:port from CONNECT target
    fn parse_host_port(target: &str) -> io::Result<(String, u16)> {
        let parts: Vec<&str> = target.split(':').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid CONNECT target format",
            ));
        }

        let host = parts[0].to_string();
        let port = parts[1].parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid port number")
        })?;

        Ok((host, port))
    }

    /// Handle a single HTTP CONNECT request
    async fn handle_connect(&self, mut client: TcpStream, peer: SocketAddr) -> io::Result<()> {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        debug!("HTTP CONNECT: New connection from {}", peer);

        let result = async {
            let mut reader = BufReader::new(&mut client);

            // Parse request line
            let (method, target) = timeout(
                Duration::from_millis(self.config.timeout_ms),
                Self::parse_request_line(&mut reader),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Request timeout"))?
            .map_err(|e| {
                warn!("Failed to parse HTTP request: {}", e);
                e
            })?;

            // Only support CONNECT method
            if method != "CONNECT" {
                let response = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
                client.write_all(response).await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Only CONNECT method supported",
                ));
            }

            // Parse target host and port (initial)
            let (mut host, mut port) = Self::parse_host_port(&target)?;
            info!("HTTP CONNECT: {} -> {}:{}", peer, host, port);

            // Read and parse headers
            let mut headers_raw = String::new();
            let mut headers_list: Vec<(String, String)> = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() { break; }
                headers_raw.push_str(&line);
                if let Some((k, v)) = trimmed.split_once(':') {
                    headers_list.push((k.trim().to_string(), v.trim().to_string()));
                }
            }

            // Optional Basic authentication
            if self.config.auth_enabled {
                let mut ok = false;
                for (k, v) in &headers_list {
                    if k.eq_ignore_ascii_case("Proxy-Authorization") && v.starts_with("Basic ") {
                        use base64::Engine as _;
                        let b64 = v[6..].trim();
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
                            if let Ok(text) = std::str::from_utf8(&bytes) {
                                if let Some((u, p)) = text.split_once(':') {
                                    let u_ok = self.config.username.as_deref().map(|s| s == u).unwrap_or(false);
                                    let p_ok = self.config.password.as_deref().map(|s| s == p).unwrap_or(false);
                                    if u_ok && p_ok { ok = true; break; }
                                }
                            }
                        }
                    }
                }
                if !ok {
                    let response = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"singbox\"\r\nContent-Length: 0\r\n\r\n";
                    client.write_all(response).await?;
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "proxy auth required"));
                }
            }

            // If sniff enabled, prefer Host header for target override
            if self.config.sniff_enabled {
                if let Some((_, v)) = headers_list
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
                {
                    if let Some((h, pstr)) = v.rsplit_once(':') {
                        if let Ok(pp) = pstr.parse::<u16>() {
                            host = h.to_string();
                            // keep original port unless valid port provided in Host
                            port = pp;
                        } else {
                            host = v.clone();
                        }
                    } else {
                        host = v.clone();
                    }
                }
            }

            // Connect to target server (final host/port)
            let target_addr = format!("{}:{}", host, port);
            let mut target_stream = timeout(
                Duration::from_millis(self.config.timeout_ms),
                TcpStream::connect(&target_addr),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Target connection timeout"))?
            .map_err(|e| {
                warn!("Failed to connect to target {}:{}: {}", host, port, e);
                e
            })?;

            // Send 200 Connection established response
            let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
            client.write_all(response).await?;

            debug!("HTTP CONNECT: Established tunnel {} <-> {}:{}", peer, host, port);

            // Start bidirectional data transfer
            let (mut client_read, mut client_write) = client.split();
            let (mut target_read, mut target_write) = target_stream.split();

            let client_to_target = async {
                tokio::io::copy(&mut client_read, &mut target_write).await
            };

            let target_to_client = async {
                tokio::io::copy(&mut target_read, &mut client_write).await
            };

            // Wait for either direction to complete
            tokio::select! {
                result = client_to_target => {
                    debug!("HTTP CONNECT: Client to target finished: {:?}", result);
                }
                result = target_to_client => {
                    debug!("HTTP CONNECT: Target to client finished: {:?}", result);
                }
            }

            Ok(())
        }.await;

        if let Err(e) = result {
            debug!("HTTP CONNECT: Connection {} failed: {}", peer, e);
        }

        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        debug!("HTTP CONNECT: Connection {} closed", peer);
        Ok(())
    }

    /// Main server loop
    async fn serve_async(&self) -> io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        let local_addr = listener.local_addr()?;

        info!("HTTP CONNECT proxy listening on {}", local_addr);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("HTTP CONNECT proxy shutting down");
                break;
            }

            let accept_result = timeout(
                Duration::from_millis(1000),
                listener.accept(),
            ).await;

            match accept_result {
                Ok(Ok((stream, peer))) => {
                    // Check connection limit
                    if self.active_connections() >= self.config.max_connections as u64 {
                        warn!("HTTP CONNECT: Connection limit reached, rejecting {}", peer);
                        drop(stream);
                        continue;
                    }

                    // Handle connection in background task
                    let service = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = service.handle_connect(stream, peer).await {
                            debug!("HTTP CONNECT: Error handling {}: {}", peer, e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    error!("HTTP CONNECT: Accept error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(_) => {
                    // Timeout, continue loop to check shutdown flag
                    continue;
                }
            }
        }

        Ok(())
    }
}

impl Clone for HttpInboundService {
    fn clone(&self) -> Self {
        Self {
            addr: self.addr,
            config: self.config.clone(),
            shutdown: Arc::clone(&self.shutdown),
            active_connections: Arc::clone(&self.active_connections),
        }
    }
}

impl InboundService for HttpInboundService {
    fn serve(&self) -> std::io::Result<()> {
        info!("Starting HTTP CONNECT proxy server on {}", self.addr);

        // Create async runtime for the server
        let rt = tokio::runtime::Runtime::new()
            .map_err(io::Error::other)?;

        // Run the server
        rt.block_on(async {
            self.serve_async().await
        })
    }
}
