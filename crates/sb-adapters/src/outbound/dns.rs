//! DNS outbound connector implementation
//!
//! Provides DNS resolution as an outbound service, allowing routing
//! DNS queries through specific servers or configurations.

use crate::outbound::prelude::*;
use sb_core::dns::transport::DnsTransport as DnsTransportTrait;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// DNS transport protocols
#[derive(Debug, Clone, PartialEq)]
pub enum DnsTransport {
    /// Plain DNS over UDP (port 53)
    Udp,
    /// Plain DNS over TCP (port 53)
    Tcp,
    /// DNS over TLS (port 853)
    DoT,
    /// DNS over HTTPS (port 443)
    DoH,
    /// DNS over QUIC (port 853)
    DoQ,
}

impl DnsTransport {
    fn default_port(&self) -> u16 {
        match self {
            DnsTransport::Udp | DnsTransport::Tcp => 53,
            DnsTransport::DoT | DnsTransport::DoQ => 853,
            DnsTransport::DoH => 443,
        }
    }
}

/// DNS server configuration
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS server address
    pub server: IpAddr,
    /// DNS server port (default: protocol specific)
    pub port: Option<u16>,
    /// Transport protocol
    pub transport: DnsTransport,
    /// Connection timeout
    pub timeout: Duration,
    /// Enable DNS over encrypted protocols
    pub tls_server_name: Option<String>,
    /// Custom DNS query timeout
    pub query_timeout: Duration,
    /// Enable EDNS0 support
    pub enable_edns0: bool,
    /// Maximum message size for EDNS0
    pub edns0_buffer_size: u16,
    /// DoH URL (when using DoH); default to cloudflare if None
    pub doh_url: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            server: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            port: None,
            transport: DnsTransport::Udp,
            timeout: Duration::from_secs(5),
            tls_server_name: None,
            query_timeout: Duration::from_secs(3),
            enable_edns0: true,
            edns0_buffer_size: 1232,
            doh_url: None,
        }
    }
}

/// DNS outbound connector
#[derive(Debug, Clone)]
pub struct DnsConnector {
    config: DnsConfig,
}

impl DnsConnector {
    /// Create a new DNS connector with the given configuration
    pub fn new(config: DnsConfig) -> Self {
        Self { config }
    }

    /// Get the DNS server address with port
    fn server_addr(&self) -> SocketAddr {
        let port = self
            .config
            .port
            .unwrap_or_else(|| self.config.transport.default_port());
        SocketAddr::new(self.config.server, port)
    }

    /// Create a DNS connection based on transport protocol
    async fn create_dns_connection(&self) -> Result<BoxedStream> {
        let server_addr = self.server_addr();

        match self.config.transport {
            DnsTransport::Udp => {
                // UDP DNS typically doesn't maintain persistent connections
                // For UDP, we create a connected UDP socket that behaves like a stream
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(AdapterError::Io)?;

                socket
                    .connect(server_addr)
                    .await
                    .map_err(AdapterError::Io)?;

                // Wrap UDP socket to behave like a stream
                Ok(Box::new(UdpStreamWrapper::new(socket)))
            }
            DnsTransport::Tcp => {
                // TCP DNS connection
                let stream =
                    tokio::time::timeout(self.config.timeout, TcpStream::connect(server_addr))
                        .await
                        .map_err(|_| AdapterError::Timeout(self.config.timeout))?
                        .map_err(AdapterError::Io)?;

                Ok(Box::new(stream))
            }
            DnsTransport::DoT => {
                // DNS over TLS - for now, fallback to TCP
                tracing::warn!("DNS over TLS not fully implemented, falling back to TCP");
                let stream =
                    tokio::time::timeout(self.config.timeout, TcpStream::connect(server_addr))
                        .await
                        .map_err(|_| AdapterError::Timeout(self.config.timeout))?
                        .map_err(AdapterError::Io)?;

                Ok(Box::new(stream))
            }
            DnsTransport::DoH => {
                #[cfg(feature = "dns_doh")]
                {
                    let url = if let Some(u) = &self.config.doh_url {
                        u.clone()
                    } else {
                        // Default to Cloudflare DoH for convenience
                        "https://cloudflare-dns.com/dns-query".to_string()
                    };
                    let doh = sb_core::dns::transport::doh::DohConfig {
                        url,
                        ..Default::default()
                    }
                    .build()
                    .map_err(|e| AdapterError::Other(format!("DoH setup failed: {}", e)))?;
                    Ok(Box::new(DohStreamWrapper::new(doh)))
                }
                #[cfg(not(feature = "dns_doh"))]
                {
                    Err(AdapterError::Other(
                        "DoH not compiled (enable feature dns_doh)".into(),
                    ))
                }
            }
            DnsTransport::DoQ => {
                #[cfg(feature = "dns_doq")]
                {
                    let port = self.config.port.unwrap_or(853);
                    let server = SocketAddr::new(self.config.server, port);
                    let sni = self
                        .config
                        .tls_server_name
                        .clone()
                        .unwrap_or_else(|| self.config.server.to_string());
                    let doq = sb_core::dns::transport::DoqTransport::new(server, sni)
                        .map_err(|e| AdapterError::Other(format!("DoQ setup failed: {}", e)))?;
                    Ok(Box::new(DoqStreamWrapper::new(doq)))
                }
                #[cfg(not(feature = "dns_doq"))]
                {
                    Err(AdapterError::Other(
                        "DoQ not compiled (enable feature dns_doq)".into(),
                    ))
                }
            }
        }
    }

    /// Validate DNS configuration
    fn validate_config(&self) -> Result<()> {
        if self.config.timeout.is_zero() {
            return Err(AdapterError::InvalidConfig("DNS timeout cannot be zero"));
        }

        if self.config.query_timeout.is_zero() {
            return Err(AdapterError::InvalidConfig(
                "DNS query timeout cannot be zero",
            ));
        }

        if matches!(self.config.transport, DnsTransport::DoT | DnsTransport::DoH)
            && self.config.tls_server_name.is_none()
        {
            tracing::warn!("TLS server name not specified for encrypted DNS transport");
        }

        Ok(())
    }
}

impl Default for DnsConnector {
    fn default() -> Self {
        Self::new(DnsConfig::default())
    }
}

#[async_trait]
impl OutboundConnector for DnsConnector {
    fn name(&self) -> &'static str {
        "dns"
    }

    async fn start(&self) -> Result<()> {
        // Validate configuration
        self.validate_config()?;

        // Test connectivity to DNS server
        if let Err(e) =
            tokio::time::timeout(self.config.timeout, TcpStream::connect(self.server_addr())).await
        {
            tracing::warn!("DNS server connectivity test failed: {:?}", e);
            // Don't fail startup for connectivity issues
        }

        tracing::info!(
            "DNS connector started - server: {}, transport: {:?}",
            self.server_addr(),
            self.config.transport
        );

        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        tracing::debug!("DNS connector dialing target: {:?}", target);

        // For DNS connector, we create a connection to the DNS server
        // The actual DNS resolution logic would be handled at a higher level
        let stream = self.create_dns_connection().await?;

        tracing::debug!(
            "DNS connection established to server: {} via {:?}",
            self.server_addr(),
            self.config.transport
        );

        Ok(stream)
    }
}

/// Wrapper to make UDP socket behave like a stream
struct UdpStreamWrapper {
    socket: UdpSocket,
    buffer: Vec<u8>,
}

impl UdpStreamWrapper {
    fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            buffer: Vec::new(),
        }
    }
}

impl tokio::io::AsyncRead for UdpStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.buffer.len());
            buf.put_slice(&self.buffer[..to_copy]);
            self.buffer.drain(..to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        let mut scratch = [0u8; 2048];
        let mut read_buf = tokio::io::ReadBuf::new(&mut scratch);
        match std::pin::Pin::new(&mut self.socket).poll_recv(cx, &mut read_buf) {
            std::task::Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                let to_copy = std::cmp::min(buf.remaining(), filled.len());
                buf.put_slice(&filled[..to_copy]);
                if to_copy < filled.len() {
                    self.buffer.extend_from_slice(&filled[to_copy..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for UdpStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.socket).poll_send(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Minimal DoQ stream adapter (one-shot request/response)
#[cfg(feature = "dns_doq")]
struct DoqStreamWrapper {
    doq: std::sync::Arc<sb_core::dns::transport::DoqTransport>,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    responded: bool,
}

#[cfg(feature = "dns_doq")]
impl DoqStreamWrapper {
    fn new(doq: sb_core::dns::transport::DoqTransport) -> Self {
        Self {
            doq: std::sync::Arc::new(doq),
            write_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            responded: false,
        }
    }
}

#[cfg(feature = "dns_doq")]
impl tokio::io::AsyncWrite for DoqStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.write_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if !self.responded {
            let packet = std::mem::take(&mut self.write_buf);
            let doq = self.doq.clone();
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move { doq.query(&packet).await })
            });
            match res {
                Ok(bytes) => {
                    self.read_buf = bytes;
                    self.read_pos = 0;
                    self.responded = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(
                        format!("DoQ query failed: {}", e),
                    )));
                }
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "dns_doq")]
impl tokio::io::AsyncRead for DoqStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        if !self.responded {
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(Ok(()))
    }
}

/// Minimal DoH stream adapter: write a single DNS query, read single response
#[cfg(feature = "dns_doh")]
struct DohStreamWrapper {
    doh: std::sync::Arc<sb_core::dns::transport::doh::DohTransport>,
    write_buf: Vec<u8>,
    read_buf: Vec<u8>,
    read_pos: usize,
    responded: bool,
}

#[cfg(feature = "dns_doh")]
impl DohStreamWrapper {
    fn new(doh: sb_core::dns::transport::doh::DohTransport) -> Self {
        Self {
            doh: std::sync::Arc::new(doh),
            write_buf: Vec::new(),
            read_buf: Vec::new(),
            read_pos: 0,
            responded: false,
        }
    }
}

#[cfg(feature = "dns_doh")]
impl tokio::io::AsyncWrite for DohStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.write_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if !self.responded {
            let packet = std::mem::take(&mut self.write_buf);
            let doh = self.doh.clone();
            let res = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move { doh.query(&packet).await })
            });
            match res {
                Ok(bytes) => {
                    self.read_buf = bytes;
                    self.read_pos = 0;
                    self.responded = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(
                        format!("DoH query failed: {}", e),
                    )));
                }
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "dns_doh")]
impl tokio::io::AsyncRead for DohStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }
        if !self.responded {
            return std::task::Poll::Pending;
        }
        // Try to collect the response using a background task stored in a global map is overkill; as a simple approach,
        // issue the DoH call synchronously here if buffer empty (edge case when reader is called before flush).
        if !self.write_buf.is_empty() && self.read_buf.is_empty() {
            return std::task::Poll::Pending;
        }
        // No more data
        std::task::Poll::Ready(Ok(()))
    }
}
