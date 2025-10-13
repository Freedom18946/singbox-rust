//! SOCKS5 outbound connector implementation
//!
//! This module provides SOCKS5 proxy support for outbound connections.
//! It implements the SOCKS5 protocol as defined in RFC 1928.

use crate::outbound::prelude::*;
use crate::traits::{OutboundDatagram, ResolveMode};
use anyhow::Context;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use sb_config::outbound::Socks5Config;

/// SOCKS5 outbound connector
#[derive(Debug, Clone)]
pub struct Socks5Connector {
    config: Socks5Config,
    #[cfg(feature = "transport_ech")]
    #[allow(dead_code)]
    ech_config: Option<sb_tls::EchClientConfig>,
}

impl Socks5Connector {
    pub fn new(config: Socks5Config) -> Self {
        #[cfg(feature = "transport_ech")]
        let ech_config = config
            .tls
            .as_ref()
            .and_then(|tls| tls.ech.as_ref())
            .filter(|ech| ech.enabled)
            .map(|ech| sb_tls::EchClientConfig {
                enabled: ech.enabled,
                config: ech.config.clone(),
                config_list: None,
                pq_signature_schemes_enabled: ech.pq_signature_schemes_enabled,
                dynamic_record_sizing_disabled: ech.dynamic_record_sizing_disabled,
            });

        Self {
            config,
            #[cfg(feature = "transport_ech")]
            ech_config,
        }
    }

    /// Create a connector with no authentication
    pub fn no_auth(server: impl Into<String>) -> Self {
        Self {
            config: Socks5Config {
                server: server.into(),
                tag: None,
                username: None,
                password: None,
                connect_timeout_sec: Some(30),
                tls: None,
            },
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a connector with username/password authentication
    pub fn with_auth(
        server: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            config: Socks5Config {
                server: server.into(),
                tag: None,
                username: Some(username.into()),
                password: Some(password.into()),
                connect_timeout_sec: Some(30),
                tls: None,
            },
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }
}

impl Default for Socks5Connector {
    fn default() -> Self {
        Self::no_auth("127.0.0.1:1080")
    }
}

#[async_trait]
impl OutboundConnector for Socks5Connector {
    fn name(&self) -> &'static str {
        "socks5"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-socks"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-socks",
        });

        #[cfg(feature = "adapter-socks")]
        Ok(())
    }

    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-socks"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-socks",
        });

        #[cfg(feature = "adapter-socks")]
        {
            let _span = crate::outbound::span_dial("socks5", &target);

            // Start metrics timing
            #[cfg(feature = "metrics")]
            let start_time = sb_metrics::start_adapter_timer();

            if target.kind != TransportKind::Tcp {
                #[cfg(not(feature = "socks-udp"))]
                return Err(AdapterError::NotImplemented { what: "socks-udp" });

                #[cfg(feature = "socks-udp")]
                return Err(AdapterError::Protocol(
                    "Use dial_udp() for UDP connections".to_string(),
                ));
            }

            let dial_result = async {
                // Parse proxy server address
                let proxy_addr: SocketAddr = self
                    .config
                    .server
                    .parse()
                    .with_context(|| {
                        format!("Invalid SOCKS5 proxy address: {}", self.config.server)
                    })
                    .map_err(|e| AdapterError::Other(e.to_string()))?;

                // Connect to proxy server with timeout
                let mut stream =
                    tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
                        .await
                        .with_context(|| {
                            format!("Failed to connect to SOCKS5 proxy {}", proxy_addr)
                        })
                        .map_err(|e| AdapterError::Other(e.to_string()))?
                        .with_context(|| {
                            format!("TCP connection to SOCKS5 proxy {} failed", proxy_addr)
                        })
                        .map_err(|e| AdapterError::Other(e.to_string()))?;

                // Perform SOCKS5 handshake
                self.socks5_handshake(&mut stream, opts.connect_timeout)
                    .await?;

                // Send CONNECT request
                self.socks5_connect(&mut stream, &target, &opts).await?;

                Ok(stream)
            }
            .await;

            // Record metrics for the dial attempt (both success and failure)
            #[cfg(feature = "metrics")]
            {
                let result = match &dial_result {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e as &dyn core::fmt::Display),
                };
                sb_metrics::record_adapter_dial("socks5", start_time, result);
            }

            // Handle the result
            match dial_result {
                Ok(stream) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %format!("{}:{}", target.host, target.port),
                        has_auth = %self.config.username.is_some(),
                        "SOCKS5 connection established"
                    );
                    Ok(Box::new(stream) as BoxedStream)
                }
                Err(e) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %format!("{}:{}", target.host, target.port),
                        has_auth = %self.config.username.is_some(),
                        error = %e,
                        "SOCKS5 connection failed"
                    );
                    Err(e)
                }
            }
        }
    }
}

impl Socks5Connector {
    /// Create UDP datagram connection through SOCKS5 UDP ASSOCIATE
    #[cfg(feature = "socks-udp")]
    pub async fn dial_udp(
        &self,
        target: Target,
        opts: DialOpts,
    ) -> Result<Arc<dyn OutboundDatagram>> {
        let proxy_addr: SocketAddr = self
            .config
            .server
            .parse()
            .with_context(|| format!("Invalid SOCKS5 proxy address: {}", self.config.server))
            .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Establish TCP control connection for UDP ASSOCIATE
        let mut control_stream =
            tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
                .await
                .with_context(|| format!("Failed to connect to SOCKS5 proxy {}", proxy_addr))
                .map_err(|e| AdapterError::Other(e.to_string()))?
                .with_context(|| format!("TCP connection to SOCKS5 proxy {} failed", proxy_addr))
                .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Perform SOCKS5 handshake
        self.socks5_handshake(&mut control_stream, opts.connect_timeout)
            .await?;

        // Send UDP ASSOCIATE request
        let relay_addr = self
            .socks5_udp_associate(&mut control_stream, opts.connect_timeout)
            .await?;

        // Create UDP socket
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(AdapterError::Io)?;

        // Connect to relay address
        udp_socket
            .connect(relay_addr)
            .await
            .map_err(AdapterError::Io)?;

        // Create SOCKS UDP wrapper
        let socks_udp = SocksUdp::new(
            target,
            udp_socket,
            relay_addr,
            control_stream,
            opts.resolve_mode.clone(),
        )
        .await?;

        Ok(Arc::new(socks_udp))
    }

    /// Create BIND connection through SOCKS5 BIND (passive TCP connection)
    #[cfg(feature = "socks-bind")]
    pub async fn dial_bind(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {
        // Parse proxy server address
        let proxy_addr: SocketAddr = self
            .config
            .server
            .parse()
            .with_context(|| format!("Invalid SOCKS5 proxy address: {}", self.config.server))
            .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Connect to proxy server with timeout
        let mut stream = tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
            .await
            .with_context(|| format!("Failed to connect to SOCKS5 proxy {}", proxy_addr))
            .map_err(|e| AdapterError::Other(e.to_string()))?
            .with_context(|| format!("TCP connection to SOCKS5 proxy {} failed", proxy_addr))
            .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Perform SOCKS5 handshake
        self.socks5_handshake(&mut stream, opts.connect_timeout)
            .await?;

        // Perform BIND and wait for incoming connection
        self.socks5_bind(&mut stream, &target, &opts).await?;

        Ok(Box::new(stream) as BoxedStream)
    }
}

/// SOCKS5 UDP datagram wrapper that handles UDP encapsulation
#[cfg(feature = "socks-udp")]
#[derive(Debug)]
pub struct SocksUdp {
    target: Target,
    udp: UdpSocket,
    #[allow(dead_code)]
    relay_addr: SocketAddr,
    #[allow(dead_code)]
    control: Arc<Mutex<TcpStream>>,
    resolve_mode: ResolveMode,
}

#[cfg(feature = "socks-udp")]
impl SocksUdp {
    async fn new(
        target: Target,
        udp: UdpSocket,
        relay_addr: SocketAddr,
        control: TcpStream,
        resolve_mode: ResolveMode,
    ) -> Result<Self> {
        Ok(Self {
            target,
            udp,
            relay_addr,
            control: Arc::new(Mutex::new(control)),
            resolve_mode,
        })
    }

    /// Encode payload with SOCKS5 UDP header
    fn encode_udp_packet(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Reserved fields (2 bytes) + Fragment (1 byte)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Address type and address
        match self.resolve_mode {
            ResolveMode::Local => {
                // Try to resolve to IP first
                if let Ok(ip) = self.target.host.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(ipv4) => {
                            packet.push(0x01); // IPv4
                            packet.extend_from_slice(&ipv4.octets());
                        }
                        IpAddr::V6(ipv6) => {
                            packet.push(0x04); // IPv6
                            packet.extend_from_slice(&ipv6.octets());
                        }
                    }
                } else {
                    // For Local mode, we should resolve the domain first
                    // For simplicity, falling back to sending domain name
                    if self.target.host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    packet.push(0x03); // Domain name
                    packet.push(self.target.host.len() as u8);
                    packet.extend_from_slice(self.target.host.as_bytes());
                }
            }
            ResolveMode::Remote => {
                // Send domain name to proxy for remote resolution
                if let Ok(ip) = self.target.host.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(ipv4) => {
                            packet.push(0x01); // IPv4
                            packet.extend_from_slice(&ipv4.octets());
                        }
                        IpAddr::V6(ipv6) => {
                            packet.push(0x04); // IPv6
                            packet.extend_from_slice(&ipv6.octets());
                        }
                    }
                } else {
                    if self.target.host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    packet.push(0x03); // Domain name
                    packet.push(self.target.host.len() as u8);
                    packet.extend_from_slice(self.target.host.as_bytes());
                }
            }
        }

        // Port (2 bytes, big endian)
        packet.extend_from_slice(&self.target.port.to_be_bytes());

        // Payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    /// Decode SOCKS5 UDP packet and extract payload
    fn decode_udp_packet<'a>(&self, packet: &'a [u8]) -> Result<&'a [u8]> {
        if packet.len() < 10 {
            return Err(AdapterError::Protocol("UDP packet too short".to_string()));
        }

        // Skip reserved fields (2 bytes) + Fragment (1 byte)
        let mut offset = 3;

        // Parse address type
        let atyp = packet[offset];
        offset += 1;

        let addr_len = match atyp {
            0x01 => 4,  // IPv4
            0x04 => 16, // IPv6
            0x03 => {
                // Domain name
                if offset >= packet.len() {
                    return Err(AdapterError::Protocol(
                        "Invalid domain length position".to_string(),
                    ));
                }
                let len = packet[offset] as usize;
                offset += 1;
                len
            }
            _ => {
                return Err(AdapterError::Protocol(format!(
                    "Invalid address type: {}",
                    atyp
                )))
            }
        };

        // Skip address and port
        offset += addr_len + 2;

        if offset > packet.len() {
            return Err(AdapterError::Protocol(
                "UDP packet header too long".to_string(),
            ));
        }

        Ok(&packet[offset..])
    }
}

#[cfg(feature = "socks-udp")]
#[async_trait]
impl OutboundDatagram for SocksUdp {
    async fn send_to(&self, payload: &[u8]) -> Result<usize> {
        let packet = self.encode_udp_packet(payload)?;

        match self.udp.send(&packet).await {
            Ok(sent) => {
                // Return original payload size, not the encapsulated packet size
                if sent >= packet.len() {
                    Ok(payload.len())
                } else {
                    Err(AdapterError::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Partial packet sent",
                    )))
                }
            }
            Err(e) => Err(AdapterError::Io(e)),
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize> {
        let mut packet_buf = vec![0u8; buf.len() + 1024]; // Extra space for SOCKS header

        match self.udp.recv(&mut packet_buf).await {
            Ok(received) => {
                let payload = self.decode_udp_packet(&packet_buf[..received])?;
                let len = payload.len().min(buf.len());
                buf[..len].copy_from_slice(&payload[..len]);
                Ok(len)
            }
            Err(e) => Err(AdapterError::Io(e)),
        }
    }

    async fn close(&self) -> Result<()> {
        // Close UDP socket (automatically closed when dropped)
        // Control connection is maintained by Arc<Mutex<TcpStream>>
        Ok(())
    }
}

#[cfg(feature = "adapter-socks")]
impl Socks5Connector {
    /// Perform SOCKS5 initial handshake and authentication
    async fn socks5_handshake(&self, stream: &mut TcpStream, timeout: Duration) -> Result<()> {
        // Step 1: Send version and authentication methods
        // Prefer offering both "no-auth" and "user/pass" when credentials are present
        // so the server can select the most permissive method it supports.
        let methods = if self.config.username.is_some() && self.config.password.is_some() {
            vec![0x00, 0x02] // No auth and Username/Password
        } else {
            vec![0x00] // No authentication
        };

        let mut request = vec![0x05, methods.len() as u8];
        request.extend_from_slice(&methods);

        tokio::time::timeout(timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Handshake write timeout",
                ))
            })??;

        // Step 2: Read server response
        let mut response = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Handshake read timeout",
                ))
            })??;

        if response[0] != 0x05 {
            return Err(AdapterError::Protocol(format!(
                "Invalid SOCKS version: {}",
                response[0]
            )));
        }

        match response[1] {
            0x00 => {
                // No authentication required
                Ok(())
            }
            0x02 => {
                // Username/password authentication required
                self.socks5_auth(stream, timeout).await
            }
            0xFF => Err(AdapterError::Protocol(
                "No acceptable authentication methods".to_string(),
            )),
            method => Err(AdapterError::Protocol(format!(
                "Unsupported authentication method: {}",
                method
            ))),
        }
    }

    /// Perform username/password authentication
    async fn socks5_auth(&self, stream: &mut TcpStream, timeout: Duration) -> Result<()> {
        let (username, password) =
            match (self.config.username.as_ref(), self.config.password.as_ref()) {
                (Some(u), Some(p)) => (u, p),
                _ => {
                    return Err(AdapterError::InvalidConfig(
                        "Username/password required but missing in config",
                    ))
                }
            };

        if username.len() > 255 || password.len() > 255 {
            return Err(AdapterError::InvalidConfig("Username or password too long"));
        }

        // Build authentication request
        let mut request = vec![0x01]; // Version
        request.push(username.len() as u8);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());

        tokio::time::timeout(timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Auth write timeout",
                ))
            })??;

        // Read authentication response
        let mut response = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Auth read timeout",
                ))
            })??;

        if response[0] != 0x01 {
            return Err(AdapterError::Protocol(format!(
                "Invalid auth version: {}",
                response[0]
            )));
        }

        if response[1] != 0x00 {
            return Err(AdapterError::AuthenticationFailed);
        }

        Ok(())
    }

    /// Perform UDP ASSOCIATE request and return relay address
    #[cfg(feature = "socks-udp")]
    async fn socks5_udp_associate(
        &self,
        stream: &mut TcpStream,
        timeout: Duration,
    ) -> Result<SocketAddr> {
        // Build UDP ASSOCIATE request
        let mut request = vec![0x05, 0x03, 0x00]; // VER, CMD=UDP ASSOCIATE, RSV

        // Use IPv4 0.0.0.0:0 as client address (we don't know our address yet)
        request.push(0x01); // ATYP=IPv4
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 0.0.0.0
        request.extend_from_slice(&[0x00, 0x00]); // port 0

        // Send request
        tokio::time::timeout(timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "UDP associate write timeout",
                ))
            })??;

        // Read response
        let mut response = [0u8; 4];
        tokio::time::timeout(timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "UDP associate read timeout",
                ))
            })??;

        if response[0] != 0x05 {
            return Err(AdapterError::Protocol(format!(
                "Invalid SOCKS version: {}",
                response[0]
            )));
        }

        if response[1] != 0x00 {
            let error_msg = match response[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(AdapterError::Protocol(format!(
                "UDP ASSOCIATE failed: {} (code: {})",
                error_msg, response[1]
            )));
        }

        // Parse the relay address from the response
        let atyp = response[3];
        match atyp {
            0x01 => {
                // IPv4
                let mut addr_bytes = [0u8; 4];
                tokio::time::timeout(timeout, stream.read_exact(&mut addr_bytes))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate addr read timeout",
                        ))
                    })??;

                let mut port_bytes = [0u8; 2];
                tokio::time::timeout(timeout, stream.read_exact(&mut port_bytes))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate port read timeout",
                        ))
                    })??;

                let port = u16::from_be_bytes(port_bytes);
                let ip = std::net::Ipv4Addr::from(addr_bytes);
                Ok(SocketAddr::new(IpAddr::V4(ip), port))
            }
            0x04 => {
                // IPv6
                let mut addr_bytes = [0u8; 16];
                tokio::time::timeout(timeout, stream.read_exact(&mut addr_bytes))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate addr read timeout",
                        ))
                    })??;

                let mut port_bytes = [0u8; 2];
                tokio::time::timeout(timeout, stream.read_exact(&mut port_bytes))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate port read timeout",
                        ))
                    })??;

                let port = u16::from_be_bytes(port_bytes);
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Ok(SocketAddr::new(IpAddr::V6(ip), port))
            }
            0x03 => {
                // Domain name - not typically used for relay addresses, but handle it
                let mut len_buf = [0u8; 1];
                tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate len read timeout",
                        ))
                    })??;

                let len = len_buf[0] as usize;
                let mut domain_buf = vec![0u8; len];
                tokio::time::timeout(timeout, stream.read_exact(&mut domain_buf))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate domain read timeout",
                        ))
                    })??;

                let mut port_bytes = [0u8; 2];
                tokio::time::timeout(timeout, stream.read_exact(&mut port_bytes))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "UDP associate port read timeout",
                        ))
                    })??;

                let port = u16::from_be_bytes(port_bytes);
                let domain = String::from_utf8_lossy(&domain_buf).to_string();

                // Try to resolve the domain
                match tokio::net::lookup_host((domain.clone(), port))
                    .await?
                    .next()
                {
                    Some(addr) => Ok(addr),
                    None => Err(AdapterError::Network(format!(
                        "Failed to resolve relay domain: {}",
                        domain
                    ))),
                }
            }
            _ => Err(AdapterError::Protocol(format!(
                "Invalid address type in UDP ASSOCIATE response: {}",
                atyp
            ))),
        }
    }

    /// Send CONNECT request and wait for response
    async fn socks5_connect(
        &self,
        stream: &mut TcpStream,
        target: &Target,
        opts: &DialOpts,
    ) -> Result<()> {
        // Build CONNECT request
        let mut request = vec![0x05, 0x01, 0x00]; // VER, CMD=CONNECT, RSV

        // Add target address based on resolve mode
        match opts.resolve_mode {
            ResolveMode::Local => {
                // Try to resolve locally first
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    // Already an IP address
                    match ip {
                        IpAddr::V4(ipv4) => {
                            request.push(0x01); // ATYP=IPv4
                            request.extend_from_slice(&ipv4.octets());
                        }
                        IpAddr::V6(ipv6) => {
                            request.push(0x04); // ATYP=IPv6
                            request.extend_from_slice(&ipv6.octets());
                        }
                    }
                } else {
                    // Domain name - resolve locally
                    match tokio::net::lookup_host((target.host.clone(), target.port)).await {
                        Ok(mut addrs) => {
                            if let Some(addr) = addrs.next() {
                                match addr.ip() {
                                    IpAddr::V4(ipv4) => {
                                        request.push(0x01); // ATYP=IPv4
                                        request.extend_from_slice(&ipv4.octets());
                                    }
                                    IpAddr::V6(ipv6) => {
                                        request.push(0x04); // ATYP=IPv6
                                        request.extend_from_slice(&ipv6.octets());
                                    }
                                }
                            } else {
                                return Err(AdapterError::Network(format!(
                                    "Failed to resolve {}",
                                    target.host
                                )));
                            }
                        }
                        Err(e) => {
                            return Err(AdapterError::Network(format!(
                                "DNS resolution failed for {}: {}",
                                target.host, e
                            )));
                        }
                    }
                }
            }
            ResolveMode::Remote => {
                // Send to proxy for remote resolution
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    // Already an IP address
                    match ip {
                        IpAddr::V4(ipv4) => {
                            request.push(0x01); // ATYP=IPv4
                            request.extend_from_slice(&ipv4.octets());
                        }
                        IpAddr::V6(ipv6) => {
                            request.push(0x04); // ATYP=IPv6
                            request.extend_from_slice(&ipv6.octets());
                        }
                    }
                } else {
                    // Domain name - send to proxy
                    if target.host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    request.push(0x03); // ATYP=DOMAINNAME
                    request.push(target.host.len() as u8);
                    request.extend_from_slice(target.host.as_bytes());
                }
            }
        }

        // Add port
        request.extend_from_slice(&target.port.to_be_bytes());

        // Send request
        tokio::time::timeout(opts.connect_timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connect write timeout",
                ))
            })??;

        // Read response
        let mut response = [0u8; 4];
        tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connect read timeout",
                ))
            })??;

        if response[0] != 0x05 {
            return Err(AdapterError::Protocol(format!(
                "Invalid SOCKS version: {}",
                response[0]
            )));
        }

        if response[1] != 0x00 {
            let error_msg = match response[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown error",
            };
            return Err(AdapterError::Protocol(format!(
                "SOCKS connect failed: {} (code: {})",
                error_msg, response[1]
            )));
        }

        // Skip the rest of the response (bound address and port)
        let atyp = response[3];
        let skip_len = match atyp {
            0x01 => 6,  // IPv4 (4 bytes) + port (2 bytes)
            0x04 => 18, // IPv6 (16 bytes) + port (2 bytes)
            0x03 => {
                // Domain name: read length first
                let mut len_buf = [0u8; 1];
                tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut len_buf))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Response read timeout",
                        ))
                    })??;
                len_buf[0] as usize + 2 // domain length + port (2 bytes)
            }
            _ => {
                return Err(AdapterError::Protocol(format!(
                    "Invalid address type: {}",
                    atyp
                )))
            }
        };

        let mut skip_buf = vec![0u8; skip_len];
        tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut skip_buf))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Response read timeout",
                ))
            })??;

        Ok(())
    }

    /// Perform BIND command and wait for second reply indicating an incoming connection
    #[cfg(feature = "socks-bind")]
    async fn socks5_bind(
        &self,
        stream: &mut TcpStream,
        target: &Target,
        opts: &DialOpts,
    ) -> Result<()> {
        use std::time::Duration;
        // Build BIND request
        let mut request = vec![0x05, 0x02, 0x00]; // VER, CMD=BIND, RSV
                                                  // Address: allow remote resolution or send IP/domain based on ResolveMode
        match opts.resolve_mode {
            ResolveMode::Local => {
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(v4) => {
                            request.push(0x01);
                            request.extend_from_slice(&v4.octets());
                        }
                        IpAddr::V6(v6) => {
                            request.push(0x04);
                            request.extend_from_slice(&v6.octets());
                        }
                    }
                } else {
                    // Resolve locally
                    let addrs = tokio::time::timeout(
                        opts.connect_timeout,
                        tokio::net::lookup_host((&target.host[..], target.port)),
                    )
                    .await
                    .map_err(|_| AdapterError::Network("DNS timeout".to_string()))
                    .and_then(|r| r.map_err(|e| AdapterError::Network(e.to_string())))?;
                    if let Some(sa) = addrs.into_iter().next() {
                        match sa.ip() {
                            IpAddr::V4(v4) => {
                                request.push(0x01);
                                request.extend_from_slice(&v4.octets());
                            }
                            IpAddr::V6(v6) => {
                                request.push(0x04);
                                request.extend_from_slice(&v6.octets());
                            }
                        }
                    } else {
                        return Err(AdapterError::Network(format!(
                            "Failed to resolve {}",
                            target.host
                        )));
                    }
                }
            }
            ResolveMode::Remote => {
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(v4) => {
                            request.push(0x01);
                            request.extend_from_slice(&v4.octets());
                        }
                        IpAddr::V6(v6) => {
                            request.push(0x04);
                            request.extend_from_slice(&v6.octets());
                        }
                    }
                } else {
                    if target.host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    request.push(0x03);
                    request.push(target.host.len() as u8);
                    request.extend_from_slice(target.host.as_bytes());
                }
            }
        }
        request.extend_from_slice(&target.port.to_be_bytes());

        // Send BIND request
        tokio::time::timeout(opts.connect_timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Bind write timeout",
                ))
            })??;

        // Read first reply (bind address)
        let mut head = [0u8; 4];
        tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut head))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Bind read timeout",
                ))
            })??;
        if head[0] != 0x05 {
            return Err(AdapterError::Protocol(format!(
                "Invalid SOCKS version: {}",
                head[0]
            )));
        }
        if head[1] != 0x00 {
            return Err(AdapterError::Protocol(format!(
                "SOCKS bind failed (code: {})",
                head[1]
            )));
        }
        // Skip bound addr in first reply
        let skip = match head[3] {
            0x01 => 6,
            0x04 => 18,
            0x03 => {
                let mut l = [0u8; 1];
                tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut l))
                    .await
                    .map_err(|_| {
                        AdapterError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Bind read timeout",
                        ))
                    })??;
                l[0] as usize + 2
            }
            _ => return Err(AdapterError::Protocol("Invalid ATYP in bind reply".into())),
        };
        let mut sink = vec![0u8; skip];
        tokio::time::timeout(opts.connect_timeout, stream.read_exact(&mut sink))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Bind read timeout",
                ))
            })??;

        // Wait for second reply (incoming connection accepted). Use a generous timeout (connect_timeout * 2)
        let wait = opts
            .connect_timeout
            .checked_mul(2)
            .unwrap_or(Duration::from_secs(60));
        tokio::time::timeout(wait, async {
            let mut head2 = [0u8; 4];
            stream.read_exact(&mut head2).await?;
            if head2[0] != 0x05 || head2[1] != 0x00 {
                return Err(std::io::Error::other("BIND not accepted"));
            }
            // Skip addr
            let skip2 = match head2[3] {
                0x01 => 6,
                0x04 => 18,
                0x03 => {
                    let mut l = [0u8; 1];
                    stream.read_exact(&mut l).await?;
                    l[0] as usize + 2
                }
                _ => 0,
            };
            let mut sink2 = vec![0u8; skip2];
            if skip2 > 0 {
                stream.read_exact(&mut sink2).await?;
            }
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| AdapterError::Other("BIND accept timeout".into()))
        .and_then(|r| r.map_err(AdapterError::Io))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_connector_creation() {
        let config = Socks5Config {
            server: "127.0.0.1:1080".to_string(),
            tag: Some("test".to_string()),
            username: None,
            password: None,
            connect_timeout_sec: Some(30),
            tls: None,
        };

        let connector = Socks5Connector::new(config);
        assert_eq!(connector.name(), "socks5");
    }
}
