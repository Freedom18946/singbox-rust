//! SOCKS5 outbound connector implementation
//! SOCKS5 出站连接器实现
//!
//! This module provides SOCKS5 proxy support for outbound connections.
//! 本模块为出站连接提供 SOCKS5 代理支持。
//! It implements the SOCKS5 protocol as defined in RFC 1928.
//! 它实现了 RFC 1928 中定义的 SOCKS5 协议。

use crate::outbound::prelude::*;
#[allow(unused_imports)]
use anyhow::Context;

use sb_types::{ConnectOptions, ResolveMode};

use std::net::{IpAddr, SocketAddr};
#[cfg(any(feature = "socks-udp", feature = "socks-tls"))]
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(feature = "socks-udp")]
use tokio::net::UdpSocket;
#[cfg(feature = "socks-udp")]
use tokio::sync::Mutex;

#[cfg(feature = "socks-tls")]
use rustls_pki_types::ServerName;
#[cfg(feature = "socks-tls")]
use tokio_rustls::{rustls::ClientConfig, TlsConnector};

use sb_config::outbound::Socks5Config;

/// SOCKS5 outbound connector
/// SOCKS5 出站连接器
#[derive(Debug, Clone)]
pub struct Socks5Connector {
    config: Socks5Config,
    use_tls: bool,
    #[cfg(feature = "transport_ech")]
    #[allow(dead_code)]
    ech_config: Option<sb_tls::EchClientConfig>,
}

impl Socks5Connector {
    pub const fn name(&self) -> &'static str {
        "socks5"
    }

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
            use_tls: false,
            #[cfg(feature = "transport_ech")]
            ech_config,
        }
    }

    /// Create a connector with TLS support
    /// 创建支持 TLS 的连接器
    #[cfg(feature = "socks-tls")]
    pub fn with_tls(config: Socks5Config) -> Self {
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
            use_tls: true,
            #[cfg(feature = "transport_ech")]
            ech_config,
        }
    }

    /// Create a connector with no authentication
    /// 创建无需认证的连接器
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
            use_tls: false,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a TLS connector with no authentication
    /// 创建无需认证的 TLS 连接器
    #[cfg(feature = "socks-tls")]
    pub fn no_auth_tls(server: impl Into<String>) -> Self {
        Self {
            config: Socks5Config {
                server: server.into(),
                tag: None,
                username: None,
                password: None,
                connect_timeout_sec: Some(30),
                tls: None,
            },
            use_tls: true,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a connector with username/password authentication
    /// 创建带用户名/密码认证的连接器
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
            use_tls: false,
            #[cfg(feature = "transport_ech")]
            ech_config: None,
        }
    }

    /// Create a TLS connector with username/password authentication
    /// 创建带用户名/密码认证的 TLS 连接器
    #[cfg(feature = "socks-tls")]
    pub fn with_auth_tls(
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
            use_tls: true,
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

impl Socks5Connector {
    pub async fn dial(&self, session: &Session) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-socks"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-socks",
        });

        #[cfg(feature = "adapter-socks")]
        {
            let retry_policy = session.connect.retry_policy.clone();

            // We need to clone these for the closure
            let this = self.clone();
            let target = session.target.clone();
            let opts = session.connect.clone();

            crate::traits::with_adapter_retry(&retry_policy, "socks5", move || {
                let this = this.clone();
                let target = target.clone();
                let opts = opts.clone();

                async move {
                    let _span = crate::outbound::span_dial("socks5", &target);

                    // Start metrics timing
                    // 开始指标计时
                    #[cfg(feature = "metrics")]
                    let start_time = sb_metrics::start_adapter_timer();

                    let dial_result = async {
                        // Parse proxy server address
                        // 解析代理服务器地址
                        let proxy_addr: SocketAddr = this.config.server.parse().map_err(|e| {
                            AdapterError::Other(format!(
                                "Invalid SOCKS5 proxy address {}: {}",
                                this.config.server, e
                            ))
                        })?;

                        // Connect to proxy server with timeout
                        // 连接到代理服务器 (带超时)
                        let mut stream = match tokio::time::timeout(
                            opts.connect_timeout,
                            TcpStream::connect(proxy_addr),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => return Err(AdapterError::Io(e)),
                            Err(_) => return Err(AdapterError::Timeout(opts.connect_timeout)),
                        };

                        if this.use_tls {
                            #[cfg(not(feature = "socks-tls"))]
                            return Err(AdapterError::NotImplemented { what: "socks-tls" });

                            #[cfg(feature = "socks-tls")]
                            {
                                // Create TLS config
                                // 创建 TLS 配置
                                let root_store = tokio_rustls::rustls::RootCertStore {
                                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                                };

                                let config = ClientConfig::builder()
                                    .with_root_certificates(root_store)
                                    .with_no_client_auth();

                                let connector = TlsConnector::from(Arc::new(config));

                                // Parse host for SNI
                                // 解析主机名用于 SNI
                                let host = this.config.server.split(':').next().ok_or(
                                    AdapterError::InvalidConfig("Invalid proxy server address"),
                                )?;

                                let server_name = ServerName::try_from(host)
                                    .map_err(|_| {
                                        AdapterError::InvalidConfig("Invalid server name for TLS")
                                    })?
                                    .to_owned();

                                // Perform TLS handshake
                                // 执行 TLS 握手
                                let mut tls_stream = tokio::time::timeout(
                                    opts.connect_timeout,
                                    connector.connect(server_name, stream),
                                )
                                .await
                                .with_context(|| {
                                    format!("TLS handshake timeout with SOCKS5 proxy {}", host)
                                })
                                .map_err(|e| AdapterError::Other(e.to_string()))?
                                .with_context(|| {
                                    format!("TLS handshake failed with SOCKS5 proxy {}", host)
                                })
                                .map_err(|e| AdapterError::Other(e.to_string()))?;

                                // Perform SOCKS5 handshake over TLS
                                // 通过 TLS 执行 SOCKS5 握手
                                this.socks5_handshake_generic(
                                    &mut tls_stream,
                                    opts.connect_timeout,
                                )
                                .await?;

                                // Send CONNECT request over TLS
                                // 通过 TLS 发送 CONNECT 请求
                                this.socks5_connect_generic(&mut tls_stream, &target, &opts)
                                    .await?;

                                Ok(Box::new(tls_stream) as BoxedStream)
                            }
                        } else {
                            // Perform SOCKS5 handshake
                            // 执行 SOCKS5 握手
                            this.socks5_handshake(&mut stream, opts.connect_timeout)
                                .await?;

                            // Send CONNECT request
                            // 发送 CONNECT 请求
                            this.socks5_connect(&mut stream, &target, &opts).await?;

                            Ok(Box::new(stream) as BoxedStream)
                        }
                    }
                    .await;

                    // Record metrics for the dial attempt (both success and failure)
                    // 记录拨号尝试的指标 (成功和失败)
                    #[cfg(feature = "metrics")]
                    {
                        let result = match &dial_result {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e as &dyn core::fmt::Display),
                        };
                        sb_metrics::record_adapter_dial("socks5", start_time, result);
                    }

                    // Handle the result
                    // 处理结果
                    match dial_result {
                        Ok(stream) => {
                            tracing::debug!(
                                server = %this.config.server,
                                target = %target,
                                has_auth = %this.config.username.is_some(),
                                "SOCKS5 connection established"
                            );
                            Ok(stream)
                        }
                        Err(e) => {
                            tracing::debug!(
                                server = %this.config.server,
                                target = %target,
                                has_auth = %this.config.username.is_some(),
                                error = %e,
                                "SOCKS5 connection failed"
                            );
                            Err(e)
                        }
                    }
                }
            })
            .await
        }
    }
}

impl sb_types::Outbound for Socks5Connector {
    fn r#type(&self) -> &str {
        "socks"
    }

    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(
            self.config
                .tag
                .clone()
                .unwrap_or_else(|| "socks".to_string()),
        )
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
    }

    fn dial<'a>(
        &'a self,
        session: &'a Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;

            let stream = Socks5Connector::dial(self, session)
                .await
                .map_err(|error| crate::outbound::core_error(error, session))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }

    fn listen_packet<'a>(
        &'a self,
        session: &'a Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            #[cfg(feature = "socks-udp")]
            {
                self.dial_udp(session)
                    .await
                    .map_err(|error| crate::outbound::core_error(error, session))
            }
            #[cfg(not(feature = "socks-udp"))]
            {
                let _ = session;
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "SOCKS UDP support is not compiled",
                ))
            }
        })
    }
}

impl Socks5Connector {
    /// Create UDP datagram connection through SOCKS5 UDP ASSOCIATE
    /// 通过 SOCKS5 UDP ASSOCIATE 创建 UDP 数据报连接
    #[cfg(feature = "socks-udp")]
    pub async fn dial_udp(&self, session: &Session) -> Result<sb_types::BoxedPacketConn> {
        let opts = &session.connect;
        let proxy_addr: SocketAddr = self
            .config
            .server
            .parse()
            .with_context(|| format!("Invalid SOCKS5 proxy address: {}", self.config.server))
            .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Establish TCP control connection for UDP ASSOCIATE
        // 为 UDP ASSOCIATE 建立 TCP 控制连接
        let mut control_stream =
            tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
                .await
                .with_context(|| format!("Failed to connect to SOCKS5 proxy {}", proxy_addr))
                .map_err(|e| AdapterError::Other(e.to_string()))?
                .with_context(|| format!("TCP connection to SOCKS5 proxy {} failed", proxy_addr))
                .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Perform SOCKS5 handshake
        // 执行 SOCKS5 握手
        self.socks5_handshake(&mut control_stream, opts.connect_timeout)
            .await?;

        // Send UDP ASSOCIATE request
        // 发送 UDP ASSOCIATE 请求
        let relay_addr = self
            .socks5_udp_associate(&mut control_stream, opts.connect_timeout)
            .await?;

        // Create UDP socket.
        //
        // Prefer binding to loopback when the relay is loopback, which avoids
        // platform sandbox restrictions that sometimes reject wildcard binds
        // in test environments, while keeping the normal dual-stack wildcard
        // behavior for real remote relays.
        let udp_socket = if relay_addr.ip().is_loopback() {
            match relay_addr.ip() {
                IpAddr::V4(_) => match UdpSocket::bind("127.0.0.1:0").await {
                    Ok(s) => s,
                    Err(_) => UdpSocket::bind("0.0.0.0:0")
                        .await
                        .map_err(AdapterError::Io)?,
                },
                IpAddr::V6(_) => match UdpSocket::bind("[::1]:0").await {
                    Ok(s) => s,
                    Err(_) => UdpSocket::bind("[::]:0").await.map_err(AdapterError::Io)?,
                },
            }
        } else {
            // Dual-stack to support IPv6 relay addresses.
            match UdpSocket::bind("[::]:0").await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(AdapterError::Io)?,
            }
        };

        // Connect to relay address
        // 连接到中继地址
        udp_socket
            .connect(relay_addr)
            .await
            .map_err(AdapterError::Io)?;

        // Create SOCKS UDP wrapper
        // 创建 SOCKS UDP 包装器
        let socks_udp = SocksUdp::new(
            udp_socket,
            relay_addr,
            control_stream,
            opts.resolve_mode.clone(),
            session.packet.idle_timeout,
        )
        .await?;

        Ok(Box::new(socks_udp))
    }

    /// Create BIND connection through SOCKS5 BIND (passive TCP connection)
    /// 通过 SOCKS5 BIND 创建 BIND 连接（被动 TCP 连接）
    #[cfg(feature = "socks-bind")]
    pub async fn dial_bind(&self, session: &Session) -> Result<BoxedStream> {
        let target = &session.target;
        let opts = &session.connect;
        // Parse proxy server address
        // 解析代理服务器地址
        let proxy_addr: SocketAddr = self
            .config
            .server
            .parse()
            .with_context(|| format!("Invalid SOCKS5 proxy address: {}", self.config.server))
            .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Connect to proxy server with timeout
        // 连接到代理服务器 (带超时)
        let mut stream = tokio::time::timeout(opts.connect_timeout, TcpStream::connect(proxy_addr))
            .await
            .with_context(|| format!("Failed to connect to SOCKS5 proxy {}", proxy_addr))
            .map_err(|e| AdapterError::Other(e.to_string()))?
            .with_context(|| format!("TCP connection to SOCKS5 proxy {} failed", proxy_addr))
            .map_err(|e| AdapterError::Other(e.to_string()))?;

        // Perform SOCKS5 handshake
        // 执行 SOCKS5 握手
        self.socks5_handshake(&mut stream, opts.connect_timeout)
            .await?;

        // Perform BIND and wait for incoming connection
        // 执行 BIND 并等待传入连接
        self.socks5_bind(&mut stream, target, opts).await?;

        Ok(Box::new(stream) as BoxedStream)
    }
}

/// SOCKS5 UDP datagram wrapper that handles UDP encapsulation
/// 处理 UDP 封装的 SOCKS5 UDP 数据报包装器
#[cfg(feature = "socks-udp")]
#[derive(Debug)]
pub struct SocksUdp {
    udp: UdpSocket,
    #[allow(dead_code)]
    relay_addr: SocketAddr,
    #[allow(dead_code)]
    control: Arc<Mutex<TcpStream>>,
    resolve_mode: ResolveMode,
    idle_timeout: Duration,
    deadlines: parking_lot::Mutex<PacketDeadlines>,
    closed: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "socks-udp")]
#[derive(Debug, Default)]
struct PacketDeadlines {
    read: Option<std::time::Instant>,
    write: Option<std::time::Instant>,
}

#[cfg(feature = "socks-udp")]
impl SocksUdp {
    async fn new(
        udp: UdpSocket,
        relay_addr: SocketAddr,
        control: TcpStream,
        resolve_mode: ResolveMode,
        idle_timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            udp,
            relay_addr,
            control: Arc::new(Mutex::new(control)),
            resolve_mode,
            idle_timeout,
            deadlines: parking_lot::Mutex::new(PacketDeadlines::default()),
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn operation_deadline(&self, read: bool) -> std::time::Instant {
        let deadlines = self.deadlines.lock();
        let explicit = if read {
            deadlines.read
        } else {
            deadlines.write
        };
        explicit.unwrap_or_else(|| std::time::Instant::now() + self.idle_timeout)
    }

    /// Encode payload with SOCKS5 UDP header
    /// 使用 SOCKS5 UDP 头部编码负载
    fn encode_udp_packet(&self, payload: &[u8], destination: &TargetAddr) -> Result<Vec<u8>> {
        let mut packet = Vec::new();
        let host = destination.host();

        // Reserved fields (2 bytes) + Fragment (1 byte)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);

        // Address type and address
        match self.resolve_mode {
            ResolveMode::Local => {
                // Try to resolve to IP first
                if let Ok(ip) = host.parse::<IpAddr>() {
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
                    if host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    packet.push(0x03); // Domain name
                    packet.push(host.len() as u8);
                    packet.extend_from_slice(host.as_bytes());
                }
            }
            ResolveMode::Remote => {
                // Send domain name to proxy for remote resolution
                if let Ok(ip) = host.parse::<IpAddr>() {
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
                    if host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    packet.push(0x03); // Domain name
                    packet.push(host.len() as u8);
                    packet.extend_from_slice(host.as_bytes());
                }
            }
        }

        // Port (2 bytes, big endian)
        packet.extend_from_slice(&destination.port().to_be_bytes());

        // Payload
        packet.extend_from_slice(payload);

        Ok(packet)
    }

    /// Decode SOCKS5 UDP packet and extract payload
    /// 解码 SOCKS5 UDP 数据包并提取负载
    fn decode_udp_packet<'a>(&self, packet: &'a [u8]) -> Result<(&'a [u8], TargetAddr)> {
        if packet.len() < 10 {
            return Err(AdapterError::Protocol("UDP packet too short".to_string()));
        }

        // Skip reserved fields (2 bytes) + Fragment (1 byte)
        let mut offset = 3;

        // Parse address type
        let atyp = packet[offset];
        offset += 1;

        let source = match atyp {
            0x01 => {
                if offset + 4 > packet.len() {
                    return Err(AdapterError::Protocol("truncated IPv4 address".to_string()));
                }
                let ip = std::net::Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                );
                offset += 4;
                sb_types::TargetAddr::ip(IpAddr::V4(ip), 0)
            }
            0x04 => {
                if offset + 16 > packet.len() {
                    return Err(AdapterError::Protocol("truncated IPv6 address".to_string()));
                }
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&packet[offset..offset + 16]);
                offset += 16;
                sb_types::TargetAddr::ip(IpAddr::V6(std::net::Ipv6Addr::from(octets)), 0)
            }
            0x03 => {
                // Domain name
                if offset >= packet.len() {
                    return Err(AdapterError::Protocol(
                        "Invalid domain length position".to_string(),
                    ));
                }
                let len = packet[offset] as usize;
                offset += 1;
                if offset + len > packet.len() {
                    return Err(AdapterError::Protocol(
                        "truncated domain address".to_string(),
                    ));
                }
                let domain = std::str::from_utf8(&packet[offset..offset + len])
                    .map_err(|_| AdapterError::Protocol("invalid domain address".to_string()))?
                    .to_string();
                offset += len;
                sb_types::TargetAddr::domain(domain, 0)
            }
            _ => {
                return Err(AdapterError::Protocol(format!(
                    "Invalid address type: {}",
                    atyp
                )))
            }
        };
        if offset + 2 > packet.len() {
            return Err(AdapterError::Protocol(
                "UDP packet header too long".to_string(),
            ));
        }
        let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 2;
        let source = match source {
            TargetAddr::Domain(host, _) => TargetAddr::domain(host, port),
            TargetAddr::Socket(address) => TargetAddr::ip(address.ip(), port),
        };
        Ok((&packet[offset..], source))
    }
}

#[cfg(feature = "socks-udp")]
impl sb_types::PacketConn for SocksUdp {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        destination: &'a TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move {
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(sb_types::CoreError::io("packet connection closed"));
            }
            let packet = self
                .encode_udp_packet(payload, destination)
                .map_err(|error| {
                    crate::outbound::core_error(error, &packet_session(destination))
                })?;
            let sent = crate::outbound::with_packet_deadline(
                Some(self.operation_deadline(false)),
                self.udp.send(&packet),
            )
            .await?;
            if sent == packet.len() {
                Ok(payload.len())
            } else {
                Err(sb_types::CoreError::io("partial SOCKS UDP packet sent"))
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> sb_types::BoxFuture<'a, Result<(usize, TargetAddr), sb_types::CoreError>> {
        Box::pin(async move {
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(sb_types::CoreError::io("packet connection closed"));
            }
            let mut packet_buf = vec![0u8; buffer.len() + 1024];
            let received = crate::outbound::with_packet_deadline(
                Some(self.operation_deadline(true)),
                self.udp.recv(&mut packet_buf),
            )
            .await?;
            let (payload, source) = self
                .decode_udp_packet(&packet_buf[..received])
                .map_err(|error| sb_types::CoreError::protocol(error.to_string()))?;
            let len = payload.len().min(buffer.len());
            buffer[..len].copy_from_slice(&payload[..len]);
            Ok((len, source))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> Option<TargetAddr> {
        self.udp.local_addr().ok().map(TargetAddr::socket)
    }

    fn set_deadline(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        let mut deadlines = self.deadlines.lock();
        deadlines.read = deadline;
        deadlines.write = deadline;
        Ok(())
    }

    fn set_read_deadline(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        self.deadlines.lock().read = deadline;
        Ok(())
    }

    fn set_write_deadline(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        self.deadlines.lock().write = deadline;
        Ok(())
    }
}

#[cfg(feature = "socks-udp")]
fn packet_session(target: &TargetAddr) -> Session {
    Session::new(0, sb_types::InboundTag::new("socks-udp"), target.clone())
}

#[cfg(feature = "adapter-socks")]
impl Socks5Connector {
    /// Perform SOCKS5 initial handshake and authentication
    /// 执行 SOCKS5 初始握手和认证
    async fn socks5_handshake(&self, stream: &mut TcpStream, timeout: Duration) -> Result<()> {
        self.socks5_handshake_generic(stream, timeout).await
    }

    /// Generic SOCKS5 handshake for any AsyncRead + AsyncWrite stream
    /// 适用于任何 AsyncRead + AsyncWrite 流的通用 SOCKS5 握手
    async fn socks5_handshake_generic<S>(&self, stream: &mut S, timeout: Duration) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + ?Sized,
    {
        // Step 1: Send version and authentication methods
        // Prefer offering both "no-auth" and "user/pass" when credentials are present
        // so the server can select the most permissive method it supports.
        // 步骤 1: 发送版本和认证方法
        // 当存在凭据时，最好同时提供 "no-auth" 和 "user/pass"
        // 这样服务端可以选择它支持的最宽松的方法。
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
        // 步骤 2: 读取服务端响应
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
                // 无需认证
                Ok(())
            }
            0x02 => {
                // Username/password authentication required
                // 需要用户名/密码认证
                self.socks5_auth_generic(stream, timeout).await
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
    /// 执行用户名/密码认证
    #[allow(dead_code)]
    async fn socks5_auth(&self, stream: &mut TcpStream, timeout: Duration) -> Result<()> {
        self.socks5_auth_generic(stream, timeout).await
    }

    async fn socks5_auth_generic<S>(&self, stream: &mut S, timeout: Duration) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + ?Sized,
    {
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
        // 构建认证请求
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
        // 读取认证响应
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
    /// 执行 UDP ASSOCIATE 请求并返回中继地址
    #[cfg(feature = "socks-udp")]
    async fn socks5_udp_associate(
        &self,
        stream: &mut TcpStream,
        timeout: Duration,
    ) -> Result<SocketAddr> {
        // Build UDP ASSOCIATE request
        // 构建 UDP ASSOCIATE 请求
        let mut request = vec![0x05, 0x03, 0x00]; // VER, CMD=UDP ASSOCIATE, RSV

        // Use IPv4 0.0.0.0:0 as client address (we don't know our address yet)
        // 使用 IPv4 0.0.0.0:0 作为客户端地址 (我们还不知道我们的地址)
        request.push(0x01); // ATYP=IPv4
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 0.0.0.0
        request.extend_from_slice(&[0x00, 0x00]); // port 0

        // Send request
        // 发送请求
        tokio::time::timeout(timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "UDP associate write timeout",
                ))
            })??;

        // Read response
        // 读取响应
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
        // 从响应中解析中继地址
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
    /// 发送 CONNECT 请求并等待响应
    async fn socks5_connect(
        &self,
        stream: &mut TcpStream,
        target: &TargetAddr,
        opts: &ConnectOptions,
    ) -> Result<()> {
        self.socks5_connect_generic(stream, target, opts).await
    }

    async fn socks5_connect_generic<S>(
        &self,
        stream: &mut S,
        target: &TargetAddr,
        opts: &ConnectOptions,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + ?Sized,
    {
        // Build CONNECT request
        // 构建 CONNECT 请求
        let mut request = vec![0x05, 0x01, 0x00]; // VER, CMD=CONNECT, RSV

        // Add target address based on resolve mode
        // 根据解析模式添加目标地址
        let host = target.host();
        let port = target.port();
        match opts.resolve_mode {
            ResolveMode::Local => {
                // Try to resolve locally first
                // 尝试先本地解析
                if let Ok(ip) = host.parse::<IpAddr>() {
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
                    // 域名 - 本地解析
                    match tokio::net::lookup_host((host.clone(), port)).await {
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
                                    host
                                )));
                            }
                        }
                        Err(e) => {
                            return Err(AdapterError::Network(format!(
                                "DNS resolution failed for {}: {}",
                                host, e
                            )));
                        }
                    }
                }
            }
            ResolveMode::Remote => {
                // Send to proxy for remote resolution
                // 发送到代理进行远程解析
                if let Ok(ip) = host.parse::<IpAddr>() {
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
                    // 域名 - 发送到代理
                    if host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    request.push(0x03); // ATYP=DOMAINNAME
                    request.push(host.len() as u8);
                    request.extend_from_slice(host.as_bytes());
                }
            }
        }

        // Add port
        // 添加端口
        request.extend_from_slice(&port.to_be_bytes());

        // Send request
        // 发送请求
        tokio::time::timeout(opts.connect_timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connect write timeout",
                ))
            })??;

        // Read response
        // 读取响应
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
        // 跳过响应的其余部分 (绑定地址和端口)
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
    /// 执行 BIND 命令并等待指示传入连接的第二个回复
    #[cfg(feature = "socks-bind")]
    async fn socks5_bind(
        &self,
        stream: &mut TcpStream,
        target: &TargetAddr,
        opts: &ConnectOptions,
    ) -> Result<()> {
        use std::time::Duration;
        // Build BIND request
        // 构建 BIND 请求
        let mut request = vec![0x05, 0x02, 0x00]; // VER, CMD=BIND, RSV
                                                  // Address: allow remote resolution or send IP/domain based on ResolveMode
                                                  // 地址: 允许远程解析或根据 ResolveMode 发送 IP/域名
        let host = target.host();
        let port = target.port();
        match opts.resolve_mode {
            ResolveMode::Local => {
                if let Ok(ip) = host.parse::<IpAddr>() {
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
                    // 本地解析
                    let addrs = tokio::time::timeout(
                        opts.connect_timeout,
                        tokio::net::lookup_host((host.as_str(), port)),
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
                        return Err(AdapterError::Network(format!("Failed to resolve {}", host)));
                    }
                }
            }
            ResolveMode::Remote => {
                if let Ok(ip) = host.parse::<IpAddr>() {
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
                    if host.len() > 255 {
                        return Err(AdapterError::InvalidConfig("Domain name too long"));
                    }
                    request.push(0x03);
                    request.push(host.len() as u8);
                    request.extend_from_slice(host.as_bytes());
                }
            }
        }
        request.extend_from_slice(&port.to_be_bytes());

        // Send BIND request
        // 发送 BIND 请求
        tokio::time::timeout(opts.connect_timeout, stream.write_all(&request))
            .await
            .map_err(|_| {
                AdapterError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Bind write timeout",
                ))
            })??;

        // Read first reply (bind address)
        // 读取第一个回复 (绑定地址)
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
        // 跳过第一个回复中的绑定地址
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
        // 等待第二个回复 (传入连接已接受)。使用宽裕的超时 (connect_timeout * 2)
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
            // 跳过地址
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

    #[cfg(feature = "socks-udp")]
    async fn test_socks_udp(idle_timeout: Duration) -> (SocksUdp, tokio::task::JoinHandle<()>) {
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind control listener");
        let control_address = control_listener.local_addr().expect("control address");
        let control_peer = tokio::spawn(async move {
            let (_stream, _) = control_listener.accept().await.expect("accept control");
            std::future::pending::<()>().await;
        });
        let control = TcpStream::connect(control_address)
            .await
            .expect("connect control");

        let relay = UdpSocket::bind("127.0.0.1:0").await.expect("bind relay");
        let relay_address = relay.local_addr().expect("relay address");
        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp client");
        udp.connect(relay_address).await.expect("connect udp relay");

        (
            SocksUdp::new(
                udp,
                relay_address,
                control,
                ResolveMode::Remote,
                idle_timeout,
            )
            .await
            .expect("construct SOCKS packet connection"),
            control_peer,
        )
    }

    #[cfg(feature = "socks-udp")]
    #[tokio::test]
    async fn socks_udp_recv_uses_idle_timeout_by_default() {
        let idle_timeout = Duration::from_millis(10);
        let (socket, control_peer) = test_socks_udp(idle_timeout).await;
        let mut buffer = [0_u8; 64];

        let error = sb_types::PacketConn::recv_from(&socket, &mut buffer)
            .await
            .expect_err("idle receive must time out");
        control_peer.abort();

        match error {
            sb_types::CoreError::Timeout { duration, .. } => {
                assert!(duration <= idle_timeout);
                assert!(!duration.is_zero());
            }
            other => panic!("expected packet timeout, got {other}"),
        }
    }

    #[cfg(feature = "socks-udp")]
    #[tokio::test]
    async fn socks_udp_explicit_read_deadline_overrides_idle_timeout() {
        let idle_timeout = Duration::from_secs(1);
        let explicit_timeout = Duration::from_millis(10);
        let (socket, control_peer) = test_socks_udp(idle_timeout).await;
        sb_types::PacketConn::set_read_deadline(
            &socket,
            Some(std::time::Instant::now() + explicit_timeout),
        )
        .expect("set read deadline");
        let mut buffer = [0_u8; 64];

        let error = sb_types::PacketConn::recv_from(&socket, &mut buffer)
            .await
            .expect_err("explicit receive deadline must time out");
        control_peer.abort();

        match error {
            sb_types::CoreError::Timeout { duration, .. } => {
                assert!(duration <= explicit_timeout);
                assert!(duration < idle_timeout);
                assert!(!duration.is_zero());
            }
            other => panic!("expected packet timeout, got {other}"),
        }
    }
}
