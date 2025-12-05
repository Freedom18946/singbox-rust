//! DNS inbound adapter: provides local DNS server functionality.
//!
//! This adapter listens on a local address (UDP and optionally TCP) and
//! forwards DNS queries to the configured DNS resolver.
//!
//! Reference: Go sing-box `protocol/dns/`

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use sb_core::adapter::InboundService;
use sb_core::dns::ResolverHandle;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// DNS inbound adapter that provides local DNS server functionality.
#[derive(Debug)]
pub struct DnsInboundAdapter {
    /// Listen address for DNS server
    listen: SocketAddr,
    /// Enable TCP DNS server (in addition to UDP)
    tcp_enabled: bool,
    /// DNS resolver handle for query resolution (uses configurable upstream)
    resolver: Arc<ResolverHandle>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Shutdown notification
    shutdown_notify: Arc<Notify>,
    /// Active connection counter
    active_queries: Arc<AtomicU64>,
}

/// DNS inbound configuration parameters
#[derive(Debug, Clone)]
pub struct DnsInboundConfig {
    /// Listen address (e.g., "127.0.0.1")
    pub listen: String,
    /// Listen port (typically 53)
    pub port: u16,
    /// Enable TCP DNS server
    pub tcp_enabled: bool,
    /// Optional custom resolver (uses env-based default if None)
    pub resolver: Option<Arc<ResolverHandle>>,
}

impl DnsInboundAdapter {
    /// Create a new DNS inbound adapter from configuration.
    ///
    /// # Arguments
    /// * `config` - DNS inbound configuration
    ///
    /// # Returns
    /// A Result containing the adapter or an error
    pub fn new(config: DnsInboundConfig) -> std::io::Result<Self> {
        let listen_str = format!("{}:{}", config.listen, config.port);
        let listen: SocketAddr = listen_str.parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid listen address '{}': {}", listen_str, e),
            )
        })?;

        // Use provided resolver or create env-based default
        let resolver = config
            .resolver
            .unwrap_or_else(|| Arc::new(ResolverHandle::from_env_or_default()));

        Ok(Self {
            listen,
            tcp_enabled: config.tcp_enabled,
            resolver,
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            active_queries: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create a new DNS inbound adapter from InboundParam.
    ///
    /// # Arguments
    /// * `param` - Inbound parameters containing listen address and port
    ///
    /// # Returns
    /// A boxed InboundService or an error if parameters are invalid
    pub fn create(
        param: &sb_core::adapter::InboundParam,
    ) -> std::io::Result<Box<dyn InboundService>> {
        let config = DnsInboundConfig {
            listen: param.listen.clone(),
            port: param.port,
            tcp_enabled: param
                .network
                .as_ref()
                .map(|n| n.to_lowercase().contains("tcp"))
                .unwrap_or(true), // Default: enable both UDP and TCP
            resolver: None, // Use env-based default
        };

        let adapter = Self::new(config)?;
        Ok(Box::new(adapter))
    }

    /// Create with a specific resolver handle
    pub fn with_resolver(mut self, resolver: Arc<ResolverHandle>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Run the UDP DNS server loop
    async fn run_udp_server(&self) -> std::io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(self.listen).await?);
        info!(addr = ?self.listen, "DNS UDP server listening");

        let mut buf = vec![0u8; 4096]; // DNS messages are typically < 512 bytes, but EDNS can be larger

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("DNS UDP server shutting down");
                break;
            }

            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src)) => {
                            self.active_queries.fetch_add(1, Ordering::Relaxed);
                            let query = buf[..len].to_vec();
                            let socket_ref = socket.clone();
                            let active_queries = self.active_queries.clone();
                            let resolver = self.resolver.clone();

                            // Spawn task with resolver
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_udp_query(&socket_ref, src, &query, resolver).await {
                                    debug!(error = %e, src = %src, "DNS query handling failed");
                                }
                                active_queries.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            if !self.shutdown.load(Ordering::Relaxed) {
                                warn!(error = %e, "DNS UDP recv error");
                            }
                        }
                    }
                }
                _ = self.shutdown_notify.notified() => {
                    info!("DNS UDP server received shutdown signal");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single UDP DNS query
    async fn handle_udp_query(
        socket: &Arc<UdpSocket>,
        src: SocketAddr,
        query: &[u8],
        resolver: Arc<ResolverHandle>,
    ) -> std::io::Result<()> {
        // Forward to DNS resolver and get response
        match Self::resolve_query(query, &resolver).await {
            Ok(response) => {
                socket.send_to(&response, src).await?;
                debug!(src = %src, query_len = query.len(), response_len = response.len(), "DNS query handled");
            }
            Err(e) => {
                // Send SERVFAIL response
                if let Some(response) = Self::create_servfail_response(query) {
                    let _ = socket.send_to(&response, src).await;
                }
                debug!(src = %src, error = %e, "DNS query resolution failed");
            }
        }
        Ok(())
    }

    /// Resolve DNS query using ResolverHandle (configurable upstream)
    async fn resolve_query(
        query: &[u8],
        resolver: &ResolverHandle,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Parse the DNS query to extract domain and type
        if query.len() < 12 {
            return Err("DNS query too short".into());
        }

        // Parse query to get domain and qtype
        let (domain, qtype) = Self::parse_query(query)?;

        // Only support A (1) and AAAA (28) records
        if qtype != 1 && qtype != 28 {
            return Self::build_response(query, &[], qtype);
        }

        // Use ResolverHandle for DNS resolution
        let mut ips = Vec::new();
        match resolver.resolve(&domain).await {
            Ok(answer) => {
                for ip in answer.ips {
                    match (qtype, ip) {
                        (1, std::net::IpAddr::V4(_)) => ips.push(ip),
                        (28, std::net::IpAddr::V6(_)) => ips.push(ip),
                        _ => {}
                    }
                }
            }
            Err(e) => {
                debug!(domain = %domain, error = %e, "DNS resolution failed");
                // Return empty response on error, SERVFAIL will be handled by caller
            }
        }

        Self::build_response(query, &ips, qtype)
    }

    /// Parse DNS query packet to extract domain name and query type
    fn parse_query(
        packet: &[u8],
    ) -> Result<(String, u16), Box<dyn std::error::Error + Send + Sync>> {
        if packet.len() < 12 {
            return Err("Packet too short".into());
        }

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        if qdcount != 1 {
            return Err("Only single question supported".into());
        }

        let mut offset = 12;
        let mut domain = String::new();

        loop {
            if offset >= packet.len() {
                return Err("Unexpected end of packet".into());
            }
            let len = packet[offset] as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            if offset + len > packet.len() {
                return Err("Label too long".into());
            }
            let label = std::str::from_utf8(&packet[offset..offset + len])
                .map_err(|_| "Invalid UTF-8 in domain label")?;
            domain.push_str(label);
            offset += len;
        }

        if offset + 4 > packet.len() {
            return Err("Packet too short for QTYPE/QCLASS".into());
        }

        let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        Ok((domain, qtype))
    }

    /// Build DNS response packet
    fn build_response(
        query: &[u8],
        ips: &[std::net::IpAddr],
        _qtype: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if query.len() < 12 {
            return Err("Query packet too short".into());
        }

        let id = &query[0..2];
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(id); // Transaction ID
                                        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
        response.extend_from_slice(&[0x81, 0x80]);

        // Copy question count from query
        response.extend_from_slice(&query[4..6]); // QDCOUNT

        // Answer count
        let answer_count = ips.len() as u16;
        response.extend_from_slice(&answer_count.to_be_bytes()); // ANCOUNT
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Find end of question section to copy it
        let mut offset = 12;
        while offset < query.len() {
            let len = query[offset] as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            offset += len;
        }
        offset += 4; // QTYPE + QCLASS

        if offset > query.len() {
            return Err("Invalid query packet".into());
        }

        // Copy question section
        response.extend_from_slice(&query[12..offset]);

        // Build answer records using pointer to QNAME (0xC00C = pointer to offset 12)
        let name_ptr = 0xC00Cu16.to_be_bytes();

        for ip in ips {
            response.extend_from_slice(&name_ptr);

            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    response.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    response.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                    response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
                    response.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    response.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA
                    response.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    response.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                    response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH 16
                    response.extend_from_slice(&ipv6.octets());
                }
            }
        }

        Ok(response)
    }
    fn create_servfail_response(query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }

        let mut response = Vec::with_capacity(query.len());
        response.extend_from_slice(query);

        // Set response flags: QR=1 (response), RCODE=2 (SERVFAIL)
        if response.len() >= 4 {
            response[2] = 0x81; // QR=1, Opcode=0, AA=0, TC=0, RD=1
            response[3] = 0x82; // RA=1, Z=0, RCODE=2 (SERVFAIL)
        }

        Some(response)
    }

    /// Run the TCP DNS server loop (RFC 1035: 2-byte length prefix)
    async fn run_tcp_server(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.listen).await?;
        info!(addr = ?self.listen, "DNS TCP server listening");

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                info!("DNS TCP server shutting down");
                break;
            }

            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((mut stream, peer_addr)) => {
                            self.active_queries.fetch_add(1, Ordering::Relaxed);
                            let active_queries = self.active_queries.clone();
                            let resolver = self.resolver.clone();

                            tokio::spawn(async move {
                                // Read 2-byte length prefix
                                let mut len_buf = [0u8; 2];
                                if stream.read_exact(&mut len_buf).await.is_err() {
                                    active_queries.fetch_sub(1, Ordering::Relaxed);
                                    return;
                                }
                                let msg_len = u16::from_be_bytes(len_buf) as usize;

                                // Read DNS message
                                let mut query = vec![0u8; msg_len];
                                if stream.read_exact(&mut query).await.is_err() {
                                    active_queries.fetch_sub(1, Ordering::Relaxed);
                                    return;
                                }

                                // Resolve and send response
                                match Self::resolve_query(&query, &resolver).await {
                                    Ok(response) => {
                                        let resp_len = (response.len() as u16).to_be_bytes();
                                        let _ = stream.write_all(&resp_len).await;
                                        let _ = stream.write_all(&response).await;
                                        debug!(peer = %peer_addr, "DNS TCP query handled");
                                    }
                                    Err(_) => {
                                        if let Some(response) = Self::create_servfail_response(&query) {
                                            let resp_len = (response.len() as u16).to_be_bytes();
                                            let _ = stream.write_all(&resp_len).await;
                                            let _ = stream.write_all(&response).await;
                                        }
                                    }
                                }
                                active_queries.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            if !self.shutdown.load(Ordering::Relaxed) {
                                warn!(error = %e, "DNS TCP accept error");
                            }
                        }
                    }
                }
                _ = self.shutdown_notify.notified() => {
                    info!("DNS TCP server received shutdown signal");
                    break;
                }
            }
        }

        Ok(())
    }
}

impl InboundService for DnsInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        // Run in a blocking context to match the sync interface
        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map(|rt| rt.handle().clone())
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let listen = self.listen;
        let shutdown = self.shutdown.clone();
        let shutdown_notify = self.shutdown_notify.clone();
        let active_queries = self.active_queries.clone();
        let tcp_enabled = self.tcp_enabled;
        let resolver = self.resolver.clone();

        rt.block_on(async move {
            info!(addr = ?listen, tcp = tcp_enabled, "DNS inbound starting");

            let adapter = DnsInboundAdapter {
                listen,
                tcp_enabled,
                resolver: resolver.clone(),
                shutdown: shutdown.clone(),
                shutdown_notify: shutdown_notify.clone(),
                active_queries,
            };

            // Run UDP server (always)
            let udp_handle = tokio::spawn({
                let adapter_clone = DnsInboundAdapter {
                    listen,
                    tcp_enabled,
                    resolver: resolver.clone(),
                    shutdown: shutdown.clone(),
                    shutdown_notify: shutdown_notify.clone(),
                    active_queries: adapter.active_queries.clone(),
                };
                async move { adapter_clone.run_udp_server().await }
            });

            // Run TCP server if enabled
            if tcp_enabled {
                let tcp_handle = tokio::spawn(async move { adapter.run_tcp_server().await });
                let _ = tokio::try_join!(udp_handle, tcp_handle);
            } else {
                let _ = udp_handle.await;
            }

            Ok(())
        })
    }

    fn request_shutdown(&self) {
        info!("DNS inbound shutdown requested");
        self.shutdown.store(true, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active_queries.load(Ordering::Relaxed))
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        Some(self.active_queries.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_inbound_config() {
        let config = DnsInboundConfig {
            listen: "127.0.0.1".to_string(),
            port: 5353,
            tcp_enabled: true,
        };

        let adapter = DnsInboundAdapter::new(config).unwrap();
        assert_eq!(adapter.listen.port(), 5353);
    }

    #[test]
    fn test_servfail_response() {
        // Minimal DNS query header
        let query = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        let response = DnsInboundAdapter::create_servfail_response(&query);
        assert!(response.is_some());

        let resp = response.unwrap();
        assert_eq!(resp[0], 0x12); // Transaction ID preserved
        assert_eq!(resp[1], 0x34);
        assert_eq!(resp[2] & 0x80, 0x80); // QR bit set (response)
        assert_eq!(resp[3] & 0x0F, 0x02); // RCODE = SERVFAIL
    }
}
