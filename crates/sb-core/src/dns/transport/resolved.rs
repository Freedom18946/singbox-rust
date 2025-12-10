//! DNS transport for systemd-resolved integration.
//!
//! This transport consumes per-link DNS configuration from the Resolve1ManagerState
//! and routes DNS queries to the appropriate servers based on domain matching.
//!
//! Mirrors Go's `service/resolved/transport.go`.

use super::{DnsStartStage, DnsTransport, DnsTransportError};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Configuration for the resolved transport.
#[derive(Debug, Clone)]
pub struct ResolvedTransportConfig {
    /// Number of dots required before name is considered absolute.
    pub ndots: usize,
    /// Whether to rotate servers.
    pub rotate: bool,
    /// Number of attempts per server.
    pub attempts: usize,
    /// Query timeout.
    pub timeout: Duration,
    /// Accept default resolvers when no domain matches.
    pub accept_default_resolvers: bool,
}

impl Default for ResolvedTransportConfig {
    fn default() -> Self {
        Self {
            ndots: 1,
            rotate: false,
            attempts: 2,
            timeout: Duration::from_secs(5),
            accept_default_resolvers: true,
        }
    }
}

/// Simple representation of a DNS server for transport.
#[derive(Debug, Clone)]
pub struct DnsServer {
    /// Server address.
    pub addr: IpAddr,
    /// Server port (0 = default 53 or 853 for DoT).
    pub port: u16,
    /// Server name for TLS (SNI).
    pub server_name: Option<String>,
    /// Whether to use DNS-over-TLS.
    pub use_dot: bool,
}

impl DnsServer {
    /// Get the effective port (default 53 for UDP, 853 for DoT).
    pub fn effective_port(&self) -> u16 {
        if self.port != 0 {
            self.port
        } else if self.use_dot {
            853
        } else {
            53
        }
    }
}

/// Per-link DNS servers and configuration.
#[derive(Debug, Default)]
pub struct LinkServers {
    /// Interface index.
    pub if_index: i32,
    /// Interface name.
    pub if_name: String,
    /// DNS servers for this link.
    pub servers: Vec<DnsServer>,
    /// Search domains.
    pub domains: Vec<LinkDomain>,
    /// Whether this is a default route.
    pub default_route: bool,
    /// Server offset for rotation.
    offset: AtomicU32,
}

/// Domain configuration.
#[derive(Debug, Clone)]
pub struct LinkDomain {
    /// Domain name (with trailing dot).
    pub domain: String,
    /// If true, only used for routing, not search.
    pub routing_only: bool,
}

impl LinkServers {
    /// Get server offset for rotation.
    pub fn server_offset(&self, rotate: bool) -> usize {
        if rotate {
            self.offset.fetch_add(1, Ordering::Relaxed) as usize
        } else {
            0
        }
    }

    /// Generate name list with search domains (ndots semantics).
    ///
    /// Mirrors Go's `TransportLink.nameList`.
    pub fn name_list(&self, ndots: usize, name: &str) -> Vec<String> {
        // Filter search domains (exclude routing-only)
        let search: Vec<&str> = self
            .domains
            .iter()
            .filter(|d| !d.routing_only)
            .map(|d| d.domain.as_str())
            .collect();

        let name_len = name.len();
        if name_len == 0 {
            return vec![];
        }

        let rooted = name.ends_with('.');
        if name_len > 254 || (name_len == 254 && !rooted) {
            return vec![];
        }

        // Check if name is rooted (FQDN)
        if rooted {
            if avoid_dns(name) {
                return vec![];
            }
            return vec![name.to_string()];
        }

        // Add trailing dot
        let name_fqdn = format!("{}.", name);

        let has_ndots = name.matches('.').count() >= ndots;
        let mut names = Vec::with_capacity(1 + search.len());

        // If has enough dots, try as-is first
        if has_ndots && !avoid_dns(&name_fqdn) {
            names.push(name_fqdn.clone());
        }

        // Try with search domains
        for suffix in &search {
            let fqdn = format!("{}{}", name_fqdn, suffix);
            if !avoid_dns(&fqdn) && fqdn.len() <= 254 {
                names.push(fqdn);
            }
        }

        // If not enough dots, try as-is last
        if !has_ndots && !avoid_dns(&name_fqdn) {
            names.push(name_fqdn);
        }

        names
    }
}

/// Check if DNS lookup should be avoided (e.g., .onion).
fn avoid_dns(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let name = name.trim_end_matches('.');
    name.ends_with(".onion") || name == "onion"
}

/// Resolved DNS transport.
///
/// Routes DNS queries to per-link servers based on domain matching.
pub struct ResolvedTransport {
    /// Transport name.
    name: String,
    /// Configuration.
    config: ResolvedTransportConfig,
    /// Per-link servers (if_index -> LinkServers).
    link_servers: RwLock<HashMap<i32, Arc<LinkServers>>>,
    /// Default route sequence (most recent last).
    default_route_sequence: RwLock<Vec<i32>>,
    /// Started flag.
    started: std::sync::atomic::AtomicBool,
}

impl ResolvedTransport {
    /// Create a new resolved transport.
    pub fn new(name: impl Into<String>, config: ResolvedTransportConfig) -> Self {
        Self {
            name: name.into(),
            config,
            link_servers: RwLock::new(HashMap::new()),
            default_route_sequence: RwLock::new(Vec::new()),
            started: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Update servers for a link.
    pub fn update_link(&self, link: LinkServers) {
        let if_index = link.if_index;
        let is_default = link.default_route;

        {
            let mut servers = self.link_servers.write();
            servers.insert(if_index, Arc::new(link));
        }

        // Update default route sequence
        {
            let mut seq = self.default_route_sequence.write();
            seq.retain(|&idx| idx != if_index);
            if is_default {
                seq.push(if_index);
            }
        }

        debug!(if_index, "Updated link DNS servers");
    }

    /// Delete a link.
    pub fn delete_link(&self, if_index: i32) {
        {
            let mut servers = self.link_servers.write();
            servers.remove(&if_index);
        }
        {
            let mut seq = self.default_route_sequence.write();
            seq.retain(|&idx| idx != if_index);
        }
        debug!(if_index, "Deleted link DNS servers");
    }

    /// Select link for a query based on domain matching.
    fn select_link(&self, qname: &str) -> Option<Arc<LinkServers>> {
        let servers = self.link_servers.read();

        // Try domain matching first
        for link in servers.values() {
            for domain in &link.domains {
                // Skip routing-only "." if not accepting default resolvers
                if domain.domain == "."
                    && domain.routing_only
                    && !self.config.accept_default_resolvers
                {
                    continue;
                }
                // Check if query name matches domain suffix
                if qname.ends_with(&domain.domain) || domain.domain == "." {
                    return Some(link.clone());
                }
            }
        }

        // Fall back to default route if accepting default resolvers
        if self.config.accept_default_resolvers {
            let seq = self.default_route_sequence.read();
            for &if_index in seq.iter().rev() {
                if let Some(link) = servers.get(&if_index) {
                    if !link.servers.is_empty() {
                        return Some(link.clone());
                    }
                }
            }
        }

        None
    }

    /// Exchange DNS query with a single server.
    async fn exchange_with_server(&self, server: &DnsServer, packet: &[u8]) -> Result<Vec<u8>> {
        let addr = std::net::SocketAddr::new(server.addr, server.effective_port());

        if server.use_dot {
            // DNS-over-TLS exchange
            self.exchange_dot(addr, &server.server_name, packet).await
        } else {
            // UDP exchange
            self.exchange_udp(addr, packet).await
        }
    }

    /// Exchange via UDP.
    async fn exchange_udp(&self, addr: std::net::SocketAddr, packet: &[u8]) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(addr).await?;
        socket.send(packet).await?;

        let mut buf = vec![0u8; 4096];
        let timeout = tokio::time::timeout(self.config.timeout, socket.recv(&mut buf)).await;

        match timeout {
            Ok(Ok(len)) => {
                buf.truncate(len);
                Ok(buf)
            }
            Ok(Err(e)) => Err(anyhow!("UDP recv error: {}", e)),
            Err(_) => Err(anyhow!("UDP timeout")),
        }
    }

    /// Exchange via DNS-over-TLS (simplified - delegates to DoT transport).
    async fn exchange_dot(
        &self,
        addr: std::net::SocketAddr,
        server_name: &Option<String>,
        packet: &[u8],
    ) -> Result<Vec<u8>> {
        #[cfg(feature = "dns_dot")]
        {
            use super::dot::DotTransport;

            let sni = server_name.clone().unwrap_or_else(|| addr.ip().to_string());

            let dot = DotTransport::new(addr, sni)?;
            dot.query(packet).await
        }

        #[cfg(not(feature = "dns_dot"))]
        {
            let _ = (addr, server_name, packet);
            Err(anyhow!("DNS-over-TLS requires the dns_dot feature"))
        }
    }

    /// Try query with one FQDN across all servers.
    async fn try_one_name(
        &self,
        servers: &LinkServers,
        original_packet: &[u8],
        fqdn: &str,
    ) -> Result<Vec<u8>> {
        if servers.servers.is_empty() {
            return Err(anyhow!("No servers available"));
        }

        let server_count = servers.servers.len();
        let offset = servers.server_offset(self.config.rotate);
        let mut last_err = None;

        // Rewrite query name if different from original
        let packet = if fqdn != extract_qname(original_packet).unwrap_or_default() {
            rewrite_qname(original_packet, fqdn)?
        } else {
            original_packet.to_vec()
        };

        for attempt in 0..self.config.attempts {
            for j in 0..server_count {
                let server = &servers.servers[(offset + j) % server_count];

                debug!(
                    attempt,
                    server_idx = (offset + j) % server_count,
                    server_addr = %server.addr,
                    fqdn,
                    "Trying DNS server"
                );

                match self.exchange_with_server(server, &packet).await {
                    Ok(response) => return Ok(response),
                    Err(e) => {
                        debug!(error = %e, "DNS query failed");
                        last_err = Some(e);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("No servers available")))
    }

    /// Exchange with parallel queries (for A/AAAA).
    ///
    /// Note: Due to Rust lifetime constraints with async spawning,
    /// this currently uses sequential execution. A fully parallel
    /// implementation would require Arc<Self> or similar refactoring.
    async fn exchange_parallel(&self, servers: &LinkServers, packet: &[u8]) -> Result<Vec<u8>> {
        // For now, use sequential execution (parallel optimization TODO)
        // The Go implementation uses goroutines which don't have the same
        // lifetime constraints as Rust's async tasks.
        self.exchange_sequential(servers, packet).await
    }

    /// Exchange with sequential queries.
    async fn exchange_sequential(&self, servers: &LinkServers, packet: &[u8]) -> Result<Vec<u8>> {
        let qname = extract_qname(packet).unwrap_or_default();
        let names = servers.name_list(self.config.ndots, &qname);

        if names.is_empty() {
            return Err(anyhow!("No valid names to query"));
        }

        let mut last_err = None;
        for fqdn in &names {
            match self.try_one_name(servers, packet, fqdn).await {
                Ok(response) => return Ok(response),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("No valid names to query")))
    }
}

#[async_trait]
impl DnsTransport for ResolvedTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if !self.started.load(Ordering::Relaxed) {
            return Err(anyhow!("Transport not started"));
        }

        // Extract query name and type
        let qname = extract_qname(packet).unwrap_or_default();
        let qtype = extract_qtype(packet);

        // Select link based on domain
        let link = match self.select_link(&qname) {
            Some(l) => l,
            None => {
                debug!(qname, "No matching link for query");
                // Return NXDOMAIN
                return Ok(create_nxdomain_response(packet));
            }
        };

        debug!(
            qname,
            if_index = link.if_index,
            if_name = %link.if_name,
            "Selected link for query"
        );

        // Use parallel for A/AAAA, sequential for others
        if qtype == 1 || qtype == 28 {
            // A = 1, AAAA = 28
            self.exchange_parallel(&link, packet).await
        } else {
            self.exchange_sequential(&link, packet).await
        }
    }

    fn name(&self) -> &'static str {
        // Leak the name for 'static lifetime (transport is long-lived)
        Box::leak(self.name.clone().into_boxed_str())
    }

    async fn start(&self, stage: DnsStartStage) -> Result<()> {
        match stage {
            DnsStartStage::Start => {
                self.started.store(true, Ordering::Relaxed);
                info!(name = %self.name, "Resolved DNS transport started");
            }
            _ => {}
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.started.store(false, Ordering::Relaxed);
        self.link_servers.write().clear();
        self.default_route_sequence.write().clear();
        info!(name = %self.name, "Resolved DNS transport closed");
        Ok(())
    }
}

// Helper functions for DNS packet manipulation

/// Extract query name from DNS packet.
fn extract_qname(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }

    let mut pos = 12; // Skip header
    let mut name = String::new();

    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            break;
        }
        if len > 63 {
            // Compression pointer - not supported for now
            return None;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(&packet[pos..pos + len]).ok()?);
        pos += len;
    }

    if !name.is_empty() && !name.ends_with('.') {
        name.push('.');
    }

    Some(name)
}

/// Extract query type from DNS packet.
fn extract_qtype(packet: &[u8]) -> u16 {
    if packet.len() < 12 {
        return 0;
    }

    let mut pos = 12;
    // Skip QNAME
    loop {
        if pos >= packet.len() {
            return 0;
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len > 63 {
            return 0;
        }
        pos += 1 + len;
    }

    if pos + 2 > packet.len() {
        return 0;
    }

    u16::from_be_bytes([packet[pos], packet[pos + 1]])
}

/// Rewrite query name in DNS packet.
fn rewrite_qname(packet: &[u8], new_name: &str) -> Result<Vec<u8>> {
    if packet.len() < 12 {
        return Err(anyhow!("Packet too short"));
    }

    // Find end of original QNAME
    let mut pos = 12;
    loop {
        if pos >= packet.len() {
            return Err(anyhow!("Invalid packet"));
        }
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len > 63 {
            return Err(anyhow!("Compression not supported"));
        }
        pos += 1 + len;
    }

    // Build new packet
    let mut new_packet = Vec::with_capacity(packet.len() + 64);

    // Copy header
    new_packet.extend_from_slice(&packet[0..12]);

    // Encode new name
    let name = new_name.trim_end_matches('.');
    for label in name.split('.') {
        if label.len() > 63 {
            return Err(anyhow!("Label too long"));
        }
        new_packet.push(label.len() as u8);
        new_packet.extend_from_slice(label.as_bytes());
    }
    new_packet.push(0); // Root label

    // Copy rest of packet (QTYPE, QCLASS, and any additional sections)
    new_packet.extend_from_slice(&packet[pos..]);

    Ok(new_packet)
}

/// Create NXDOMAIN response for a query.
fn create_nxdomain_response(query: &[u8]) -> Vec<u8> {
    if query.len() < 12 {
        return vec![];
    }

    let mut response = query.to_vec();

    // Set QR bit (response) and RCODE = 3 (NXDOMAIN)
    response[2] = (response[2] & 0x7F) | 0x80; // QR = 1
    response[3] = (response[3] & 0xF0) | 0x03; // RCODE = 3

    // Set answer/authority/additional counts to 0
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_list_basic() {
        let servers = LinkServers {
            if_index: 1,
            if_name: "eth0".to_string(),
            servers: vec![],
            domains: vec![LinkDomain {
                domain: "example.com.".to_string(),
                routing_only: false,
            }],
            default_route: false,
            ..Default::default()
        };

        let names = servers.name_list(1, "www");
        assert!(names.contains(&"www.example.com.".to_string()));
        assert!(names.contains(&"www.".to_string()));
    }

    #[test]
    fn test_name_list_fqdn() {
        let servers = LinkServers::default();
        let names = servers.name_list(1, "example.com.");
        assert_eq!(names, vec!["example.com.".to_string()]);
    }

    #[test]
    fn test_avoid_dns_onion() {
        assert!(avoid_dns("test.onion"));
        assert!(avoid_dns("test.onion."));
        assert!(!avoid_dns("test.onionx"));
        assert!(!avoid_dns("example.com"));
    }

    #[test]
    fn test_extract_qname() {
        // Simple DNS query for "example.com"
        let packet = [
            0x00, 0x01, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // QNAME: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // Root
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        let qname = extract_qname(&packet);
        assert_eq!(qname, Some("example.com.".to_string()));
    }

    #[test]
    fn test_extract_qtype() {
        let packet = [
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE = A
            0x00, 0x01,
        ];
        assert_eq!(extract_qtype(&packet), 1);
    }

    #[test]
    fn test_dns_server_effective_port() {
        let server = DnsServer {
            addr: "8.8.8.8".parse().unwrap(),
            port: 0,
            server_name: None,
            use_dot: false,
        };
        assert_eq!(server.effective_port(), 53);

        let dot_server = DnsServer {
            addr: "8.8.8.8".parse().unwrap(),
            port: 0,
            server_name: None,
            use_dot: true,
        };
        assert_eq!(dot_server.effective_port(), 853);
    }
}
