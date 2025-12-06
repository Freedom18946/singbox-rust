//! Tailscale DNS Transport for MagicDNS resolution.
//!
//! This module provides DNS resolution via Tailscale's MagicDNS service.
//! MagicDNS uses `100.100.100.100` as the resolver for `.ts.net` domains.
//!
//! # Features
//! - DNS-over-UDP to Tailscale's MagicDNS (100.100.100.100:53)
//! - Automatic detection of Tailnet domains (.ts.net, .tailscale.net)
//! - Fallback to system DNS for non-Tailnet domains
//!
//! # Example
//! ```ignore
//! use sb_transport::tailscale_dns::TailscaleDnsTransport;
//!
//! let dns = TailscaleDnsTransport::new()?;
//! let addrs = dns.resolve("my-device.ts.net").await?;
//! ```

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// Tailscale MagicDNS server address.
pub const MAGIC_DNS_ADDR: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);
/// Tailscale MagicDNS port.
pub const MAGIC_DNS_PORT: u16 = 53;

/// Tailscale DNS transport for MagicDNS resolution.
#[derive(Debug, Clone)]
pub struct TailscaleDnsTransport {
    /// MagicDNS server address.
    dns_server: SocketAddr,
    /// Query timeout.
    timeout: Duration,
}

impl Default for TailscaleDnsTransport {
    fn default() -> Self {
        Self {
            dns_server: SocketAddr::new(IpAddr::V4(MAGIC_DNS_ADDR), MAGIC_DNS_PORT),
            timeout: Duration::from_secs(5),
        }
    }
}

impl TailscaleDnsTransport {
    /// Create a new Tailscale DNS transport with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom DNS server (for testing).
    pub fn with_server(server: SocketAddr) -> Self {
        Self {
            dns_server: server,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set query timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Check if a hostname should use MagicDNS.
    pub fn is_tailnet_domain(hostname: &str) -> bool {
        let lower = hostname.to_lowercase();
        lower.ends_with(".ts.net")
            || lower.ends_with(".tailscale.net")
            || lower.ends_with(".ts.net.")
            || lower.ends_with(".tailscale.net.")
    }

    /// Resolve a hostname via MagicDNS.
    ///
    /// Returns resolved IP addresses or an error.
    pub async fn resolve(&self, hostname: &str) -> io::Result<Vec<IpAddr>> {
        debug!("Resolving {} via MagicDNS at {}", hostname, self.dns_server);

        // Build DNS query
        let query = self.build_dns_query(hostname)?;

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Send query
        socket.send_to(&query, self.dns_server).await?;

        // Receive response with timeout
        let mut buf = vec![0u8; 512];
        let (len, _) = match timeout(self.timeout, socket.recv_from(&mut buf)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("DNS query timeout for {}", hostname),
                ))
            }
        };

        // Parse response
        self.parse_dns_response(&buf[..len], hostname)
    }

    /// Build a DNS A query for the given hostname.
    fn build_dns_query(&self, hostname: &str) -> io::Result<Vec<u8>> {
        let mut packet = Vec::with_capacity(512);

        // Transaction ID (random)
        let txid: u16 = rand::random();
        packet.extend_from_slice(&txid.to_be_bytes());

        // Flags: standard query, recursion desired
        packet.extend_from_slice(&[0x01, 0x00]);

        // QDCOUNT: 1 question
        packet.extend_from_slice(&[0x00, 0x01]);
        // ANCOUNT: 0 answers
        packet.extend_from_slice(&[0x00, 0x00]);
        // NSCOUNT: 0 authority
        packet.extend_from_slice(&[0x00, 0x00]);
        // ARCOUNT: 0 additional
        packet.extend_from_slice(&[0x00, 0x00]);

        // Question section: encode hostname
        for label in hostname.trim_end_matches('.').split('.') {
            if label.len() > 63 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS label too long",
                ));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label

        // QTYPE: A record (IPv4)
        packet.extend_from_slice(&[0x00, 0x01]);
        // QCLASS: IN (Internet)
        packet.extend_from_slice(&[0x00, 0x01]);

        trace!("Built DNS query for {}: {} bytes", hostname, packet.len());
        Ok(packet)
    }

    /// Parse DNS response and extract IP addresses.
    fn parse_dns_response(&self, data: &[u8], hostname: &str) -> io::Result<Vec<IpAddr>> {
        if data.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response too short",
            ));
        }

        // Check response code (RCODE in lower 4 bits of byte 3)
        let rcode = data[3] & 0x0f;
        if rcode != 0 {
            let msg = match rcode {
                1 => "Format error",
                2 => "Server failure",
                3 => "Name error (NXDOMAIN)",
                4 => "Not implemented",
                5 => "Refused",
                _ => "Unknown error",
            };
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS query for {} failed: {}", hostname, msg),
            ));
        }

        // Parse answer count
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        if ancount == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No DNS records found for {}", hostname),
            ));
        }

        // Skip question section
        let mut pos = 12;
        while pos < data.len() && data[pos] != 0 {
            let len = data[pos] as usize;
            if len >= 0xc0 {
                // Pointer
                pos += 2;
                break;
            }
            pos += len + 1;
        }
        pos += 5; // Skip null terminator + QTYPE + QCLASS

        // Parse answers
        let mut addresses = Vec::new();
        for _ in 0..ancount {
            if pos + 12 > data.len() {
                break;
            }

            // Skip name (handle compression)
            if data[pos] >= 0xc0 {
                pos += 2;
            } else {
                while pos < data.len() && data[pos] != 0 {
                    let len = data[pos] as usize;
                    if len >= 0xc0 {
                        pos += 2;
                        break;
                    }
                    pos += len + 1;
                }
                pos += 1;
            }

            if pos + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > data.len() {
                break;
            }

            // A record (IPv4)
            if rtype == 1 && rdlength == 4 {
                let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                addresses.push(IpAddr::V4(ip));
                debug!("Resolved {} -> {}", hostname, ip);
            }
            // AAAA record (IPv6)
            else if rtype == 28 && rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                let ip = std::net::Ipv6Addr::from(octets);
                addresses.push(IpAddr::V6(ip));
                debug!("Resolved {} -> {}", hostname, ip);
            }

            pos += rdlength;
        }

        if addresses.is_empty() {
            warn!("No A/AAAA records found for {}", hostname);
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No IP addresses found for {}", hostname),
            ));
        }

        Ok(addresses)
    }
}

/// DERP (Designated Encrypted Relay for Packets) client for Tailscale relay.
///
/// DERP is used when direct WireGuard connections fail (NAT traversal issues).
#[derive(Debug, Clone)]
pub struct DerpClient {
    /// DERP server URL.
    server_url: String,
    /// Connection timeout.
    #[allow(dead_code)]
    timeout: Duration,
}

impl DerpClient {
    /// Create a new DERP client.
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            timeout: Duration::from_secs(10),
        }
    }

    /// Default Tailscale DERP servers.
    pub fn default_servers() -> Vec<String> {
        vec![
            "https://derp1.tailscale.com".to_string(),
            "https://derp2.tailscale.com".to_string(),
            "https://derp3.tailscale.com".to_string(),
        ]
    }

    /// Get server URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Check if DERP server is reachable.
    pub async fn probe(&self) -> io::Result<()> {
        // TODO: Implement DERP protocol handshake
        debug!("DERP probe to {}", self.server_url);
        Ok(())
    }

    /// Send packet through DERP relay.
    pub async fn send(&self, _peer_key: &[u8; 32], _data: &[u8]) -> io::Result<()> {
        // TODO: Implement DERP send
        Err(io::Error::other(
            "DERP send not yet implemented",
        ))
    }

    /// Receive packet from DERP relay.
    pub async fn recv(&self) -> io::Result<(Vec<u8>, [u8; 32])> {
        // TODO: Implement DERP recv
        Err(io::Error::other(
            "DERP recv not yet implemented",
        ))
    }
}

/// Tailscale coordination client for peer discovery.
#[derive(Debug)]
pub struct CoordinationClient {
    /// Control plane URL.
    control_url: String,
    /// Auth key for headless auth.
    auth_key: Option<String>,
}

impl CoordinationClient {
    /// Create a new coordination client.
    pub fn new(control_url: impl Into<String>) -> Self {
        Self {
            control_url: control_url.into(),
            auth_key: None,
        }
    }

    /// Set auth key for headless authentication.
    pub fn with_auth_key(mut self, key: impl Into<String>) -> Self {
        self.auth_key = Some(key.into());
        self
    }

    /// Default Tailscale control plane URL.
    pub fn default_control_url() -> &'static str {
        "https://controlplane.tailscale.com"
    }

    /// Register this node with the coordination server.
    pub async fn register(&self, _public_key: &[u8; 32]) -> io::Result<()> {
        // TODO: Implement node registration
        debug!("Registering with control plane at {}", self.control_url);
        Ok(())
    }

    /// Get peer list from coordination server.
    pub async fn get_peers(&self) -> io::Result<Vec<TailscalePeer>> {
        // TODO: Implement peer list retrieval
        Ok(vec![])
    }
}

/// Tailscale peer information.
#[derive(Debug, Clone)]
pub struct TailscalePeer {
    /// Peer's public key (WireGuard).
    pub public_key: [u8; 32],
    /// Peer's Tailscale IP (100.x.x.x).
    pub tailscale_ip: Ipv4Addr,
    /// Peer's hostname.
    pub hostname: String,
    /// Direct endpoints (IP:port).
    pub endpoints: Vec<SocketAddr>,
    /// Preferred DERP server ID.
    pub derp_id: Option<u32>,
    /// Whether peer is currently online.
    pub online: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tailnet_domain() {
        assert!(TailscaleDnsTransport::is_tailnet_domain("my-device.ts.net"));
        assert!(TailscaleDnsTransport::is_tailnet_domain("server.tailscale.net"));
        assert!(TailscaleDnsTransport::is_tailnet_domain("My-Device.TS.NET"));
        assert!(TailscaleDnsTransport::is_tailnet_domain("test.ts.net."));

        assert!(!TailscaleDnsTransport::is_tailnet_domain("google.com"));
        assert!(!TailscaleDnsTransport::is_tailnet_domain("ts.net.example.com"));
    }

    #[test]
    fn test_default_config() {
        let dns = TailscaleDnsTransport::new();
        assert_eq!(
            dns.dns_server,
            SocketAddr::new(IpAddr::V4(MAGIC_DNS_ADDR), MAGIC_DNS_PORT)
        );
    }

    #[test]
    fn test_build_dns_query() {
        let dns = TailscaleDnsTransport::new();
        let query = dns.build_dns_query("test.ts.net").unwrap();

        // Should have header (12 bytes) + question
        assert!(query.len() > 12);

        // Check flags (recursion desired)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);

        // Check QDCOUNT = 1
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
    }

    #[test]
    fn test_derp_default_servers() {
        let servers = DerpClient::default_servers();
        assert!(!servers.is_empty());
        assert!(servers[0].contains("derp"));
    }
}
