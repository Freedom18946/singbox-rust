//! Enhanced UDP DNS Transport with Metrics and Error Classification
//!
//! This module provides a production-ready UDP DNS transport implementation with:
//! - Comprehensive metrics integration
//! - Error classification and retry logic
//! - Configurable timeouts and fallback strategies

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use crate::dns::transport::DnsTransport;
use crate::metrics::dns::{record_error_display, record_query, record_rtt, DnsErrorClass, DnsQueryType};

/// Enhanced UDP DNS transport with metrics and error handling
pub struct EnhancedUdpTransport {
    servers: Vec<SocketAddr>,
    timeout: Duration,
    retries: usize,
    enabled: bool,
}

impl EnhancedUdpTransport {
    /// Create new enhanced UDP transport
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        let timeout = std::env::var("SB_DNS_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(Duration::from_millis(2000), Duration::from_millis);

        let retries = std::env::var("SB_DNS_RETRIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2);

        let enabled = std::env::var("SB_DNS_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            servers,
            timeout,
            retries,
            enabled,
        }
    }

    /// Check if DNS is enabled via environment
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Parse DNS query to extract query type for metrics
    fn extract_query_type(packet: &[u8]) -> DnsQueryType {
        // Basic DNS packet parsing to extract QTYPE
        // DNS header is 12 bytes, then comes QNAME + QTYPE + QCLASS
        if packet.len() < 16 {
            return DnsQueryType::Other;
        }

        // Skip header (12 bytes) and find QTYPE
        let mut offset = 12;

        // Skip QNAME (variable length, null-terminated labels)
        while offset < packet.len() {
            let label_len = packet[offset] as usize;
            if label_len == 0 {
                offset += 1;
                break;
            }
            offset += 1 + label_len;
            if offset >= packet.len() {
                return DnsQueryType::Other;
            }
        }

        // Extract QTYPE (2 bytes, big endian)
        if offset + 2 <= packet.len() {
            let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            DnsQueryType::from_u16(qtype)
        } else {
            DnsQueryType::Other
        }
    }

    /// Classify DNS error from error message
    fn classify_error(error: &anyhow::Error) -> DnsErrorClass {
        DnsErrorClass::from_error_str(&error.to_string())
    }

    /// Query single DNS server with timeout
    async fn query_server(&self, server: SocketAddr, packet: &[u8]) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| anyhow!("Failed to bind UDP socket: {e}"))?;

        socket
            .connect(server)
            .await
            .map_err(|e| anyhow!("Failed to connect to DNS server {server}: {e}"))?;

        // Send query
        socket
            .send(packet)
            .await
            .map_err(|e| anyhow!("Failed to send DNS query to {server}: {e}"))?;

        // Receive response with timeout
        let mut response_buf = vec![0u8; 512]; // Standard DNS UDP message size

        let response_len = tokio::time::timeout(self.timeout, socket.recv(&mut response_buf))
            .await
            .map_err(|_| anyhow!("DNS query timeout after {:?}", self.timeout))?
            .map_err(|e| anyhow!("Failed to receive DNS response: {e}"))?;

        response_buf.truncate(response_len);
        Ok(response_buf)
    }
}

#[async_trait]
impl DnsTransport for EnhancedUdpTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if !self.enabled {
            return Err(anyhow!("DNS transport disabled via SB_DNS_ENABLE"));
        }

        if self.servers.is_empty() {
            return Err(anyhow!("No DNS servers configured"));
        }

        let query_type = Self::extract_query_type(packet);
        let start_time = Instant::now();

        // Record the query attempt
        record_query(query_type);

        let mut last_error = None;

        // Try each server with retries
        for server in &self.servers {
            for attempt in 0..=self.retries {
                match self.query_server(*server, packet).await {
                    Ok(response) => {
                        let rtt_ms = start_time.elapsed().as_millis() as f64;
                        record_rtt(rtt_ms);

                        tracing::debug!(
                            "DNS query successful: server={}, attempt={}, rtt={}ms",
                            server,
                            attempt,
                            rtt_ms
                        );

                        return Ok(response);
                    }
                    Err(e) => {
                        last_error = Some(e);

                        if attempt < self.retries {
                            tracing::debug!(
                                "DNS query failed, retrying: server={}, attempt={}, error={}",
                                server,
                                attempt,
                                last_error
                                    .as_ref().map_or_else(|| "unknown".into(), std::string::ToString::to_string)
                            );

                            // Brief delay before retry
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        } else {
                            tracing::debug!(
                                "DNS query failed after {} retries: server={}, error={}",
                                self.retries,
                                server,
                                last_error
                                    .as_ref().map_or_else(|| "unknown".into(), std::string::ToString::to_string)
                            );
                        }
                    }
                }
            }
        }

        // All servers and retries failed
        let final_error = match last_error {
            Some(e) => e,
            None => anyhow!("No DNS servers available"),
        };
        record_error_display(&final_error);

        Err(final_error)
    }

    fn name(&self) -> &'static str {
        "enhanced_udp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_query_type_extraction() {
        // Create a minimal DNS query for A record (google.com)
        let mut packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];

        // Add QNAME: google.com (6+google+3+com+0)
        packet.extend_from_slice(&[6]);
        packet.extend_from_slice(b"google");
        packet.extend_from_slice(&[3]);
        packet.extend_from_slice(b"com");
        packet.extend_from_slice(&[0]);

        // Add QTYPE: A (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        // Add QCLASS: IN (1)
        packet.extend_from_slice(&[0x00, 0x01]);

        let query_type = EnhancedUdpTransport::extract_query_type(&packet);
        assert_eq!(query_type.as_str(), "A");
    }

    #[test]
    fn test_error_classification() {
        let timeout_error = anyhow!("DNS query timeout");
        assert_eq!(
            EnhancedUdpTransport::classify_error(&timeout_error).as_str(),
            "timeout"
        );

        let network_error = anyhow!("Network unreachable");
        assert_eq!(
            EnhancedUdpTransport::classify_error(&network_error).as_str(),
            "network_error"
        );
    }

    #[test]
    fn test_transport_creation() {
        let servers = vec![
            SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
            SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
        ];

        let transport = EnhancedUdpTransport::new(servers.clone());
        assert_eq!(transport.servers, servers);
        assert_eq!(transport.name(), "enhanced_udp");
    }
}
