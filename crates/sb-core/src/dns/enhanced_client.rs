//! Enhanced DNS Client with Router Integration
//!
//! This module provides a minimal DNS client that integrates with the router system
//! and provides essential DNS resolution services behind the SB_DNS_ENABLE=1 flag.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::dns::transport::{enhanced_udp::EnhancedUdpTransport, DnsTransport};
use crate::metrics::dns::{
    record_cache_hit, record_cache_miss, record_failed_query, record_successful_query,
    set_cache_size, DnsErrorClass, DnsQueryType,
};

/// DNS cache entry with TTL and timestamp
#[derive(Clone, Debug)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
    cached_at: Instant,
}

impl CacheEntry {
    fn new(addresses: Vec<IpAddr>, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            addresses,
            expires_at: now + ttl,
            cached_at: now,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    #[cfg(any(test, feature = "dev-cli"))]
    fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// Enhanced DNS client with caching and metrics
pub struct EnhancedDnsClient {
    transport: Arc<dyn DnsTransport>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    default_ttl: Duration,
    max_cache_size: usize,
    enabled: bool,
    fallback_enabled: bool,
}

impl EnhancedDnsClient {
    /// Create new enhanced DNS client
    pub fn new() -> Self {
        let default_ttl = std::env::var("SB_DNS_TTL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(300)); // 5 minutes default

        let max_cache_size = std::env::var("SB_DNS_CACHE_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1024);

        let enabled = std::env::var("SB_DNS_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let fallback_enabled = std::env::var("SB_DNS_FALLBACK")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        // Configure DNS servers from environment
        let servers = Self::parse_dns_servers();
        let transport = Arc::new(EnhancedUdpTransport::new(servers));

        Self {
            transport,
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
            max_cache_size,
            enabled,
            fallback_enabled,
        }
    }

    /// Parse DNS servers from environment variables
    fn parse_dns_servers() -> Vec<SocketAddr> {
        let servers_str =
            std::env::var("SB_DNS_SERVERS").unwrap_or_else(|_| "8.8.8.8:53,1.1.1.1:53".to_string());

        servers_str
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                if let Ok(addr) = trimmed.parse::<SocketAddr>() {
                    Some(addr)
                } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    Some(SocketAddr::new(ip, 53))
                } else {
                    tracing::warn!("Invalid DNS server address: {}", trimmed);
                    None
                }
            })
            .collect()
    }

    /// Check if DNS client is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get cached entry if valid
    async fn get_cached(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(hostname) {
            if !entry.is_expired() {
                record_cache_hit();
                return Some(entry.addresses.clone());
            }
        }
        record_cache_miss();
        None
    }

    /// Store entry in cache with eviction
    async fn cache_entry(&self, hostname: String, addresses: Vec<IpAddr>, ttl: Option<Duration>) {
        let mut cache = self.cache.write().await;

        // Evict expired entries first
        cache.retain(|_, entry| !entry.is_expired());

        // If still at capacity, remove oldest entry
        if cache.len() >= self.max_cache_size {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        let ttl = ttl.unwrap_or(self.default_ttl);
        cache.insert(hostname, CacheEntry::new(addresses, ttl));

        // Update cache size metric
        set_cache_size(cache.len());
    }

    /// Build DNS query packet for A/AAAA records
    fn build_dns_query(hostname: &str, query_type: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS Header (12 bytes)
        packet.extend_from_slice(&[
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query, recursion desired
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ]);

        // QNAME: encode hostname as labels
        for label in hostname.split('.') {
            if !label.is_empty() {
                packet.push(label.len() as u8);
                packet.extend_from_slice(label.as_bytes());
            }
        }
        packet.push(0); // Null terminator

        // QTYPE (2 bytes)
        packet.extend_from_slice(&query_type.to_be_bytes());

        // QCLASS: IN (1) (2 bytes)
        packet.extend_from_slice(&[0x00, 0x01]);

        packet
    }

    /// Parse DNS response to extract IP addresses
    fn parse_dns_response(response: &[u8]) -> Result<Vec<IpAddr>> {
        if response.len() < 12 {
            return Err(anyhow!("DNS response too short"));
        }

        // Check response flags
        let flags = u16::from_be_bytes([response[2], response[3]]);
        let rcode = flags & 0x0F;

        if rcode != 0 {
            return match rcode {
                1 => Err(anyhow!("DNS format error")),
                2 => Err(anyhow!("DNS server failure")),
                3 => Err(anyhow!("NXDOMAIN - name does not exist")),
                _ => Err(anyhow!("DNS error code: {}", rcode)),
            };
        }

        let answer_count = u16::from_be_bytes([response[6], response[7]]);
        if answer_count == 0 {
            return Ok(Vec::new());
        }

        // For simplicity, we'll use a basic parser
        // In production, you'd want a more robust DNS message parser
        let mut addresses = Vec::new();
        let mut offset = 12;

        // Skip question section
        while offset < response.len() && response[offset] != 0 {
            let label_len = response[offset] as usize;
            if label_len == 0 {
                offset += 1;
                break;
            }
            offset += 1 + label_len;
        }
        offset += 5; // Skip null terminator, QTYPE, and QCLASS

        // Parse answer section
        for _ in 0..answer_count {
            if offset + 10 > response.len() {
                break;
            }

            // Skip name (use compression if needed)
            if response[offset] & 0xC0 == 0xC0 {
                offset += 2;
            } else {
                while offset < response.len() && response[offset] != 0 {
                    let label_len = response[offset] as usize;
                    offset += 1 + label_len;
                }
                offset += 1;
            }

            if offset + 10 > response.len() {
                break;
            }

            let record_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            offset += 8; // Skip TYPE, CLASS, TTL

            let data_len = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
            offset += 2;

            if offset + data_len > response.len() {
                break;
            }

            match record_type {
                1 if data_len == 4 => {
                    // A record
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        response[offset],
                        response[offset + 1],
                        response[offset + 2],
                        response[offset + 3],
                    ));
                    addresses.push(ip);
                }
                28 if data_len == 16 => {
                    // AAAA record
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&response[offset..offset + 16]);
                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
                    addresses.push(ip);
                }
                _ => {
                    // Skip other record types
                }
            }

            offset += data_len;
        }

        Ok(addresses)
    }

    /// Perform DNS resolution via transport
    async fn resolve_via_transport(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        #[cfg(feature = "chaos")]
        crate::util::failpoint::hit("dns::query");
        let start_time = Instant::now();
        let mut all_addresses = Vec::new();

        // Query A record
        let a_query = Self::build_dns_query(hostname, 1); // A record
        match self.transport.query(&a_query).await {
            Ok(response) => {
                if let Ok(mut addresses) = Self::parse_dns_response(&response) {
                    all_addresses.append(&mut addresses);
                }
            }
            Err(e) => {
                tracing::debug!("A record query failed for {}: {}", hostname, e);
            }
        }

        // Query AAAA record
        let aaaa_query = Self::build_dns_query(hostname, 28); // AAAA record
        match self.transport.query(&aaaa_query).await {
            Ok(response) => {
                if let Ok(mut addresses) = Self::parse_dns_response(&response) {
                    all_addresses.append(&mut addresses);
                }
            }
            Err(e) => {
                tracing::debug!("AAAA record query failed for {}: {}", hostname, e);
            }
        }

        let rtt_ms = start_time.elapsed().as_millis() as f64;

        if all_addresses.is_empty() {
            let error_class = DnsErrorClass::NameError;
            record_failed_query(DnsQueryType::A, error_class);
            Err(anyhow!("No DNS records found for {}", hostname))
        } else {
            record_successful_query(DnsQueryType::A, rtt_ms, false);
            Ok(all_addresses)
        }
    }

    /// Fallback to system resolver
    async fn resolve_system_fallback(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        if !self.fallback_enabled {
            return Err(anyhow!("System fallback disabled"));
        }

        let start_time = Instant::now();

        match tokio::net::lookup_host(format!("{}:0", hostname)).await {
            Ok(addr_iter) => {
                let addresses: Vec<IpAddr> = addr_iter.map(|addr| addr.ip()).collect();
                if addresses.is_empty() {
                    record_failed_query(DnsQueryType::A, DnsErrorClass::NameError);
                    Err(anyhow!("System resolver returned no addresses"))
                } else {
                    let rtt_ms = start_time.elapsed().as_millis() as f64;
                    record_successful_query(DnsQueryType::A, rtt_ms, false);
                    Ok(addresses)
                }
            }
            Err(e) => {
                record_failed_query(DnsQueryType::A, DnsErrorClass::NetworkError);
                Err(anyhow!("System resolver failed: {}", e))
            }
        }
    }

    /// Resolve hostname to IP addresses
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        if !self.enabled {
            return Err(anyhow!("DNS client disabled via SB_DNS_ENABLE"));
        }

        // Check cache first
        if let Some(cached_addrs) = self.get_cached(hostname).await {
            return Ok(cached_addrs);
        }

        // Try transport first
        let transport_result = self.resolve_via_transport(hostname).await;

        match transport_result {
            Ok(addresses) => {
                // Cache successful result
                self.cache_entry(hostname.to_string(), addresses.clone(), None)
                    .await;
                Ok(addresses)
            }
            Err(transport_error) => {
                tracing::debug!("DNS transport failed for {}: {}", hostname, transport_error);

                // Try system fallback
                match self.resolve_system_fallback(hostname).await {
                    Ok(addresses) => {
                        // Cache fallback result with shorter TTL
                        let fallback_ttl = self.default_ttl / 2;
                        self.cache_entry(
                            hostname.to_string(),
                            addresses.clone(),
                            Some(fallback_ttl),
                        )
                        .await;
                        Ok(addresses)
                    }
                    Err(fallback_error) => {
                        tracing::warn!(
                            "All DNS resolution methods failed for {}: transport={}, fallback={}",
                            hostname,
                            transport_error,
                            fallback_error
                        );
                        Err(transport_error) // Return original transport error
                    }
                }
            }
        }
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let total_entries = cache.len();
        let expired_entries = cache.values().filter(|entry| entry.is_expired()).count();
        (total_entries, expired_entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_query_building() {
        let query = EnhancedDnsClient::build_dns_query("example.com", 1);
        assert!(query.len() > 12); // Header + question
        assert_eq!(&query[0..2], &[0x12, 0x34]); // Transaction ID
    }

    #[test]
    fn test_cache_entry() {
        let addresses = vec![IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))];
        let entry = CacheEntry::new(addresses.clone(), Duration::from_secs(300));

        assert_eq!(entry.addresses, addresses);
        assert!(!entry.is_expired());
        assert!(entry.remaining_ttl() <= Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_client_creation() {
        let client = EnhancedDnsClient::new();
        assert_eq!(client.max_cache_size, 1024);
        assert_eq!(client.default_ttl, Duration::from_secs(300));
    }
}
