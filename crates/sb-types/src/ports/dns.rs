//! DNS resolver port.

use crate::errors::DnsError;
use std::net::IpAddr;

/// DNS cache statistics.
#[derive(Debug, Clone, Default)]
pub struct DnsCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
}

/// DNS resolver port.
///
/// sb-core uses this to resolve domain names.
/// Implementations may be: system resolver, DoH, DoT, etc.
pub trait DnsPort: Send + Sync + 'static {
    /// Resolve a domain name to IP addresses.
    fn resolve_ip(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send;

    /// Get cache statistics.
    fn cache_stats(&self) -> DnsCacheStats;
}
