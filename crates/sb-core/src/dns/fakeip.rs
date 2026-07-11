use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

// ============================================================================
// FakeIP Store/Storage/Metadata Traits (Go parity)
// ============================================================================

// ============================================================================
// FakeIP Store/Storage/Metadata Traits (Go parity)
// ============================================================================

/// FakeIP storage interface for persistence (Go parity: adapter.FakeIPStorage)
/// Note: Synchronous to match allocate_v4/allocate_v6 APIs which are called in sync contexts.
pub trait FakeIpStorage: Send + Sync + std::fmt::Debug {
    /// Get the fake IP for a domain if it exists in storage
    fn get_by_domain(&self, domain: &str, is_ipv6: bool) -> Option<IpAddr>;

    /// Store a new mapping
    fn store(&self, domain: &str, ip: IpAddr);

    /// Load persisted FakeIP metadata (e.g. current pointer) if available.
    fn load_metadata(&self) -> Option<FakeIpMetadata> {
        None
    }

    /// Save FakeIP metadata with debounce.
    fn save_metadata_debounced(&self, _metadata: FakeIpMetadata) {}

    /// Reset persisted FakeIP mappings and allocation cursors.
    fn reset(&self) {}
}

/// Persisted FakeIP metadata — simplified Go parity.
///
/// Go stores prefixes and current pointers; Rust already sources base/mask from env/IR,
/// so we persist only the current pointers to reduce address churn across restarts.
#[derive(Debug, Clone)]
pub struct FakeIpMetadata {
    pub inet4_current_u32: u32,
    pub inet6_current_u128: u128,
}

// ============================================================================
// Helper functions
// ============================================================================

fn ipv4_add(ip: Ipv4Addr, delta: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip).wrapping_add(delta))
}

fn ipv6_add(ip: Ipv6Addr, delta: u128) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(ip).wrapping_add(delta))
}

fn start_v4(base: Ipv4Addr) -> Ipv4Addr {
    // Mirror sing-box behavior: skip network address and one reserved slot.
    ipv4_add(base, 2)
}

fn start_v6(base: Ipv6Addr) -> Ipv6Addr {
    // Mirror sing-box behavior: skip network address and one reserved slot.
    ipv6_add(base, 2)
}

#[derive(Debug)]
struct State {
    enabled: bool,
    v4_base: Ipv4Addr,
    v4_mask: u8,
    v4_current: Ipv4Addr,
    v6_base: Ipv6Addr,
    v6_mask: u8,
    v6_current: Ipv6Addr,
    // Maps
    by_domain_v4: LruCache<String, Ipv4Addr>,
    by_domain_v6: LruCache<String, Ipv6Addr>,
    by_ip: LruCache<IpAddr, String>,
    #[allow(dead_code)]
    cap: usize,
    // Persistence
    storage: Option<Arc<dyn FakeIpStorage>>,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

const DEFAULT_FAKEIP_CACHE_CAPACITY: usize = 1024;

fn fakeip_capacity(cap: usize) -> NonZeroUsize {
    NonZeroUsize::new(cap).unwrap_or(NonZeroUsize::MIN)
}

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        let defaults = crate::runtime_options::DnsRuntimeOptions::default();
        let v4_base = defaults.fakeip_v4_base;
        let v4_mask = defaults.fakeip_v4_mask;
        let v6_base = defaults.fakeip_v6_base;
        let v6_mask = defaults.fakeip_v6_mask;
        let cap = defaults.fakeip_capacity;
        let cap_nz = fakeip_capacity(cap.max(DEFAULT_FAKEIP_CACHE_CAPACITY));
        Mutex::new(State {
            enabled: defaults.fakeip_enabled,
            v4_base,
            v4_mask,
            v4_current: start_v4(v4_base),
            v6_base,
            v6_mask,
            v6_current: start_v6(v6_base),
            by_domain_v4: LruCache::new(cap_nz),
            by_domain_v6: LruCache::new(cap_nz),
            by_ip: LruCache::new(cap_nz),
            cap,
            storage: None,
        })
    })
}

pub fn configure(dns: &sb_config::ir::DnsIR, options: &crate::runtime_options::DnsRuntimeOptions) {
    let v4_base = dns
        .fakeip_v4_base
        .as_deref()
        .and_then(|value| value.parse().ok())
        .unwrap_or(options.fakeip_v4_base);
    let v4_mask = dns.fakeip_v4_mask.unwrap_or(options.fakeip_v4_mask);
    let v6_base = dns
        .fakeip_v6_base
        .as_deref()
        .and_then(|value| value.parse().ok())
        .unwrap_or(options.fakeip_v6_base);
    let v6_mask = dns.fakeip_v6_mask.unwrap_or(options.fakeip_v6_mask);
    let cap = options.fakeip_capacity;
    let cap_nz = fakeip_capacity(cap.max(DEFAULT_FAKEIP_CACHE_CAPACITY));
    let mut st = state().lock();
    st.enabled = dns.fakeip_enabled.unwrap_or(options.fakeip_enabled);
    st.v4_base = v4_base;
    st.v4_mask = v4_mask;
    st.v4_current = start_v4(v4_base);
    st.v6_base = v6_base;
    st.v6_mask = v6_mask;
    st.v6_current = start_v6(v6_base);
    st.cap = cap;
    st.by_domain_v4 = LruCache::new(cap_nz);
    st.by_domain_v6 = LruCache::new(cap_nz);
    st.by_ip = LruCache::new(cap_nz);
}

pub fn enabled() -> bool {
    state().lock().enabled
}

pub fn set_storage(storage: Arc<dyn FakeIpStorage>) {
    let mut st = state().lock();
    st.storage = Some(storage);

    // Best-effort restore persisted current pointers. Must happen after FakeIP env is applied.
    let Some(storage) = st.storage.clone() else {
        return;
    };
    let Some(meta) = storage.load_metadata() else {
        return;
    };

    let v4 = Ipv4Addr::from(meta.inet4_current_u32);
    let v6 = Ipv6Addr::from(meta.inet6_current_u128);

    // Ensure restored pointers still belong to current FakeIP ranges.
    if is_fake_v4(v4, st.v4_base, st.v4_mask) {
        st.v4_current = v4;
    }
    if is_fake_v6(v6, st.v6_base, st.v6_mask) {
        st.v6_current = v6;
    }
}

pub fn allocate_v4(domain: &str) -> IpAddr {
    let mut st = state().lock();
    if let Some(ip) = st.by_domain_v4.get(domain) {
        return IpAddr::V4(*ip);
    }

    // Check persistence
    if let Some(storage) = st.storage.clone() {
        if let Some(IpAddr::V4(ip)) = storage.get_by_domain(domain, false) {
            st.by_domain_v4.put(domain.to_string(), ip);
            st.by_ip.put(IpAddr::V4(ip), domain.to_string());
            // Update current pointer loosely if needed, but not strictly required for correctness
            return IpAddr::V4(ip);
        }
    }

    let candidate = ipv4_add(st.v4_current, 1);
    let ip = if is_fake_v4(candidate, st.v4_base, st.v4_mask) {
        candidate
    } else {
        start_v4(st.v4_base)
    };
    st.v4_current = ip;
    st.by_domain_v4.put(domain.to_string(), ip);
    let ipaddr = IpAddr::V4(ip);
    st.by_ip.put(ipaddr, domain.to_string());

    if !is_fake_v6(st.v6_current, st.v6_base, st.v6_mask) {
        st.v6_current = start_v6(st.v6_base);
    }

    if let Some(storage) = st.storage.clone() {
        storage.store(domain, ipaddr);
        storage.save_metadata_debounced(FakeIpMetadata {
            inet4_current_u32: u32::from(ip),
            inet6_current_u128: u128::from(st.v6_current),
        });
    }

    ipaddr
}

pub fn allocate_v6(domain: &str) -> IpAddr {
    let mut st = state().lock();
    if let Some(ip) = st.by_domain_v6.get(domain) {
        return IpAddr::V6(*ip);
    }

    // Check persistence
    if let Some(storage) = st.storage.clone() {
        if let Some(IpAddr::V6(ip)) = storage.get_by_domain(domain, true) {
            st.by_domain_v6.put(domain.to_string(), ip);
            st.by_ip.put(IpAddr::V6(ip), domain.to_string());
            return IpAddr::V6(ip);
        }
    }

    let candidate = ipv6_add(st.v6_current, 1);
    let ip = if is_fake_v6(candidate, st.v6_base, st.v6_mask) {
        candidate
    } else {
        start_v6(st.v6_base)
    };
    st.v6_current = ip;
    st.by_domain_v6.put(domain.to_string(), ip);
    let ipaddr = IpAddr::V6(ip);
    st.by_ip.put(ipaddr, domain.to_string());

    if !is_fake_v4(st.v4_current, st.v4_base, st.v4_mask) {
        st.v4_current = start_v4(st.v4_base);
    }

    if let Some(storage) = st.storage.clone() {
        storage.store(domain, ipaddr);
        storage.save_metadata_debounced(FakeIpMetadata {
            inet4_current_u32: u32::from(st.v4_current),
            inet6_current_u128: u128::from(ip),
        });
    }

    ipaddr
}

pub fn lookup_domain(ip: &IpAddr) -> Option<String> {
    let mut st = state().lock();
    st.by_ip.get(ip).cloned()
}

pub fn mapping_count() -> usize {
    let mut st = state().lock();
    st.by_domain_v4.len() + st.by_domain_v6.len()
}

pub fn reset() -> usize {
    let mut st = state().lock();

    let count = st.by_domain_v4.len() + st.by_domain_v6.len();
    st.by_domain_v4.clear();
    st.by_domain_v6.clear();
    st.by_ip.clear();
    st.v4_current = start_v4(st.v4_base);
    st.v6_current = start_v6(st.v6_base);

    if let Some(storage) = st.storage.clone() {
        storage.reset();
    }

    count
}

fn mask_v4(ip: Ipv4Addr, mask: u8) -> Ipv4Addr {
    let ipn = u32::from(ip);
    let m = if mask == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(mask))
    };
    Ipv4Addr::from(ipn & m)
}

fn mask_v6(ip: Ipv6Addr, mask: u8) -> Ipv6Addr {
    let ipn = u128::from(ip);
    let m: u128 = if mask == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(mask))
    };
    Ipv6Addr::from(ipn & m)
}

fn is_fake_v4(ip: Ipv4Addr, base: Ipv4Addr, mask: u8) -> bool {
    mask_v4(ip, mask) == mask_v4(base, mask)
}
fn is_fake_v6(ip: Ipv6Addr, base: Ipv6Addr, mask: u8) -> bool {
    mask_v6(ip, mask) == mask_v6(base, mask)
}

pub fn is_fake_ip(ip: &IpAddr) -> bool {
    let mut st = state().lock();
    match ip {
        IpAddr::V4(v4) => is_fake_v4(*v4, st.v4_base, st.v4_mask),
        IpAddr::V6(v6) => is_fake_v6(*v6, st.v6_base, st.v6_mask),
    }
}

pub fn to_domain(ip: &IpAddr) -> Option<String> {
    if is_fake_ip(ip) {
        lookup_domain(ip)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_options::DnsRuntimeOptions;

    fn configure_options(options: DnsRuntimeOptions) {
        let mut dns = sb_config::ir::DnsIR::default();
        dns.fakeip_enabled = None;
        configure(&dns, &options);
    }

    #[test]
    fn test_fakeip_v4_allocation() {
        configure_options(DnsRuntimeOptions {
            fakeip_v4_base: "198.18.0.0".parse().unwrap(),
            fakeip_v4_mask: 16,
            ..Default::default()
        });

        let ip1 = allocate_v4("example.com");
        let ip2 = allocate_v4("google.com");
        let ip3 = allocate_v4("example.com"); // Should return same IP

        // Same domain should get same IP
        assert_eq!(ip1, ip3);

        // Different domains should get different IPs
        assert_ne!(ip1, ip2);

        // Should be in FakeIP range
        assert!(is_fake_ip(&ip1));
        assert!(is_fake_ip(&ip2));

        // Reverse lookup should work
        assert_eq!(to_domain(&ip1), Some("example.com".to_string()));
        assert_eq!(to_domain(&ip2), Some("google.com".to_string()));
    }

    #[test]
    fn test_fakeip_v6_allocation() {
        configure_options(DnsRuntimeOptions {
            fakeip_v6_base: "fd00::".parse().unwrap(),
            fakeip_v6_mask: 8,
            ..Default::default()
        });

        let ip1 = allocate_v6("example.com");
        let ip2 = allocate_v6("google.com");
        let ip3 = allocate_v6("example.com"); // Should return same IP

        // Same domain should get same IP
        assert_eq!(ip1, ip3);

        // Different domains should get different IPs
        assert_ne!(ip1, ip2);

        // Should be in FakeIP range
        assert!(is_fake_ip(&ip1));
        assert!(is_fake_ip(&ip2));

        // Reverse lookup should work
        assert_eq!(to_domain(&ip1), Some("example.com".to_string()));
        assert_eq!(to_domain(&ip2), Some("google.com".to_string()));
    }

    #[test]
    fn test_fakeip_detection() {
        configure_options(DnsRuntimeOptions {
            fakeip_v4_base: "198.18.0.0".parse().unwrap(),
            fakeip_v4_mask: 16,
            ..Default::default()
        });

        let fake_ip = allocate_v4("test.com");
        assert!(is_fake_ip(&fake_ip));

        // Real IP should not be detected as fake
        let real_ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!is_fake_ip(&real_ip));

        let real_ipv6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_fake_ip(&real_ipv6));
    }

    #[test]
    fn test_fakeip_reverse_lookup() {
        configure_options(DnsRuntimeOptions::default());

        let domain = "example.org";
        let ip = allocate_v4(domain);

        // Reverse lookup should return original domain
        assert_eq!(lookup_domain(&ip), Some(domain.to_string()));
        assert_eq!(to_domain(&ip), Some(domain.to_string()));

        // Non-fake IP should return None
        let real_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(to_domain(&real_ip), None);
    }

    #[test]
    fn test_fakeip_enabled() {
        configure_options(DnsRuntimeOptions::default());
        assert!(!enabled());

        configure_options(DnsRuntimeOptions {
            fakeip_enabled: true,
            ..Default::default()
        });
        assert!(enabled());

        configure_options(DnsRuntimeOptions::default());
        assert!(!enabled());
    }

    #[test]
    fn test_fakeip_cidr_masking() {
        // Test IPv4 masking
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let masked_24 = mask_v4(ip, 24);
        assert_eq!(masked_24, Ipv4Addr::new(192, 168, 1, 0));

        let masked_16 = mask_v4(ip, 16);
        assert_eq!(masked_16, Ipv4Addr::new(192, 168, 0, 0));

        // Test IPv6 masking
        let ip6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let masked_32 = mask_v6(ip6, 32);
        assert_eq!(masked_32, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
    }
}
