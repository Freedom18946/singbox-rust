use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use lru::LruCache;
use std::num::NonZeroUsize;
use parking_lot::Mutex;

#[derive(Debug)]
struct State {
    v4_base: Ipv4Addr,
    v4_mask: u8,
    next: u32,
    v6_base: Ipv6Addr,
    v6_mask: u8,
    next6: u128,
    // Maps
    by_domain: LruCache<String, IpAddr>,
    by_ip: LruCache<IpAddr, String>,
    cap: usize,
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        // Defaults: 240.0.0.0/8, capacity 16384
        let v4_base: Ipv4Addr = std::env::var("SB_FAKEIP_V4_BASE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Ipv4Addr::new(240, 0, 0, 0));
        let v4_mask: u8 = std::env::var("SB_FAKEIP_V4_MASK").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let v6_base: Ipv6Addr = std::env::var("SB_FAKEIP_V6_BASE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Ipv6Addr::new(0xfd00,0,0,0,0,0,0,0));
        let v6_mask: u8 = std::env::var("SB_FAKEIP_V6_MASK").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
        let cap: usize = std::env::var("SB_FAKEIP_CAP").ok().and_then(|s| s.parse().ok()).unwrap_or(16384);
        let cap_nz = NonZeroUsize::new(cap).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Mutex::new(State {
            v4_base,
            v4_mask,
            next: 1,
            v6_base,
            v6_mask,
            next6: 1,
            by_domain: LruCache::new(cap_nz),
            by_ip: LruCache::new(cap_nz),
            cap,
        })
    })
}

pub fn enabled() -> bool {
    std::env::var("SB_DNS_FAKEIP_ENABLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn allocate_v4(domain: &str) -> IpAddr {
    let mut st = state().lock();
    if let Some(ip) = st.by_domain.get(domain) {
        return *ip;
    }
    // Compute next IP within CIDR
    let base_u32 = u32::from(st.v4_base);
    let host_bits = 32 - st.v4_mask as u32;
    let max_hosts = (1u128 << host_bits) as u32;
    let offset = (st.next % max_hosts).max(1); // avoid network address
    st.next = st.next.wrapping_add(1);
    let ip = Ipv4Addr::from(base_u32.wrapping_add(offset));
    let ipaddr = IpAddr::V4(ip);
    st.by_domain.put(domain.to_string(), ipaddr);
    st.by_ip.put(ipaddr, domain.to_string());
    ipaddr
}

pub fn allocate_v6(domain: &str) -> IpAddr {
    let mut st = state().lock();
    if let Some(ip) = st.by_domain.get(domain) {
        return *ip;
    }
    // Compute next IPv6 within prefix
    let base_u128 = u128::from(st.v6_base);
    let host_bits = 128 - st.v6_mask as u32;
    let max_hosts = if host_bits >= 128 { u128::MAX } else { 1u128 << host_bits };
    let offset = (st.next6 % max_hosts).max(1);
    st.next6 = st.next6.wrapping_add(1);
    let ip = Ipv6Addr::from(base_u128.wrapping_add(offset));
    let ipaddr = IpAddr::V6(ip);
    st.by_domain.put(domain.to_string(), ipaddr);
    st.by_ip.put(ipaddr, domain.to_string());
    ipaddr
}

pub fn lookup_domain(ip: &IpAddr) -> Option<String> {
    let mut st = state().lock();
    st.by_ip.get(ip).cloned()
}

fn mask_v4(ip: Ipv4Addr, mask: u8) -> Ipv4Addr {
    let ipn = u32::from(ip);
    let m = if mask == 0 { 0 } else { u32::MAX << (32 - mask as u32) };
    Ipv4Addr::from(ipn & m)
}

fn mask_v6(ip: Ipv6Addr, mask: u8) -> Ipv6Addr {
    let ipn = u128::from(ip);
    let m: u128 = if mask == 0 { 0 } else { u128::MAX << (128 - mask as u32) };
    Ipv6Addr::from(ipn & m)
}

fn is_fake_v4(ip: Ipv4Addr, base: Ipv4Addr, mask: u8) -> bool { mask_v4(ip, mask) == mask_v4(base, mask) }
fn is_fake_v6(ip: Ipv6Addr, base: Ipv6Addr, mask: u8) -> bool { mask_v6(ip, mask) == mask_v6(base, mask) }

pub fn is_fake_ip(ip: &IpAddr) -> bool {
    let st = state().lock();
    match ip {
        IpAddr::V4(v4) => is_fake_v4(*v4, st.v4_base, st.v4_mask),
        IpAddr::V6(v6) => is_fake_v6(*v6, st.v6_base, st.v6_mask),
    }
}

pub fn to_domain(ip: &IpAddr) -> Option<String> {
    if is_fake_ip(ip) { lookup_domain(ip) } else { None }
}
