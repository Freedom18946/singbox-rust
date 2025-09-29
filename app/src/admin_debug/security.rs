use anyhow::{Context, Result};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

/// IDNA normalization for internationalized domain names
pub fn normalize_host(host: &str) -> Result<String> {
    let trimmed = host.trim_end_matches('.');

    // Convert to ASCII using IDNA rules (handles punycode conversion)
    match idna::domain_to_ascii(trimmed) {
        Ok(ascii_host) => Ok(ascii_host),
        Err(_) => anyhow::bail!("invalid domain name: {}", trimmed),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets {
        [10, _, _, _] => true,
        [172, b, _, _] if (16..=31).contains(&b) => true,
        [192, 168, _, _] => true,
        [169, 254, _, _] => true, // link-local
        _ => false,
    }
}

#[inline]
fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    // fc00::/7 → 0b11111100 mask
    (ip.octets()[0] & 0xfe) == 0xfc
}
fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    is_unique_local_v6(ip) || ip.is_loopback() || ip.is_unspecified() || is_ipv4_mapped_ipv6(ip)
}

// Helper function to check if IPv6 address is IPv4-mapped (::ffff:x.y.z.w)
fn is_ipv4_mapped_ipv6(ip: Ipv6Addr) -> bool {
    matches!(
        ip.octets(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, _, _, _, _]
    )
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

pub fn forbid_private_host(url: &Url) -> Result<()> {
    // 仅允许域名或公网 IP；对私网/环回/本地链路直接拒绝
    if let Some(host) = url.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(ip) {
                anyhow::bail!("private ip not allowed: {ip}");
            }
        } else {
            // Apply IDNA normalization for domain names
            let _normalized = normalize_host(host)
                .with_context(|| format!("IDNA normalization failed for host: {}", host))?;
        }
        Ok(())
    } else {
        anyhow::bail!("missing host");
    }
}

pub fn forbid_private_host_or_resolved(url: &Url) -> Result<()> {
    forbid_private_host(url)?; // 先查纯 IP 场景
    if let Some(host) = url.host_str() {
        // 域名解析并校验每个 A/AAAA
        if let Some(port) = url.port_or_known_default() {
            // Use normalized host for DNS resolution
            let resolved_host = if host.parse::<IpAddr>().is_ok() {
                host.to_string() // IP address, use as-is
            } else {
                normalize_host(host)
                    .with_context(|| format!("IDNA normalization failed for host: {}", host))?
            };

            let addrs = (resolved_host.as_str(), port)
                .to_socket_addrs()
                .with_context(|| format!("resolve host failed: {resolved_host}"))?;
            for addr in addrs {
                if is_private_ip(addr.ip()) {
                    anyhow::bail!("resolved to private ip: {}", addr.ip());
                }
            }
        } else {
            anyhow::bail!("missing port for resolution");
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Allow {
    domains: Vec<String>,       // 精确或后缀（以 . 开头）
    cidrs: Vec<IpNet>,          // 10.0.0.0/8, fd00::/8 等
    ips: Vec<std::net::IpAddr>, // 精确 IP
}

fn parse_private_allowlist() -> Allow {
    let raw = std::env::var("SB_SUBS_PRIVATE_ALLOWLIST").unwrap_or_default();
    let mut domains = Vec::new();
    let mut cidrs = Vec::new();
    let mut ips = Vec::new();
    for item in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Ok(net) = item.parse::<IpNet>() {
            cidrs.push(net);
            continue;
        }
        if let Ok(ip) = item.parse::<std::net::IpAddr>() {
            ips.push(ip);
            continue;
        }
        domains.push(item.trim_end_matches('.').to_lowercase());
    }
    Allow {
        domains,
        cidrs,
        ips,
    }
}

fn host_matches_allowlist(host: &str, ip: Option<IpAddr>, allow: &Allow) -> bool {
    // Apply IDNA normalization for consistent comparison
    let normalized_host = if let Ok(norm) = normalize_host(host) {
        norm.to_lowercase()
    } else {
        host.trim_end_matches('.').to_lowercase()
    };

    if allow
        .domains
        .iter()
        .any(|a| (a.starts_with('.') && normalized_host.ends_with(a)) || normalized_host == *a)
    {
        return true;
    }
    if let Some(ip) = ip {
        if allow.ips.iter().any(|x| *x == ip) {
            return true;
        }
        if allow.cidrs.iter().any(|net| net.contains(&ip)) {
            return true;
        }
    }
    false
}

/// 带 allowlist 的私网/环回/DNS 私网终点拦截
pub fn forbid_private_host_or_resolved_with_allowlist(url: &Url) -> Result<()> {
    let allow = parse_private_allowlist();
    if let Some(host) = url.host_str() {
        // 直连 IP 且在 allowlist → 放行
        if let Ok(ip) = host.parse::<IpAddr>() {
            if host_matches_allowlist(host, Some(ip), &allow) {
                return Ok(());
            }
        } else if host_matches_allowlist(host, None, &allow) {
            return Ok(());
        }
    }
    // 常规检查（含 DNS 解析后的 A/AAAA）
    forbid_private_host_or_resolved(url)
}
