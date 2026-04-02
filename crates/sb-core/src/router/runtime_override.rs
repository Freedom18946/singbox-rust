use super::{ip_in_v4net, ip_in_v6net, normalize_host, Ipv4Net, Ipv6Net};
use crate::router::decision_intern::intern_decision;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
struct RuntimeOverride {
    exact: HashMap<String, &'static str>,
    suffix: Vec<(String, &'static str)>,
    cidr4_buckets: Vec<Vec<(Ipv4Net, &'static str)>>,
    cidr6_buckets: Vec<Vec<(Ipv6Net, &'static str)>>,
    port: HashMap<u16, &'static str>,
    port_ranges: Vec<(u16, u16, &'static str)>,
    transport_tcp: Option<&'static str>,
    transport_udp: Option<&'static str>,
    default: Option<&'static str>,
}

type RuntimeOverrideCacheEntry = Option<(String, Arc<RuntimeOverride>)>;

static RUNTIME_OVERRIDE_CACHE: Lazy<RwLock<RuntimeOverrideCacheEntry>> =
    Lazy::new(|| RwLock::new(None));

fn parse_runtime_override(raw: &str) -> RuntimeOverride {
    let mut exact = HashMap::new();
    let mut suffix = Vec::new();
    let mut cidr4_buckets: Vec<Vec<(Ipv4Net, &'static str)>> = vec![Vec::new(); 33];
    let mut cidr6_buckets: Vec<Vec<(Ipv6Net, &'static str)>> = vec![Vec::new(); 129];
    let mut port = HashMap::new();
    let mut port_ranges = Vec::new();
    let mut transport_tcp = None;
    let mut transport_udp = None;
    let mut default = None;

    for seg in raw.split([',', ';']) {
        let segment = seg.trim();
        if segment.is_empty() {
            continue;
        }
        let (key, value) = match segment.split_once('=') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => continue,
        };
        let value = intern_decision(value);

        if key.eq_ignore_ascii_case("default") {
            default = Some(value);
            continue;
        }
        let Some((kind, pattern)) = key.split_once(':') else {
            continue;
        };
        match kind.to_ascii_lowercase().as_str() {
            "exact" => {
                exact.insert(normalize_host(pattern), value);
            }
            "suffix" => {
                suffix.push((pattern.trim_start_matches('.').to_ascii_lowercase(), value));
            }
            "cidr4" => {
                let mut it = pattern.split('/');
                if let (Some(ip), Some(mask)) = (it.next(), it.next()) {
                    if let (Ok(net), Ok(mask)) =
                        (ip.trim().parse::<Ipv4Addr>(), mask.trim().parse::<u8>())
                    {
                        if mask <= 32 {
                            cidr4_buckets[mask as usize].push((Ipv4Net { net, mask }, value));
                        }
                    }
                }
            }
            "cidr6" => {
                let mut it = pattern.split('/');
                if let (Some(ip), Some(mask)) = (it.next(), it.next()) {
                    if let (Ok(net), Ok(mask)) =
                        (ip.trim().parse::<Ipv6Addr>(), mask.trim().parse::<u8>())
                    {
                        if mask <= 128 {
                            cidr6_buckets[mask as usize].push((Ipv6Net { net, mask }, value));
                        }
                    }
                }
            }
            "port" => {
                if let Ok(port_value) = pattern.parse::<u16>() {
                    port.insert(port_value, value);
                }
            }
            "portrange" => {
                let mut it = pattern.splitn(2, '-');
                if let (Some(start), Some(end)) = (it.next(), it.next()) {
                    if let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) {
                        if end >= start {
                            port_ranges.push((start, end, value));
                        }
                    }
                }
            }
            "portset" => {
                for token in pattern.split(',') {
                    if let Ok(port_value) = token.trim().parse::<u16>() {
                        port.insert(port_value, value);
                    }
                }
            }
            "transport" => match pattern.to_ascii_lowercase().as_str() {
                "tcp" => transport_tcp = Some(value),
                "udp" => transport_udp = Some(value),
                _ => {}
            },
            _ => {}
        }
    }

    RuntimeOverride {
        exact,
        suffix,
        cidr4_buckets,
        cidr6_buckets,
        port,
        port_ranges,
        transport_tcp,
        transport_udp,
        default,
    }
}

fn runtime_override() -> Option<Arc<RuntimeOverride>> {
    let raw = match std::env::var("SB_ROUTER_OVERRIDE") {
        Ok(raw) if !raw.trim().is_empty() => raw,
        _ => return None,
    };
    if let Ok(cache) = RUNTIME_OVERRIDE_CACHE.read() {
        if let Some((cached, parsed)) = &*cache {
            if cached == &raw {
                return Some(Arc::clone(parsed));
            }
        }
    }
    let parsed = Arc::new(parse_runtime_override(&raw));
    if let Ok(mut cache) = RUNTIME_OVERRIDE_CACHE.write() {
        *cache = Some((raw, Arc::clone(&parsed)));
    }
    Some(parsed)
}

pub fn runtime_override_http(
    host_norm: &str,
    port: Option<u16>,
) -> Option<(&'static str, &'static str)> {
    let override_rules = runtime_override()?;
    if let Some(decision) = override_rules.exact.get(host_norm) {
        return Some((*decision, "override"));
    }
    for (suffix, decision) in &override_rules.suffix {
        if host_norm.ends_with(suffix) {
            return Some((*decision, "override"));
        }
    }
    if let Ok(ip) = host_norm.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                for mask in (0..=32).rev() {
                    for (cidr, decision) in &override_rules.cidr4_buckets[mask] {
                        if ip_in_v4net(ipv4, *cidr) {
                            return Some((*decision, "override_cidr"));
                        }
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                for mask in (0..=128).rev() {
                    for (cidr, decision) in &override_rules.cidr6_buckets[mask] {
                        if ip_in_v6net(ipv6, *cidr) {
                            return Some((*decision, "override_cidr"));
                        }
                    }
                }
            }
        }
    }
    if let Some(port_value) = port {
        if let Some(decision) = override_rules.port.get(&port_value) {
            return Some((*decision, "override"));
        }
        for (start, end, decision) in &override_rules.port_ranges {
            if port_value >= *start && port_value <= *end {
                return Some((*decision, "override"));
            }
        }
    }
    if let Some(decision) = override_rules.transport_tcp {
        return Some((decision, "override"));
    }
    if let Some(decision) = override_rules.default {
        return Some((decision, "override_default"));
    }
    None
}

pub fn runtime_override_udp(host_norm: &str) -> Option<(&'static str, &'static str)> {
    let override_rules = runtime_override()?;
    if let Some(decision) = override_rules.exact.get(host_norm) {
        return Some((*decision, "override"));
    }
    for (suffix, decision) in &override_rules.suffix {
        if host_norm.ends_with(suffix) {
            return Some((*decision, "override"));
        }
    }
    if let Ok(ip) = host_norm.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                for mask in (0..=32).rev() {
                    for (cidr, decision) in &override_rules.cidr4_buckets[mask] {
                        if ip_in_v4net(ipv4, *cidr) {
                            return Some((*decision, "override_cidr"));
                        }
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                for mask in (0..=128).rev() {
                    for (cidr, decision) in &override_rules.cidr6_buckets[mask] {
                        if ip_in_v6net(ipv6, *cidr) {
                            return Some((*decision, "override_cidr"));
                        }
                    }
                }
            }
        }
    }
    if let Some(decision) = override_rules.transport_udp {
        return Some((decision, "override"));
    }
    if let Some(decision) = override_rules.default {
        return Some((decision, "override_default"));
    }
    None
}

pub(crate) fn runtime_override_ip(ip: IpAddr) -> Option<&'static str> {
    let override_rules = runtime_override()?;
    match ip {
        IpAddr::V4(ipv4) => {
            for mask in (0..=32).rev() {
                for (cidr, decision) in &override_rules.cidr4_buckets[mask] {
                    if ip_in_v4net(ipv4, *cidr) {
                        return Some(*decision);
                    }
                }
            }
        }
        IpAddr::V6(ipv6) => {
            for mask in (0..=128).rev() {
                for (cidr, decision) in &override_rules.cidr6_buckets[mask] {
                    if ip_in_v6net(ipv6, *cidr) {
                        return Some(*decision);
                    }
                }
            }
        }
    }
    None
}
