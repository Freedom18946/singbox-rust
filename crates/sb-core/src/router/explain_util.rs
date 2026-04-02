use super::{ip_in_v4net, ip_in_v6net, RouterHandle};
use std::net::IpAddr;

pub fn try_override(
    _r: &RouterHandle,
    _q: &super::explain::ExplainQuery,
) -> Option<(String, String)> {
    if let Some(host) = _q.host.as_ref().or(_q.sni.as_ref()) {
        let host_norm = super::normalize_host(host);
        if let Some((decision, reason)) = super::runtime_override_http(&host_norm, Some(_q.port)) {
            return Some((decision.to_string(), reason.to_string()));
        }
    }

    if let Some(domain) = &_q.sni {
        if let Ok(domain_overrides) = std::env::var("SB_ROUTER_DOMAIN_OVERRIDES") {
            for override_rule in domain_overrides.split(',') {
                if let Some((pattern, decision)) = override_rule.split_once('=') {
                    if domain.contains(pattern.trim()) {
                        return Some((decision.trim().to_string(), "domain_override".to_string()));
                    }
                }
            }
        }
    }

    None
}

pub fn try_cidr(_r: &RouterHandle, ip: Option<IpAddr>) -> Option<(String, String)> {
    let ip = ip?;

    // Get the current router index
    let idx = _r.index_snapshot();

    // Check IPv4 CIDR rules
    if ip.is_ipv4() {
        for (i, bucket) in idx.cidr4_buckets.iter().enumerate() {
            for (cidr, decision) in bucket {
                if let IpAddr::V4(ipv4) = ip {
                    if ip_in_v4net(ipv4, *cidr) {
                        return Some((decision.to_string(), format!("cidr4_bucket_{}_match", i)));
                    }
                }
            }
        }

        // Check general IPv4 CIDR rules
        for (cidr, decision) in &idx.cidr4 {
            if let IpAddr::V4(ipv4) = ip {
                if ip_in_v4net(ipv4, *cidr) {
                    return Some((decision.to_string(), "cidr4_match".to_string()));
                }
            }
        }
    }

    // Check IPv6 CIDR rules
    if ip.is_ipv6() {
        for (i, bucket) in idx.cidr6_buckets.iter().enumerate() {
            for (cidr, decision) in bucket {
                if let IpAddr::V6(ipv6) = ip {
                    if ip_in_v6net(ipv6, *cidr) {
                        return Some((decision.to_string(), format!("cidr6_bucket_{}_match", i)));
                    }
                }
            }
        }

        // Check general IPv6 CIDR rules
        for (cidr, decision) in &idx.cidr6 {
            if let IpAddr::V6(ipv6) = ip {
                if ip_in_v6net(ipv6, *cidr) {
                    return Some((decision.to_string(), "cidr6_match".to_string()));
                }
            }
        }
    }

    None
}

pub fn try_geo(_r: &RouterHandle, ip: Option<IpAddr>) -> Option<(String, String)> {
    let ip = ip?;

    // Get the current router index
    let idx = _r.index_snapshot();

    // Check GeoIP rules
    for rule in &idx.geoip_rules {
        // Prefer the router-local GeoIP providers before touching legacy globals.
        if let Some(country_code) = _r.legacy_geo_cc(ip) {
            // Check if this rule matches the country
            // rule is (String, &'static str) where first element is country, second is decision
            if rule.0 == country_code {
                return Some((
                    rule.1.to_string(),
                    format!("geoip_country_{}", country_code),
                ));
            }
        }

        if let Some(decision) = _r.enhanced_geoip_lookup(ip, &idx) {
            return Some((decision.to_string(), "geoip_lookup".to_string()));
        }
    }

    // Fallback to enhanced GeoIP database if available
    if let Some(_geoip_db) = _r.geoip_db() {
        // Enhanced GeoIP lookup would be implemented here
        // For now, we skip this functionality to avoid compilation errors
        tracing::debug!("Enhanced GeoIP lookup not yet implemented");
    }

    None
}

pub fn try_suffix(_r: &RouterHandle, sni: &str) -> Option<(String, String)> {
    if sni.is_empty() {
        return None;
    }

    // Get the current router index
    let idx = _r.index_snapshot();

    // Normalize the hostname
    let normalized = super::normalize_host(sni);

    // Check suffix rules in the router index
    for (suffix, decision) in &idx.suffix {
        if normalized.ends_with(suffix) || normalized == *suffix {
            return Some((decision.to_string(), "suffix_match".to_string()));
        }

        // Also check with dot prefix for proper domain matching
        if normalized.ends_with(&format!(".{}", suffix)) {
            return Some((decision.to_string(), "suffix_domain_match".to_string()));
        }
    }

    // Check if there's a wildcard suffix rule
    for (suffix, decision) in &idx.suffix {
        if let Some(pattern) = suffix.strip_prefix('*') {
            // Remove the '*'
            if normalized.ends_with(pattern) {
                return Some((decision.to_string(), "suffix_wildcard_match".to_string()));
            }
        }
    }

    None
}

pub fn try_exact(_r: &RouterHandle, sni: &str) -> Option<(String, String)> {
    if sni.is_empty() {
        return None;
    }

    // Get the current router index
    let idx = _r.index_snapshot();

    // Normalize the hostname
    let normalized = super::normalize_host(sni);

    // Check exact rules in the router index
    if let Some(decision) = idx.exact.get(&normalized) {
        return Some((decision.to_string(), "exact_match".to_string()));
    }

    // Also try the original hostname without normalization
    if let Some(decision) = idx.exact.get(sni) {
        return Some((decision.to_string(), "exact_raw_match".to_string()));
    }

    // Check case-insensitive exact match
    let lowercase = sni.to_lowercase();
    if let Some(decision) = idx.exact.get(&lowercase) {
        return Some((
            decision.to_string(),
            "exact_case_insensitive_match".to_string(),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{try_override, RouterHandle};
    use crate::router::{explain::ExplainQuery, router_build_index_from_str};
    use crate::testutil::EnvVarGuard;

    #[test]
    fn try_override_uses_runtime_override_query_seam() {
        let _override = EnvVarGuard::set(
            "SB_ROUTER_OVERRIDE",
            "exact:api.example.com=proxy;default=reject",
        );
        let idx = router_build_index_from_str("default=unresolved", 64).expect("router index");
        let handle = RouterHandle::from_index(idx);
        let query = ExplainQuery {
            sni: Some("api.example.com".into()),
            host: None,
            ip: None,
            port: 443,
            proto: "tcp",
            transport: Some("tcp"),
            alpn: None,
        };

        let result = try_override(&handle, &query).expect("override should match");
        assert_eq!(result.0, "proxy");
        assert_eq!(result.1, "override");
    }
}
