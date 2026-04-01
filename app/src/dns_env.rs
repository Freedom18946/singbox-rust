//! Runtime-facing DNS environment bridge for `run_engine`.

/// Apply DNS environment configuration from config file (top-level `dns` block).
/// Returns true if any DNS setting was derived from config.
#[cfg(feature = "router")]
#[allow(clippy::too_many_lines)]
pub fn apply_dns_env_from_config(doc: &serde_json::Value) -> bool {
    let mut applied = false;
    let Some(dns) = doc.get("dns") else {
        return false;
    };

    // servers: [{ address: "udp://1.1.1.1" | "https://..." | "dot://..." | "doq://..." | "system" | "rcode://..." }]
    if let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) {
        let mut pool_tokens: Vec<String> = Vec::new();
        let mut first_mode_set = false;
        for s in servers {
            let Some(addr_raw) = s.get("address").and_then(|v| v.as_str()) else {
                continue;
            };
            if addr_raw.starts_with("rcode://") {
                continue;
            }
            if let Some(rest) = addr_raw.strip_prefix("udp://") {
                let token = if rest.contains(':') {
                    format!("udp:{rest}")
                } else {
                    format!("udp:{rest}:53")
                };
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "udp");
                    let svr = token.trim_start_matches("udp:");
                    set_if_unset("SB_DNS_UDP_SERVER", svr);
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if addr_raw.starts_with("https://") || addr_raw.starts_with("http://") {
                let token = format!("doh:{addr_raw}");
                pool_tokens.push(token);
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "doh");
                    set_if_unset("SB_DNS_DOH_URL", addr_raw);
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if let Some(rest) = addr_raw
                .strip_prefix("dot://")
                .or_else(|| addr_raw.strip_prefix("tls://"))
            {
                let token = if rest.contains(':') {
                    format!("dot:{rest}")
                } else {
                    format!("dot:{rest}:853")
                };
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "dot");
                    let dot = token.trim_start_matches("dot:");
                    set_if_unset("SB_DNS_DOT_ADDR", dot);
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if let Some(rest) = addr_raw
                .strip_prefix("doq://")
                .or_else(|| addr_raw.strip_prefix("quic://"))
            {
                let token = format!("doq:{rest}");
                pool_tokens.push(token.clone());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "doq");
                    if let Some((addr, sni)) = rest.split_once('@') {
                        set_if_unset("SB_DNS_DOQ_ADDR", addr);
                        set_if_unset("SB_DNS_DOQ_SERVER_NAME", sni);
                    } else {
                        set_if_unset("SB_DNS_DOQ_ADDR", rest);
                    }
                    applied = true;
                    first_mode_set = true;
                }
                continue;
            }
            if addr_raw.eq_ignore_ascii_case("system") {
                pool_tokens.push("system".to_string());
                if !first_mode_set {
                    set_if_unset("SB_DNS_MODE", "system");
                    applied = true;
                    first_mode_set = true;
                }
            }
        }
        if !pool_tokens.is_empty() {
            set_if_unset("SB_DNS_POOL", &pool_tokens.join(","));
        }
    }

    if let Some(strategy) = dns.get("strategy").and_then(|v| v.as_str()) {
        match strategy.to_ascii_lowercase().as_str() {
            "ipv4_only" | "prefer_ipv4" => {
                set_if_unset("SB_DNS_QTYPE", "a");
                set_if_unset("SB_DNS_HE_ORDER", "A_FIRST");
                applied = true;
            }
            "ipv6_only" | "prefer_ipv6" => {
                set_if_unset("SB_DNS_QTYPE", "aaaa");
                set_if_unset("SB_DNS_HE_ORDER", "AAAA_FIRST");
                applied = true;
            }
            _ => {}
        }
    }

    if let Some(ttl) = dns.get("ttl").and_then(|v| v.as_object()) {
        if let Some(secs) = ttl.get("default").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_DEFAULT_TTL_S", &secs.to_string());
            applied = true;
        }
        if let Some(secs) = ttl.get("min").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_MIN_TTL_S", &secs.to_string());
            applied = true;
        }
        if let Some(secs) = ttl.get("max").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_MAX_TTL_S", &secs.to_string());
            applied = true;
        }
        if let Some(secs) = ttl.get("neg").and_then(num_or_string_secs) {
            set_if_unset("SB_DNS_NEG_TTL_S", &secs.to_string());
            applied = true;
        }
    }

    if let Some(hosts) = dns.get("hosts").and_then(|v| v.as_object()) {
        let mut parts: Vec<String> = Vec::new();
        for (host, val) in hosts {
            let host = host.trim().to_ascii_lowercase();
            if host.is_empty() {
                continue;
            }
            let mut ips: Vec<String> = Vec::new();
            match val {
                serde_json::Value::String(s) => {
                    if !s.trim().is_empty() {
                        ips.push(s.trim().to_string());
                    }
                }
                serde_json::Value::Array(arr) => {
                    for it in arr {
                        if let Some(s) = it.as_str() {
                            if !s.trim().is_empty() {
                                ips.push(s.trim().to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
            if !ips.is_empty() {
                parts.push(format!("{}={}", host, ips.join(";")));
            }
        }
        if !parts.is_empty() {
            set_if_unset("SB_DNS_STATIC", &parts.join(","));
            if let Some(ttl_s) = dns
                .get("hosts_ttl")
                .or_else(|| dns.get("static_ttl"))
                .and_then(num_or_string_secs)
            {
                set_if_unset("SB_DNS_STATIC_TTL_S", &ttl_s.to_string());
            }
            applied = true;
        }
    }

    if let Some(fakeip) = dns.get("fakeip").and_then(|v| v.as_object()) {
        let enabled = fakeip
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if enabled {
            set_if_unset("SB_DNS_FAKEIP_ENABLE", "1");
            applied = true;
            if let Some(r) = fakeip.get("inet4_range").and_then(|v| v.as_str()) {
                if let Some((base, mask)) = split_cidr(r) {
                    set_if_unset("SB_FAKEIP_V4_BASE", base);
                    set_if_unset("SB_FAKEIP_V4_MASK", &mask.to_string());
                }
            }
            if let Some(r) = fakeip.get("inet6_range").and_then(|v| v.as_str()) {
                if let Some((base, mask)) = split_cidr(r) {
                    set_if_unset("SB_FAKEIP_V6_BASE", base);
                    set_if_unset("SB_FAKEIP_V6_MASK", &mask.to_string());
                }
            }
        }
    }

    if let Some(s) = dns.get("pool_strategy").and_then(|v| v.as_str()) {
        let s_lc = s.to_ascii_lowercase();
        let v_norm = match s_lc.as_str() {
            "race" | "racing" => "race",
            "fanout" | "parallel" => "fanout",
            "sequential" | "seq" => "sequential",
            _ => s_lc.as_str(),
        };
        set_if_unset("SB_DNS_POOL_STRATEGY", v_norm);
        applied = true;
    }

    if let Some(pool) = dns.get("pool").and_then(|v| v.as_object()) {
        if let Some(v) = pool
            .get("race_window_ms")
            .and_then(serde_json::Value::as_u64)
        {
            set_if_unset("SB_DNS_RACE_WINDOW_MS", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool.get("he_race_ms").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_HE_RACE_MS", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool.get("he_order").and_then(|x| x.as_str()) {
            let norm = if v.eq_ignore_ascii_case("AAAA_FIRST") {
                "AAAA_FIRST"
            } else {
                "A_FIRST"
            };
            set_if_unset("SB_DNS_HE_ORDER", norm);
            applied = true;
        }
        if let Some(v) = pool.get("max_inflight").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_POOL_MAX_INFLIGHT", &v.to_string());
            applied = true;
        }
        if let Some(v) = pool
            .get("per_host_inflight")
            .and_then(serde_json::Value::as_u64)
        {
            set_if_unset("SB_DNS_PER_HOST_INFLIGHT", &v.to_string());
            applied = true;
        }
    }

    if let Some(v) = dns.get("timeout_ms").and_then(serde_json::Value::as_u64) {
        let s = v.to_string();
        set_if_unset("SB_DNS_UDP_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_DOT_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_DOH_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_DOQ_TIMEOUT_MS", &s);
        set_if_unset("SB_DNS_QUERY_TIMEOUT_MS", &s);
        applied = true;
    }

    if let Some(cache) = dns.get("cache").and_then(|v| v.as_object()) {
        if cache
            .get("enable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            set_if_unset("SB_DNS_CACHE_ENABLE", "1");
            applied = true;
        }
        if let Some(cap) = cache.get("cap").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_CACHE_CAP", &cap.to_string());
            applied = true;
        }
        if let Some(neg_ms) = cache.get("neg_ttl_ms").and_then(serde_json::Value::as_u64) {
            set_if_unset("SB_DNS_CACHE_NEG_TTL_MS", &neg_ms.to_string());
            applied = true;
        }
    }

    applied
}

#[cfg(feature = "router")]
fn set_if_unset(key: &str, value: &str) {
    if std::env::var(key).is_err() {
        std::env::set_var(key, value);
    }
}

#[cfg(feature = "router")]
fn num_or_string_secs(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(n) = s.parse::<u64>() {
            return Some(n);
        }
        let (num, suf) = s.split_at(s.len().saturating_sub(1));
        if let Ok(n) = num.parse::<u64>() {
            return Some(match suf {
                "s" | "S" => n,
                "m" | "M" => n.saturating_mul(60),
                "h" | "H" => n.saturating_mul(3600),
                _ => return None,
            });
        }
    }
    None
}

#[cfg(feature = "router")]
fn split_cidr(s: &str) -> Option<(&str, u8)> {
    let s = s.trim();
    let (base, mask) = s.split_once('/')?;
    let mask = mask.parse::<u8>().ok()?;
    Some((base, mask))
}

#[cfg(all(test, feature = "router"))]
mod tests {
    use super::apply_dns_env_from_config;
    use serde_json::json;
    use serial_test::serial;

    const TRACKED_ENV_PREFIXES: &[&str] = &["SB_DNS_", "SB_FAKEIP_"];

    struct ScopedDnsEnv {
        saved: Vec<(String, String)>,
    }

    impl ScopedDnsEnv {
        fn capture() -> Self {
            let saved = std::env::vars()
                .filter(|(key, _)| tracked_dns_env(key))
                .collect();
            clear_tracked_dns_env();
            Self { saved }
        }
    }

    impl Drop for ScopedDnsEnv {
        fn drop(&mut self) {
            clear_tracked_dns_env();
            for (key, value) in &self.saved {
                std::env::set_var(key, value);
            }
        }
    }

    fn tracked_dns_env(key: &str) -> bool {
        TRACKED_ENV_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
    }

    fn clear_tracked_dns_env() {
        let keys: Vec<String> = std::env::vars()
            .map(|(key, _)| key)
            .filter(|key| tracked_dns_env(key))
            .collect();
        for key in keys {
            std::env::remove_var(key);
        }
    }

    fn env_var(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn apply(doc: serde_json::Value) -> bool {
        apply_dns_env_from_config(&doc)
    }

    #[test]
    #[serial]
    fn derives_udp_server_envs() {
        let _guard = ScopedDnsEnv::capture();

        let applied = apply(json!({
            "dns": {
                "servers": [{ "address": "udp://1.1.1.1" }]
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_MODE").as_deref(), Some("udp"));
        assert_eq!(env_var("SB_DNS_UDP_SERVER").as_deref(), Some("1.1.1.1:53"));
        assert_eq!(env_var("SB_DNS_POOL").as_deref(), Some("udp:1.1.1.1:53"));
    }

    #[test]
    #[serial]
    fn derives_doh_server_envs() {
        let _guard = ScopedDnsEnv::capture();

        let applied = apply(json!({
            "dns": {
                "servers": [{ "address": "https://dns.example/dns-query" }]
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_MODE").as_deref(), Some("doh"));
        assert_eq!(
            env_var("SB_DNS_DOH_URL").as_deref(),
            Some("https://dns.example/dns-query")
        );
        assert_eq!(
            env_var("SB_DNS_POOL").as_deref(),
            Some("doh:https://dns.example/dns-query")
        );
    }

    #[test]
    #[serial]
    fn derives_dot_server_envs() {
        let _guard = ScopedDnsEnv::capture();

        let applied = apply(json!({
            "dns": {
                "servers": [{ "address": "dot://dns.example" }]
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_MODE").as_deref(), Some("dot"));
        assert_eq!(
            env_var("SB_DNS_DOT_ADDR").as_deref(),
            Some("dns.example:853")
        );
        assert_eq!(
            env_var("SB_DNS_POOL").as_deref(),
            Some("dot:dns.example:853")
        );
    }

    #[test]
    #[serial]
    fn derives_doq_server_envs() {
        let _guard = ScopedDnsEnv::capture();

        let applied = apply(json!({
            "dns": {
                "servers": [{ "address": "doq://dns.example:8853@resolver.example" }]
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_MODE").as_deref(), Some("doq"));
        assert_eq!(
            env_var("SB_DNS_DOQ_ADDR").as_deref(),
            Some("dns.example:8853")
        );
        assert_eq!(
            env_var("SB_DNS_DOQ_SERVER_NAME").as_deref(),
            Some("resolver.example")
        );
        assert_eq!(
            env_var("SB_DNS_POOL").as_deref(),
            Some("doq:dns.example:8853@resolver.example")
        );
    }

    #[test]
    #[serial]
    fn derives_system_server_envs() {
        let _guard = ScopedDnsEnv::capture();

        let applied = apply(json!({
            "dns": {
                "servers": [{ "address": "system" }]
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_MODE").as_deref(), Some("system"));
        assert_eq!(env_var("SB_DNS_POOL").as_deref(), Some("system"));
    }

    #[test]
    #[serial]
    fn maps_strategy_to_qtype_and_happy_eyeballs_order() {
        {
            let _guard = ScopedDnsEnv::capture();
            let applied = apply(json!({ "dns": { "strategy": "prefer_ipv4" } }));
            assert!(applied);
            assert_eq!(env_var("SB_DNS_QTYPE").as_deref(), Some("a"));
            assert_eq!(env_var("SB_DNS_HE_ORDER").as_deref(), Some("A_FIRST"));
        }

        {
            let _guard = ScopedDnsEnv::capture();
            let applied = apply(json!({ "dns": { "strategy": "prefer_ipv6" } }));
            assert!(applied);
            assert_eq!(env_var("SB_DNS_QTYPE").as_deref(), Some("aaaa"));
            assert_eq!(env_var("SB_DNS_HE_ORDER").as_deref(), Some("AAAA_FIRST"));
        }
    }

    #[test]
    #[serial]
    fn maps_ttl_and_hosts_to_static_envs() {
        let _guard = ScopedDnsEnv::capture();

        let applied = apply(json!({
            "dns": {
                "ttl": {
                    "default": 30,
                    "min": "15s",
                    "max": "2m",
                    "neg": "1h"
                },
                "hosts": {
                    "Example.COM": ["1.1.1.1", "2001:db8::1"],
                    "single.example": "9.9.9.9"
                },
                "hosts_ttl": "45s"
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_DEFAULT_TTL_S").as_deref(), Some("30"));
        assert_eq!(env_var("SB_DNS_MIN_TTL_S").as_deref(), Some("15"));
        assert_eq!(env_var("SB_DNS_MAX_TTL_S").as_deref(), Some("120"));
        assert_eq!(env_var("SB_DNS_NEG_TTL_S").as_deref(), Some("3600"));
        assert_eq!(env_var("SB_DNS_STATIC_TTL_S").as_deref(), Some("45"));

        let mut static_entries: Vec<String> = env_var("SB_DNS_STATIC")
            .expect("static entries should be set")
            .split(',')
            .map(std::string::ToString::to_string)
            .collect();
        static_entries.sort();
        assert_eq!(
            static_entries,
            vec![
                "example.com=1.1.1.1;2001:db8::1".to_string(),
                "single.example=9.9.9.9".to_string()
            ]
        );
    }

    #[test]
    #[serial]
    fn preserves_existing_env_values_when_bridge_runs() {
        let _guard = ScopedDnsEnv::capture();
        std::env::set_var("SB_DNS_MODE", "manual");
        std::env::set_var("SB_DNS_QTYPE", "txt");

        let applied = apply(json!({
            "dns": {
                "servers": [{ "address": "udp://8.8.8.8" }],
                "strategy": "prefer_ipv4"
            }
        }));

        assert!(applied);
        assert_eq!(env_var("SB_DNS_MODE").as_deref(), Some("manual"));
        assert_eq!(env_var("SB_DNS_QTYPE").as_deref(), Some("txt"));
        assert_eq!(env_var("SB_DNS_HE_ORDER").as_deref(), Some("A_FIRST"));
        assert_eq!(env_var("SB_DNS_POOL").as_deref(), Some("udp:8.8.8.8:53"));
    }

    #[test]
    #[serial]
    fn returns_false_when_no_supported_dns_settings_are_present() {
        let _guard = ScopedDnsEnv::capture();

        assert!(!apply(json!({})));
        assert!(!apply(json!({
            "dns": {
                "servers": [{ "address": "rcode://success" }]
            }
        })));
    }

    #[test]
    #[serial]
    fn wp30aj_pin_dns_env_bridge_owner_is_dns_env_rs() {
        let source = include_str!("dns_env.rs");
        let run_engine = include_str!("run_engine.rs");

        assert!(source.contains("pub fn apply_dns_env_from_config"));
        assert!(!run_engine.contains("fn apply_dns_env_from_config("));
    }

    #[test]
    #[serial]
    fn wp30aj_pin_run_engine_delegates_dns_env_bridge() {
        let run_engine = include_str!("run_engine.rs");
        let supervisor = include_str!("run_engine_runtime/supervisor.rs");

        assert!(supervisor.contains("crate::dns_env::apply_dns_env_from_config(&raw)"));
        assert!(run_engine.contains("run_engine_runtime::supervisor::run_supervisor(opts).await"));
        assert!(!run_engine.contains("SB_DNS_"));
    }
}
