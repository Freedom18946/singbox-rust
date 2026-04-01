use sb_config::Config;

pub(crate) fn apply_dns_from_config(cfg: &Config) {
    use serde_json::Value;

    let raw = cfg.raw();
    let mut pool_tokens: Vec<String> = Vec::new();

    if let Some(dns) = raw.get("dns").and_then(Value::as_object) {
        if let Some(servers) = dns.get("servers").and_then(|value| value.as_array()) {
            for server in servers {
                if let Some(token) = server_to_token(server) {
                    push_dedup(&mut pool_tokens, token);
                }
            }
        }

        if let Some(strategy) = dns.get("strategy").and_then(Value::as_str) {
            std::env::set_var("SB_DNS_POOL_STRATEGY", strategy);
        }
        if let Some(window_ms) = dns.get("race_window_ms").and_then(Value::as_u64) {
            std::env::set_var("SB_DNS_RACE_WINDOW_MS", window_ms.to_string());
        }
        if let Some(timeout_ms) = dns.get("timeout_ms").and_then(Value::as_u64) {
            std::env::set_var("SB_DNS_TIMEOUT_MS", timeout_ms.to_string());
        }
        if let Some(ipv6) = dns.get("ipv6").and_then(Value::as_bool) {
            if ipv6 {
                std::env::set_var("SB_DNS_IPV6", "1");
            }
        }
        if let Some(he_order) = dns.get("he_order").and_then(Value::as_str) {
            std::env::set_var("SB_DNS_HE_ORDER", he_order);
        }
    }

    if pool_tokens.is_empty() {
        pool_tokens.push("system".to_string());
    }

    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var("SB_DNS_POOL", pool_tokens.join(","));
}

pub(crate) fn push_dedup(values: &mut Vec<String>, candidate: String) {
    if !values
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&candidate))
    {
        values.push(candidate);
    }
}

pub(crate) fn server_to_token(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => normalize_addr(text),
        serde_json::Value::Object(map) => map
            .get("address")
            .and_then(serde_json::Value::as_str)
            .and_then(normalize_addr),
        _ => None,
    }
}

pub(crate) fn normalize_addr(addr: &str) -> Option<String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }

    for prefix in ["system", "udp:", "tcp:", "doh:", "dot:", "doq:"] {
        if addr.eq_ignore_ascii_case("system") || addr.starts_with(prefix) {
            return Some(addr.to_string());
        }
    }

    if addr.starts_with("https://") {
        return Some(format!("doh:{addr}"));
    }
    if addr.starts_with("udp://") {
        return Some(format!("udp:{}", addr.trim_start_matches("udp://")));
    }
    if addr.starts_with("tcp://") {
        return Some(format!("tcp:{}", addr.trim_start_matches("tcp://")));
    }
    if addr.starts_with("dot://") {
        return Some(format!("dot:{}", addr.trim_start_matches("dot://")));
    }
    if addr.starts_with("doq://") {
        return Some(format!("doq:{}", addr.trim_start_matches("doq://")));
    }
    if addr.contains(':') {
        return Some(format!("udp:{addr}"));
    }

    Some("system".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        saved: HashMap<&'static str, Option<String>>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    fn load_config(doc: serde_json::Value) -> anyhow::Result<Config> {
        Config::from_value(doc)
    }

    #[test]
    fn normalize_addr_and_server_to_token_cover_bootstrap_dns_forms() {
        assert_eq!(
            normalize_addr("https://dns.google/dns-query"),
            Some("doh:https://dns.google/dns-query".to_string())
        );
        assert_eq!(
            normalize_addr("udp://1.1.1.1:53"),
            Some("udp://1.1.1.1:53".to_string())
        );
        assert_eq!(
            server_to_token(&json!({"address":"dot://dns.google"})),
            Some("dot://dns.google".to_string())
        );
        assert_eq!(
            server_to_token(&json!("1.1.1.1:53")),
            Some("udp:1.1.1.1:53".to_string())
        );
        assert_eq!(normalize_addr("resolver-name"), Some("system".to_string()));
    }

    #[test]
    fn push_dedup_is_ascii_case_insensitive() {
        let mut values = vec!["udp:1.1.1.1:53".to_string()];
        push_dedup(&mut values, "UDP:1.1.1.1:53".to_string());
        push_dedup(&mut values, "system".to_string());

        assert_eq!(
            values,
            vec!["udp:1.1.1.1:53".to_string(), "system".to_string()]
        );
    }

    #[test]
    fn apply_dns_from_config_sets_pool_and_runtime_env_vars() -> anyhow::Result<()> {
        let _guard = env_lock().lock().expect("env lock");
        let _restore = EnvGuard::new(&[
            "SB_DNS_ENABLE",
            "SB_ROUTER_DNS",
            "SB_DNS_POOL",
            "SB_DNS_POOL_STRATEGY",
            "SB_DNS_RACE_WINDOW_MS",
            "SB_DNS_TIMEOUT_MS",
            "SB_DNS_IPV6",
            "SB_DNS_HE_ORDER",
        ]);
        let cfg = load_config(json!({
            "schema_version": 2,
            "outbounds": [{ "type": "direct", "name": "direct" }],
            "route": { "rules": [], "default": "direct" },
            "dns": {
                "servers": [
                    "1.1.1.1:53",
                    { "address": "1.1.1.1:53" },
                    { "address": "https://dns.google/dns-query" }
                ],
                "strategy": "race",
                "race_window_ms": 25,
                "timeout_ms": 1000,
                "ipv6": true,
                "he_order": "AAAA_FIRST"
            }
        }))?;

        apply_dns_from_config(&cfg);

        assert_eq!(std::env::var("SB_DNS_ENABLE").ok().as_deref(), Some("1"));
        assert_eq!(std::env::var("SB_ROUTER_DNS").ok().as_deref(), Some("1"));
        assert_eq!(
            std::env::var("SB_DNS_POOL").ok().as_deref(),
            Some("udp:1.1.1.1:53,doh:https://dns.google/dns-query")
        );
        assert_eq!(
            std::env::var("SB_DNS_POOL_STRATEGY").ok().as_deref(),
            Some("race")
        );
        assert_eq!(
            std::env::var("SB_DNS_RACE_WINDOW_MS").ok().as_deref(),
            Some("25")
        );
        assert_eq!(
            std::env::var("SB_DNS_TIMEOUT_MS").ok().as_deref(),
            Some("1000")
        );
        assert_eq!(std::env::var("SB_DNS_IPV6").ok().as_deref(), Some("1"));
        assert_eq!(
            std::env::var("SB_DNS_HE_ORDER").ok().as_deref(),
            Some("AAAA_FIRST")
        );

        Ok(())
    }

    #[test]
    fn apply_dns_from_config_defaults_to_system_pool_when_servers_are_absent() -> anyhow::Result<()>
    {
        let _guard = env_lock().lock().expect("env lock");
        let _restore = EnvGuard::new(&["SB_DNS_ENABLE", "SB_ROUTER_DNS", "SB_DNS_POOL"]);
        let cfg = load_config(json!({
            "schema_version": 2,
            "outbounds": [{ "type": "direct", "name": "direct" }],
            "route": { "rules": [], "default": "direct" },
            "dns": {}
        }))?;

        apply_dns_from_config(&cfg);

        assert_eq!(std::env::var("SB_DNS_POOL").ok().as_deref(), Some("system"));

        Ok(())
    }

    #[test]
    fn wp30an_pin_dns_apply_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("dns_apply.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("pub(crate) fn apply_dns_from_config"));
        assert!(source.contains("pub(crate) fn push_dedup"));
        assert!(source.contains("pub(crate) fn server_to_token"));
        assert!(source.contains("pub(crate) fn normalize_addr"));
        assert!(!bootstrap.contains("fn apply_dns_from_config("));
        assert!(!bootstrap.contains("fn push_dedup("));
        assert!(!bootstrap.contains("fn server_to_token("));
        assert!(!bootstrap.contains("fn normalize_addr("));
        assert!(
            bootstrap.contains("crate::bootstrap_runtime::dns_apply::apply_dns_from_config(&cfg);")
        );
    }
}
