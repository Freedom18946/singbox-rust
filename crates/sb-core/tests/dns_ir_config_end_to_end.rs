//! End-to-end tests for IR-driven DNS resolver

#![cfg(feature = "router")]

use std::io::Write as _;

use tempfile::NamedTempFile;

#[tokio::test]
async fn dns_ir_hosts_overlay_and_engine_presence() {
    // JSON config with dns.hosts and minimal servers/default
    let json = serde_json::json!({
        "dns": {
            "servers": [ {"tag": "system", "address": "system"} ],
            "default": "system",
            "hosts": { "unit.test.local": ["203.0.113.1", "2001:db8::1"] },
            "hosts_ttl": 123
        }
    });

    // Parse to IR
    let ir = sb_config::validator::v2::to_ir_v1(&json);

    // Build resolver from IR
    let resolver =
        sb_core::dns::config_builder::resolver_from_ir(&ir).expect("build resolver from ir");

    // Hosts overlay should resolve without using network
    let ans = resolver
        .resolve("unit.test.local")
        .await
        .expect("resolve host");
    assert!(ans.ips.iter().any(|ip| ip.is_ipv4()));
    assert_eq!(ans.ttl.as_secs(), 123);

    // Also verify that when rules exist, the resolver type becomes rule engine
    let json_rules = serde_json::json!({
        "dns": {
            "servers": [ {"tag": "system", "address": "system"} ],
            "default": "system",
            "rules": [ {"domain_suffix": ["example.com"], "server": "system"} ]
        }
    });
    let ir2 = sb_config::validator::v2::to_ir_v1(&json_rules);
    let resolver2 = sb_core::dns::config_builder::resolver_from_ir(&ir2)
        .expect("build resolver from ir with rules");
    // name() should be "dns_rule_engine" per EngineResolver
    assert_eq!(resolver2.name(), "dns_rule_engine");
}

#[cfg(all(
    feature = "dns_dhcp",
    feature = "dns_resolved",
    feature = "dns_tailscale"
))]
#[tokio::test]
async fn dns_ir_builds_with_dhcp_resolved_tailscale_servers() {
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            EnvGuard { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = &self.prev {
                std::env::set_var(self.key, prev);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    // Prepare synthetic resolv.conf files for DHCP/resolved upstream discovery.
    let mut dhcp_file = NamedTempFile::new().unwrap();
    writeln!(dhcp_file, "nameserver 127.0.0.1").unwrap();
    let _dhcp_env = EnvGuard::set(
        "SB_DNS_DHCP_RESOLV_CONF",
        dhcp_file.path().to_str().unwrap(),
    );

    let mut resolved_file = NamedTempFile::new().unwrap();
    writeln!(resolved_file, "nameserver 127.0.0.53").unwrap();
    let resolved_spec = format!("resolved://?resolv={}", resolved_file.path().display());

    let json = serde_json::json!({
        "dns": {
            "servers": [
                {"tag": "ts", "address": "tailscale://127.0.0.2:5353"},
                {"tag": "dh", "address": "dhcp://"},
                {"tag": "rs", "address": resolved_spec},
            ],
            "default": "ts"
        }
    });

    let ir = sb_config::validator::v2::to_ir_v1(&json);
    let resolver = sb_core::dns::config_builder::resolver_from_ir(&ir)
        .expect("build resolver with dhcp/resolved/tailscale upstreams");

    // With no rules, resolver should be the base dns_ir resolver.
    assert_eq!(resolver.name(), "dns_ir");
}
