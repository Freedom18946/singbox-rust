#![cfg(feature = "dns_dhcp")]

use std::io::Write as _;

use sb_core::dns::{transport::DhcpResolver, Resolver};
use tempfile::NamedTempFile;

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, prev }
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

#[tokio::test]
async fn dhcp_resolver_falls_back_to_system_when_empty() {
    // Use an empty resolv.conf to force DHCP upstream to delegate to the system resolver.
    let mut resolv = NamedTempFile::new().expect("create temp resolv.conf");
    writeln!(resolv, "# no nameserver entries for test").unwrap();
    let _guard = EnvGuard::set(
        "SB_DNS_DHCP_RESOLV_CONF",
        resolv.path().to_str().expect("path to str"),
    );

    let resolver = DhcpResolver::new();
    let answer = resolver
        .resolve("localhost")
        .await
        .expect("resolve localhost via DHCP resolver");

    assert_eq!(resolver.name(), "dhcp");
    assert!(
        !answer.ips.is_empty(),
        "DHCP resolver should return at least one IP (system fallback)"
    );
}
