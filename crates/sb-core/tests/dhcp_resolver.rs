#![cfg(feature = "dns_dhcp")]

use sb_core::dns::{transport::DhcpResolver, Resolver};

#[tokio::test]
async fn dhcp_resolver_falls_back_to_system_when_empty() {
    // Use an empty resolv.conf to force DHCP upstream to delegate to the system resolver.
    // A numeric loopback keeps this fallback contract independent of host DNS availability.
    let resolv = tempfile::NamedTempFile::new().expect("create empty resolv.conf");
    let spec = format!("dhcp://{}", resolv.path().display());

    let resolver = DhcpResolver::from_spec(&spec).expect("create DHCP resolver from temp path");
    let answer = resolver
        .resolve("127.0.0.1")
        .await
        .expect("resolve numeric loopback via DHCP resolver");

    assert_eq!(resolver.name(), "dhcp");
    assert!(
        answer.ips.contains(&"127.0.0.1".parse().unwrap()),
        "DHCP resolver should return loopback through system fallback"
    );
}
