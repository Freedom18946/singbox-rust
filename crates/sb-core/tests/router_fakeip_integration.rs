#![cfg(feature = "router")]
#![allow(clippy::await_holding_lock)]

use sb_core::dns::fakeip;
use sb_core::router::RouterHandle;
use sb_core::runtime_options::{DnsRuntimeOptions, RouterRuntimeOptions};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

fn serial_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn configure_fakeip(enabled: bool) {
    let mut ir = sb_config::ir::DnsIR::default();
    ir.fakeip_enabled = None;
    fakeip::configure(
        &ir,
        &DnsRuntimeOptions {
            fakeip_enabled: enabled,
            fakeip_v4_base: "198.18.0.0".parse().unwrap(),
            fakeip_v4_mask: 16,
            fakeip_v6_base: "fd00::".parse().unwrap(),
            fakeip_v6_mask: 8,
            ..Default::default()
        },
    );
}

fn router(rules: &str) -> RouterHandle {
    RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules.replace(',', "\n"),
        ..Default::default()
    }))
}

#[tokio::test]
async fn test_fakeip_routing_domain_exact_match() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v4("google.com");
    assert!(fakeip::is_fake_ip(&fake_ip));
    assert_eq!(
        router("exact:google.com=proxy")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "proxy"
    );
}

#[tokio::test]
async fn test_fakeip_routing_domain_suffix_match() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v4("maps.google.com");
    assert_eq!(
        router("suffix:.google.com=proxy")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "proxy"
    );
}

#[tokio::test]
async fn test_fakeip_routing_fallback_to_ip_rules() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v4("unknown.example.com");
    assert_eq!(
        router("cidr4:198.18.0.0/16=block")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "block"
    );
}

#[tokio::test]
async fn test_fakeip_routing_domain_priority() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v4("priority.test.com");
    assert_eq!(
        router("exact:priority.test.com=proxy,cidr4:198.18.0.0/16=direct")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "proxy"
    );
}

#[tokio::test]
async fn test_fakeip_routing_disabled() {
    let _guard = serial_guard();
    configure_fakeip(false);
    let fake_ip = fakeip::allocate_v4("test.com");
    assert_eq!(
        router("exact:test.com=proxy,cidr4:198.18.0.0/16=block")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "block"
    );
}

#[tokio::test]
async fn test_fakeip_routing_ipv6() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v6("ipv6test.com");
    assert_eq!(
        router("exact:ipv6test.com=proxy")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "proxy"
    );
}

#[tokio::test]
async fn test_fakeip_routing_real_ip_no_false_positive() {
    let _guard = serial_guard();
    configure_fakeip(true);
    assert_eq!(
        router("exact:realip.com=proxy,cidr4:8.8.8.0/24=block")
            .decide_udp_async("8.8.8.8")
            .await,
        "block"
    );
}

#[tokio::test]
async fn test_fakeip_routing_multiple_domains_same_rule() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let router = router("suffix:.cdn.com=proxy");
    for domain in ["img.cdn.com", "static.cdn.com", "api.cdn.com"] {
        let fake_ip = fakeip::allocate_v4(domain);
        assert_eq!(router.decide_udp_async(&fake_ip.to_string()).await, "proxy");
    }
}

#[tokio::test]
async fn test_fakeip_routing_no_domain_rules_default() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v4("noroute.example.com");
    assert_eq!(
        router("").decide_udp_async(&fake_ip.to_string()).await,
        "unresolved"
    );
}

#[tokio::test]
async fn test_fakeip_routing_case_insensitive() {
    let _guard = serial_guard();
    configure_fakeip(true);
    let fake_ip = fakeip::allocate_v4("EXAMPLE.COM");
    assert_eq!(
        router("exact:example.com=proxy")
            .decide_udp_async(&fake_ip.to_string())
            .await,
        "proxy"
    );
}
