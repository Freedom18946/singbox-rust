//! Registry coverage tests for adapter builders compiled into the app test profile.

use sb_core::adapter::registry;

const ALWAYS_OUTBOUNDS: &[&str] = &[
    "direct",
    "block",
    "dns",
    "tor",
    "anytls",
    "wireguard",
    "tailscale",
    "hysteria",
    "tuic",
    "hysteria2",
    "ssh",
    "shadowtls",
    "selector",
    "urltest",
];

const FEATURED_OUTBOUNDS: &[&str] = &[
    "http",
    "socks",
    "socks4",
    "shadowsocks",
    "shadowsocksr",
    "trojan",
    "vmess",
    "vless",
];

const ALWAYS_INBOUNDS: &[&str] = &[
    "naive",
    "shadowtls",
    "hysteria",
    "hysteria2",
    "tuic",
    "anytls",
    "direct",
];

const FEATURED_INBOUNDS: &[&str] = &["http", "socks", "shadowsocks", "vmess", "vless", "trojan"];

#[cfg(target_os = "linux")]
const PLATFORM_INBOUNDS: &[&str] = &["redirect", "tproxy"];

#[cfg(not(target_os = "linux"))]
const PLATFORM_INBOUNDS: &[&str] = &[];

fn setup() {
    sb_adapters::register_all();
}

fn expected_inbounds() -> Vec<&'static str> {
    let mut kinds = Vec::new();
    kinds.extend(ALWAYS_INBOUNDS);
    kinds.extend(FEATURED_INBOUNDS);
    kinds.extend(PLATFORM_INBOUNDS);

    if cfg!(feature = "adapters") {
        kinds.extend(["mixed", "dns"]);
    }
    if cfg!(any(
        feature = "adapters",
        feature = "adapter-ssh",
        feature = "ssh"
    )) {
        kinds.push("ssh");
    }
    if cfg!(any(
        feature = "adapters",
        feature = "adapter-tun",
        feature = "tun"
    )) {
        kinds.push("tun");
    }

    kinds
}

#[test]
fn compiled_outbound_builders_are_registered() {
    setup();

    for kind in ALWAYS_OUTBOUNDS.iter().chain(FEATURED_OUTBOUNDS) {
        assert!(
            registry::get_outbound(kind).is_some(),
            "missing outbound builder: {kind}"
        );
    }
}

#[test]
fn compiled_inbound_builders_are_registered() {
    setup();

    for kind in expected_inbounds() {
        assert!(
            registry::get_inbound(kind).is_some(),
            "missing inbound builder: {kind}"
        );
    }
}
