#![cfg(feature = "router")]
use sb_core::net::datagram::UdpTargetAddr;
use sb_core::router::{self};
use std::sync::{Mutex, OnceLock};

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn router_udp_rules_default_direct() {
    let _g = TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    // Ensure clean env to avoid leakage from other tests
    std::env::remove_var("SB_ROUTER_UDP");
    std::env::remove_var("SB_ROUTER_UDP_RULES");
    // 不设置 env，默认 direct
    let h = router::RouterHandle::new_for_tests(); // 若无此构造，可改为 router::RouterHandle::default()
    let d = UdpTargetAddr::Domain {
        host: "foo.bar".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&d), "direct");
}

#[test]
fn router_udp_rules_env_parsing() {
    let _g = TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    // Clean then set
    std::env::remove_var("SB_ROUTER_UDP");
    std::env::remove_var("SB_ROUTER_UDP_RULES");
    std::env::remove_var("SB_TEST_USE_ENV");
    std::env::set_var("SB_ROUTER_UDP", "1");
    std::env::set_var(
        "SB_ROUTER_UDP_RULES",
        "exact:foo.bar=proxy,suffix:.example.com=reject,default=direct",
    );
    // Instruct RouterHandle::new_for_tests to snapshot env for this test
    std::env::set_var("SB_TEST_USE_ENV", "1");
    let h = router::RouterHandle::new_for_tests();
    let x = UdpTargetAddr::Domain {
        host: "foo.bar".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&x), "proxy");
    let y = UdpTargetAddr::Domain {
        host: "api.example.com".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&y), "reject");
    let z = UdpTargetAddr::Domain {
        host: "unknown.tld".into(),
        port: 53,
    };
    assert_eq!(h.decide_udp(&z), "direct");
    // Cleanup to not affect other tests
    std::env::remove_var("SB_ROUTER_UDP");
    std::env::remove_var("SB_ROUTER_UDP_RULES");
    std::env::remove_var("SB_TEST_USE_ENV");
}
