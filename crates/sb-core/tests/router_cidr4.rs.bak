use sb_core::net::datagram::UdpTargetAddr;
use sb_core::router;

#[test]
#[ignore = "env-sensitive; run with RUST_TEST_THREADS=1 if needed"]
fn cidr4_basic_match_and_miss() {
    std::env::remove_var("SB_ROUTER_UDP");
    std::env::remove_var("SB_ROUTER_UDP_RULES");
    let h = router::RouterHandle::new_for_tests();
    // 默认 direct
    let d = UdpTargetAddr::Ip("10.1.2.3:53".parse().unwrap());
    assert_eq!(h.decide_udp(&d), "direct");

    std::env::set_var("SB_ROUTER_UDP", "1");
    std::env::set_var(
        "SB_ROUTER_UDP_RULES",
        "cidr4:10.0.0.0/8=reject,default=direct",
    );
    assert_eq!(h.decide_udp(&d), "reject");

    let e = UdpTargetAddr::Ip("11.0.0.1:53".parse().unwrap());
    assert_eq!(h.decide_udp(&e), "direct");
}

#[test]
#[ignore = "env-sensitive; run with RUST_TEST_THREADS=1 if needed"]
fn cidr4_illegal_ignored() {
    std::env::set_var("SB_ROUTER_UDP", "1");
    std::env::set_var("SB_ROUTER_UDP_RULES", "cidr4:bad/xx=reject,default=direct");
    let h = router::RouterHandle::new_for_tests();
    let x = UdpTargetAddr::Ip("10.0.0.1:1".parse().unwrap());
    assert_eq!(h.decide_udp(&x), "direct");
}

#[test]
#[ignore = "env-sensitive; run with RUST_TEST_THREADS=1 if needed"]
fn cidr4_priority_with_exact() {
    std::env::set_var("SB_ROUTER_UDP", "1");
    std::env::set_var(
        "SB_ROUTER_UDP_RULES",
        "exact:10.1.2.3=proxy,cidr4:10.0.0.0/8=reject,default=direct",
    );
    let h = router::RouterHandle::new_for_tests();
    let ip = UdpTargetAddr::Ip("10.1.2.3:9999".parse().unwrap());
    assert_eq!(h.decide_udp(&ip), "proxy");
}
