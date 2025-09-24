use sb_core::net::datagram::UdpTargetAddr;
use sb_core::router;
use std::env;

fn main() {
    env::set_var("RUST_LOG", "info");
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: router_rules_probe <host> [SB_ROUTER_UDP_RULES=...]");
        return;
    }
    let host = args[1].clone();
    if args.len() >= 3 {
        env::set_var("SB_ROUTER_UDP_RULES", &args[2]);
    }
    env::set_var("SB_ROUTER_UDP", "1");
    let h = router::RouterHandle::new_for_tests();
    let d = UdpTargetAddr::Domain { host, port: 53 };
    let dec = h.decide_udp(&d);
    println!("decision={}", dec);
}
