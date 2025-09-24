use sb_core::net::ratelimit::maybe_drop_udp;

#[test]
#[ignore = "env-sensitive (global OnceLock); run in isolation"]
fn ratelimit_bps_pps_basic() {
    // configure low limits
    std::env::set_var("SB_UDP_OUTBOUND_BPS_MAX", "100"); // ~10 bytes per 100ms slice
    std::env::set_var("SB_UDP_OUTBOUND_PPS_MAX", "2"); // 2 pkts per slice
                                                       // ensure we start at a fresh slice
    std::thread::sleep(std::time::Duration::from_millis(120));
    // First packet 8 bytes: ok
    assert_eq!(maybe_drop_udp(8), None);
    // Second packet 8 bytes: pps hits 2 → this is allowed (second)
    assert_eq!(maybe_drop_udp(8), None);
    // Third packet should hit pps
    assert_eq!(maybe_drop_udp(1), Some("pps"));
}

#[test]
#[ignore = "env-sensitive (global OnceLock); run in isolation"]
fn ratelimit_rollover_and_burst_after_idle() {
    std::env::set_var("SB_UDP_OUTBOUND_BPS_MAX", "100");
    std::env::set_var("SB_UDP_OUTBOUND_PPS_MAX", "0");
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert_eq!(maybe_drop_udp(12), Some("bps")); // over 10 bytes slice
                                                 // sleep to next slice
    std::thread::sleep(std::time::Duration::from_millis(120));
    // Now should pass
    assert_eq!(maybe_drop_udp(8), None);
}
