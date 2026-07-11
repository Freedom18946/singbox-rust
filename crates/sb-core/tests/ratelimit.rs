use sb_core::net::ratelimit::UdpRateLimiter;
use sb_core::runtime_options::NetworkRuntimeOptions;

#[test]
fn ratelimit_bps_pps_basic() {
    let options = NetworkRuntimeOptions {
        udp_outbound_bytes_per_second: 100,
        udp_outbound_packets_per_second: 20,
        ..NetworkRuntimeOptions::default()
    };
    let limiter = UdpRateLimiter::from_options(&options);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert_eq!(limiter.maybe_drop_udp(4), None);
    assert_eq!(limiter.maybe_drop_udp(4), None);
    assert_eq!(limiter.maybe_drop_udp(1), Some("pps"));
}

#[test]
fn ratelimit_rollover_and_burst_after_idle() {
    let options = NetworkRuntimeOptions {
        udp_outbound_bytes_per_second: 100,
        ..NetworkRuntimeOptions::default()
    };
    let limiter = UdpRateLimiter::from_options(&options);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert_eq!(limiter.maybe_drop_udp(12), Some("bps"));
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert_eq!(limiter.maybe_drop_udp(8), None);
}
