#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // fuzz SOCKS5 UDP header parsers
    let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
    #[cfg(any())]
    {
        let _ = sb_adapters::inbound::socks::udp_enhanced::parse_socks5_udp_header(data);
    }
});

