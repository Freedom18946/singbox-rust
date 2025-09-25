#![cfg(feature = "socks")]

use proptest::prelude::*;

// Property: random bytes for SOCKS5 UDP parse never panic
proptest! {
    #[test]
    fn random_bytes_do_not_panic_udp_parse(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(&data);
    }
}

// Property: invalid DOMAIN length is rejected
#[test]
fn invalid_domain_length_rejected() {
    // RSV/FRAG ok + ATYP=0x03 (DOMAIN), len=10 but only 5 bytes of domain then port missing
    let mut buf = vec![0,0,0,0x03, 10];
    buf.extend_from_slice(b"short");
    let r = sb_adapters::inbound::socks::udp::parse_udp_datagram(&buf);
    assert!(r.is_err());
}

