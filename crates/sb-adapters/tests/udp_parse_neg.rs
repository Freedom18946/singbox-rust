#![cfg(feature = "socks")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use sb_adapters::inbound::socks::udp::{parse_udp_datagram, ParseError};

#[test]
fn rsv_or_frag_nonzero_is_bad() {
    let bad = [0x00, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 53, 0xaa];
    assert!(matches!(
        parse_udp_datagram(&bad),
        Err(ParseError::BadRsvFrag)
    ));
    let bad2 = [0x00, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0, 53, 0xaa];
    assert!(matches!(
        parse_udp_datagram(&bad2),
        Err(ParseError::BadRsvFrag)
    ));
}

#[test]
fn too_short_truncated() {
    let bad = [0x00, 0x00, 0x00]; // < 4
    assert!(matches!(
        parse_udp_datagram(&bad),
        Err(ParseError::Truncated)
    ));
}

#[test]
fn v4_truncated() {
    // RSV/FRAG/ATYP(v4) + only 3 bytes of v4
    let bad = [0x00, 0x00, 0x00, 0x01, 1, 2, 3];
    assert!(matches!(
        parse_udp_datagram(&bad),
        Err(ParseError::Truncated)
    ));
}

#[test]
fn domain_len_too_large() {
    // domain len=5 but only 3 bytes given
    let bad = [0x00, 0x00, 0x00, 0x03, 5, b'a', b'b', b'c'];
    assert!(matches!(
        parse_udp_datagram(&bad),
        Err(ParseError::BadDomainLen)
    ));
}

#[test]
fn v6_truncated() {
    // ATYP=0x04 but less than 16+2 bytes remain
    let mut bad = vec![0x00, 0x00, 0x00, 0x04];
    bad.resize(4 + 10, 0);
    assert!(matches!(
        parse_udp_datagram(&bad),
        Err(ParseError::Truncated)
    ));
}
