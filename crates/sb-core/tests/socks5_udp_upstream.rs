#![cfg(feature = "scaffold")]

use sb_core::outbound::socks5_udp::strip_udp_reply;

#[test]
fn strip_udp_reply_rejects_short_packet() {
    assert!(strip_udp_reply(&[0x00]).is_err());
    assert!(strip_udp_reply(&[0x00, 0x00, 0x01]).is_err());
}

#[test]
fn strip_udp_reply_parses_ipv4() {
    let payload = b"hello";
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
    pkt.push(0x01);
    pkt.extend_from_slice(&[127, 0, 0, 1]);
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(payload);

    let (addr, body) = strip_udp_reply(&pkt).expect("decode ipv4");
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert_eq!(addr.port(), 53);
    assert_eq!(body, payload);
}
