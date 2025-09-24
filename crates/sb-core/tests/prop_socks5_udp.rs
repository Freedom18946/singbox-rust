use proptest::prelude::*;
use sb_core::socks5::{decode_udp_reply, encode_udp_request};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    // encode(request) → decode(reply) 在镜像场景下应当互逆
    #[test]
    fn roundtrip_v4(
        a in any::<[u8;4]>(),
        port in 1u16..65535,
        payload in prop::collection::vec(any::<u8>(), 0..1200)
    ) {
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port);
        let pkt = encode_udp_request(&dst, &payload);
        let (out, body) = decode_udp_reply(&pkt).unwrap();
        prop_assert_eq!(out, dst);
        prop_assert_eq!(body, &payload[..]);
    }

    #[test]
    fn roundtrip_v6(
        a in any::<[u8;16]>(),
        port in 1u16..65535,
        payload in prop::collection::vec(any::<u8>(), 0..1200)
    ) {
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port);
        let pkt = encode_udp_request(&dst, &payload);
        let (out, body) = decode_udp_reply(&pkt).unwrap();
        prop_assert_eq!(out, dst);
        prop_assert_eq!(body, &payload[..]);
    }
}

#[test]
fn frag_bit_rejected() {
    // 造一个合法包，再把 FRAG 改成非 0，期望 decode 报错
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let pkt = encode_udp_request(&dst, b"hello");
    let mut bad = pkt.clone();
    bad[2] = 1; // FRAG
    assert!(decode_udp_reply(&bad).is_err());
}
