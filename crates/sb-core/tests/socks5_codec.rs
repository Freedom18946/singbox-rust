use sb_core::socks5::{decode_udp_reply, encode_udp_request};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn encode_v4() {
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let p = b"hello";
    let out = encode_udp_request(&dst, p);
    // RSV RSV FRAG ATYP(1) + 4 + 2 + DATA
    assert_eq!(out[0..3], [0, 0, 0]);
    assert_eq!(out[3], 0x01);
    assert_eq!(&out[4..8], &[8, 8, 8, 8]);
    assert_eq!(&out[8..10], &53u16.to_be_bytes());
    assert_eq!(&out[10..], p);
}

#[test]
fn encode_v6() {
    let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 853);
    let p = b"tls";
    let out = encode_udp_request(&dst, p);
    assert_eq!(out[0..3], [0, 0, 0]);
    assert_eq!(out[3], 0x04);
    assert_eq!(&out[4..20], &Ipv6Addr::LOCALHOST.octets());
    assert_eq!(&out[20..22], &853u16.to_be_bytes());
    assert_eq!(&out[22..], p);
}

#[test]
fn decode_v4_ok() {
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9999);
    let p = b"aaaa";
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0, 0, 0, 0x01, 1, 2, 3, 4]);
    buf.extend_from_slice(&9999u16.to_be_bytes());
    buf.extend_from_slice(p);
    let (got, body) = decode_udp_reply(&buf).unwrap();
    assert_eq!(got, dst);
    assert_eq!(body, p);
}

#[test]
fn decode_v6_ok() {
    let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
    let p = b"bbb";
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0, 0, 0, 0x04]);
    buf.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(p);
    let (got, body) = decode_udp_reply(&buf).unwrap();
    assert_eq!(got, dst);
    assert_eq!(body, p);
}

#[test]
fn decode_frag_unsupported() {
    // FRAG != 0
    let mut buf = vec![0, 0, 1, 0x01, 127, 0, 0, 1, 9, 9];
    buf.extend_from_slice(b"x");
    assert!(decode_udp_reply(&buf).is_err());
}

#[test]
fn decode_truncated() {
    // too short
    assert!(decode_udp_reply(&[0, 0]).is_err());
    // ATYP missing tail
    assert!(decode_udp_reply(&[0, 0, 0, 0x01, 1, 2, 3]).is_err());
}
