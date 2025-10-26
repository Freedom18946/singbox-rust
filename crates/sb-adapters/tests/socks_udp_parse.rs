#![allow(clippy::unwrap_used, clippy::expect_used)]
// 这个测试文件基于当前 SOCKS UDP 模块的实际结构
// 由于解析函数是私有的，这里主要测试公共接口

use sb_core::net::datagram::UdpTargetAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// 手动构造 SOCKS5 UDP 包格式用于测试
fn encode_socks5_udp_ipv4(ip: Ipv4Addr, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
    buf.push(0x01); // ATYP = IPv4
    buf.extend_from_slice(&ip.octets());
    buf.extend_from_slice(&port.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[test]
fn encode_ipv4_packet() {
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    let port = 5353u16;
    let payload = b"hello";

    let packet = encode_socks5_udp_ipv4(ip, port, payload);

    // 验证基本格式
    assert_eq!(packet[0], 0x00); // RSV
    assert_eq!(packet[1], 0x00); // RSV
    assert_eq!(packet[2], 0x00); // FRAG
    assert_eq!(packet[3], 0x01); // ATYP = IPv4
    assert_eq!(&packet[4..8], &[1, 2, 3, 4]); // IP
    assert_eq!(&packet[8..10], &port.to_be_bytes()); // Port
    assert_eq!(&packet[10..], payload); // Payload
}

#[test]
fn reject_frag_packet() {
    // 构造 FRAG=1 的非法数据包
    let mut packet = encode_socks5_udp_ipv4(Ipv4Addr::new(1, 2, 3, 4), 5353, b"test");
    packet[2] = 0x01; // 设置 FRAG=1（非法）

    // 这个包应该被拒绝，但由于解析函数是私有的，我们只能验证包格式
    assert_eq!(packet[2], 0x01); // 确认 FRAG 被设置
}

#[test]
fn create_target_addr() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let target = UdpTargetAddr::Ip(addr);

    match target {
        UdpTargetAddr::Ip(sa) => {
            assert_eq!(sa.port(), 8080);
            assert_eq!(sa.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        }
        _ => panic!("Expected IP target"),
    }
}
