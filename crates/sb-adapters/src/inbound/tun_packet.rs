//! IP packet construction utilities for TUN
//!
//! Provides utilities to construct IP/TCP/UDP packets for writing back to TUN interface.
//!
//! NOTE: Skeleton/WIP code - warnings suppressed.
#![allow(unused, dead_code, clippy::too_many_arguments)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Construct an IPv4 TCP packet
pub fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let ip_header_len = 20;
    let tcp_header_len = 20;
    let total_len = ip_header_len + tcp_header_len + payload.len();

    let mut packet = vec![0u8; total_len];

    // IPv4 Header (20 bytes)
    packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00; // DSCP, ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // Total length
    packet[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
    packet[6..8].copy_from_slice(&[0x40, 0x00]); // Flags: Don't Fragment
    packet[8] = 64; // TTL
    packet[9] = 6; // Protocol: TCP
                   // Checksum at 10-11 will be calculated later
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    // Calculate IP checksum
    let ip_checksum = calculate_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // TCP Header (20 bytes minimum)
    let tcp_offset = ip_header_len;
    packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
    packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&ack.to_be_bytes());
    packet[tcp_offset + 12] = 0x50; // Data offset: 5 (20 bytes), Reserved: 0
    packet[tcp_offset + 13] = flags; // Flags
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&65535u16.to_be_bytes()); // Window size
                                                                                       // Checksum at tcp_offset + 16..18 calculated later
    packet[tcp_offset + 18..tcp_offset + 20].copy_from_slice(&[0x00, 0x00]); // Urgent pointer

    // Copy payload
    if !payload.is_empty() {
        packet[tcp_offset + tcp_header_len..].copy_from_slice(payload);
    }

    // Calculate TCP checksum (with pseudo-header)
    let tcp_checksum = calculate_tcp_checksum_ipv4(src_ip, dst_ip, &packet[tcp_offset..]);
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    packet
}

/// Construct an IPv4 UDP packet
pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_header_len = 20;
    let udp_header_len = 8;
    let total_len = ip_header_len + udp_header_len + payload.len();

    let mut packet = vec![0u8; total_len];

    // IPv4 Header
    packet[0] = 0x45;
    packet[1] = 0x00;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&[0x00, 0x00]);
    packet[6..8].copy_from_slice(&[0x40, 0x00]);
    packet[8] = 64; // TTL
    packet[9] = 17; // Protocol: UDP
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let ip_checksum = calculate_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // UDP Header
    let udp_offset = ip_header_len;
    let udp_len = (udp_header_len + payload.len()) as u16;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&[0x00, 0x00]); // Checksum (optional for IPv4)

    // Copy payload
    if !payload.is_empty() {
        packet[udp_offset + udp_header_len..].copy_from_slice(payload);
    }

    packet
}

/// Construct an IPv6 TCP packet (bare IP, no platform AF prefix).
///
/// The macOS utun `write` path prepends the 4-byte protocol-family header itself
/// (see `sb-platform/src/tun/macos.rs`), so this must emit a raw IP packet.
pub fn build_ipv6_tcp_packet(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let ip_header_len = 40;
    let tcp_header_len = 20;
    let upper_len = tcp_header_len + payload.len();
    let total_len = ip_header_len + upper_len;

    let mut packet = vec![0u8; total_len];

    // IPv6 Header (40 bytes)
    packet[0] = 0x60; // Version 6, traffic class high nibble 0
                      // packet[1..4] traffic class low / flow label = 0
    packet[4..6].copy_from_slice(&(upper_len as u16).to_be_bytes()); // Payload length
    packet[6] = 6; // Next header: TCP
    packet[7] = 64; // Hop limit
    packet[8..24].copy_from_slice(&src_ip.octets());
    packet[24..40].copy_from_slice(&dst_ip.octets());

    // TCP Header (20 bytes)
    let tcp_offset = ip_header_len;
    packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
    packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&ack.to_be_bytes());
    packet[tcp_offset + 12] = 0x50; // Data offset: 5 (20 bytes)
    packet[tcp_offset + 13] = flags;
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&65535u16.to_be_bytes()); // Window
    packet[tcp_offset + 18..tcp_offset + 20].copy_from_slice(&[0x00, 0x00]); // Urgent pointer

    if !payload.is_empty() {
        packet[tcp_offset + tcp_header_len..].copy_from_slice(payload);
    }

    // TCP checksum (mandatory for IPv6) with IPv6 pseudo-header
    let tcp_checksum = calculate_tcp_checksum_ipv6(src_ip, dst_ip, &packet[tcp_offset..]);
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    packet
}

/// Construct an IPv6 UDP packet (bare IP, no platform AF prefix).
pub fn build_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let ip_header_len = 40;
    let udp_header_len = 8;
    let upper_len = udp_header_len + payload.len();
    let total_len = ip_header_len + upper_len;

    let mut packet = vec![0u8; total_len];

    // IPv6 Header
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(upper_len as u16).to_be_bytes());
    packet[6] = 17; // Next header: UDP
    packet[7] = 64; // Hop limit
    packet[8..24].copy_from_slice(&src_ip.octets());
    packet[24..40].copy_from_slice(&dst_ip.octets());

    // UDP Header
    let udp_offset = ip_header_len;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(upper_len as u16).to_be_bytes());
    // Checksum at udp_offset + 6..8 calculated below

    if !payload.is_empty() {
        packet[udp_offset + udp_header_len..].copy_from_slice(payload);
    }

    // UDP checksum is mandatory for IPv6; 0 must be transmitted as 0xFFFF.
    let mut udp_checksum = calculate_udp_checksum_ipv6(src_ip, dst_ip, &packet[udp_offset..]);
    if udp_checksum == 0 {
        udp_checksum = 0xFFFF;
    }
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    packet
}

/// Calculate Internet checksum (RFC 1071)
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() - 1 {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Add remaining byte if odd length
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Calculate TCP checksum with IPv4 pseudo-header
fn calculate_tcp_checksum_ipv4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + tcp_segment.len());

    // Pseudo-header
    pseudo_header.extend_from_slice(&src_ip.octets());
    pseudo_header.extend_from_slice(&dst_ip.octets());
    pseudo_header.push(0); // Reserved
    pseudo_header.push(6); // Protocol (TCP)
    pseudo_header.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());

    // TCP segment (with checksum field zeroed)
    pseudo_header.extend_from_slice(tcp_segment);

    // Zero out checksum field before calculation
    if pseudo_header.len() >= 28 {
        pseudo_header[28] = 0;
        pseudo_header[29] = 0;
    }

    calculate_checksum(&pseudo_header)
}

/// Build an IPv6 upper-layer pseudo-header (RFC 8200 §8.1) prefixing `segment`.
///
/// Layout: src(16) + dst(16) + upper_layer_length(4, big-endian) + zero(3) + next_header(1).
fn ipv6_pseudo_header(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    next_header: u8,
    segment: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40 + segment.len());
    buf.extend_from_slice(&src_ip.octets());
    buf.extend_from_slice(&dst_ip.octets());
    buf.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0]); // Reserved
    buf.push(next_header);
    buf.extend_from_slice(segment);
    buf
}

/// Calculate TCP checksum with IPv6 pseudo-header
fn calculate_tcp_checksum_ipv6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, tcp_segment: &[u8]) -> u16 {
    let mut buf = ipv6_pseudo_header(src_ip, dst_ip, 6, tcp_segment);

    // Zero out the TCP checksum field (offset 16 within the segment → 40 + 16).
    if buf.len() >= 40 + 18 {
        buf[40 + 16] = 0;
        buf[40 + 17] = 0;
    }

    calculate_checksum(&buf)
}

/// Calculate UDP checksum with IPv6 pseudo-header
fn calculate_udp_checksum_ipv6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, udp_segment: &[u8]) -> u16 {
    let mut buf = ipv6_pseudo_header(src_ip, dst_ip, 17, udp_segment);

    // Zero out the UDP checksum field (offset 6 within the segment → 40 + 6).
    if buf.len() >= 40 + 8 {
        buf[40 + 6] = 0;
        buf[40 + 7] = 0;
    }

    calculate_checksum(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_calculation() {
        // Test with known data
        let data = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let _checksum = calculate_checksum(&data);
    }

    #[test]
    fn test_tcp_packet_construction() {
        let src_ip = "192.168.1.2".parse().unwrap();
        let dst_ip = "93.184.216.34".parse().unwrap();
        let packet = build_ipv4_tcp_packet(
            src_ip,
            12345,
            dst_ip,
            80,
            b"GET / HTTP/1.1\r\n",
            1000,
            2000,
            0x18, // PSH+ACK
        );

        // Verify packet structure
        assert_eq!(packet[0], 0x45); // IPv4, IHL=5
        assert_eq!(packet[9], 6); // TCP protocol
        assert!(packet.len() >= 40); // Min IP+TCP headers
    }

    #[test]
    fn test_ipv4_udp_checksum_is_zero() {
        let src: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let dst: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let packet = build_ipv4_udp_packet(src, 5000, dst, 53, b"\x00\x01query");
        assert_eq!(packet[9], 17); // UDP protocol
                                   // IPv4 UDP checksum is optional and emitted as 0.
        assert_eq!(&packet[20 + 6..20 + 8], &[0x00, 0x00]);
        // Length field = udp header + payload
        assert_eq!(
            u16::from_be_bytes([packet[20 + 4], packet[20 + 5]]) as usize,
            8 + b"\x00\x01query".len()
        );
    }

    #[test]
    fn test_ipv6_tcp_packet_construction_and_checksum() {
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let payload = b"GET / HTTP/1.1\r\n";
        let packet = build_ipv6_tcp_packet(src, 40000, dst, 443, payload, 111, 222, 0x12);

        assert_eq!(packet[0] >> 4, 6); // Version 6
        assert_eq!(packet[6], 6); // Next header TCP
        assert_eq!(packet.len(), 40 + 20 + payload.len());
        // Payload length field
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]) as usize,
            20 + payload.len()
        );
        // Recomputing the checksum over the segment WITH the checksum in place yields 0.
        let segment = &packet[40..];
        let verify = calculate_checksum(&ipv6_pseudo_header(src, dst, 6, segment));
        assert_eq!(verify, 0, "IPv6 TCP checksum must verify to 0");
    }

    #[test]
    fn test_ipv6_udp_packet_construction_and_checksum() {
        let src: Ipv6Addr = "fd00::2".parse().unwrap();
        let dst: Ipv6Addr = "2606:4700::1111".parse().unwrap();
        let payload = b"\xde\xad\xbe\xef";
        let packet = build_ipv6_udp_packet(src, 5353, dst, 53, payload);

        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(packet[6], 17); // Next header UDP
        assert_eq!(packet.len(), 40 + 8 + payload.len());
        // IPv6 UDP checksum is mandatory and must be non-zero.
        assert_ne!(&packet[40 + 6..40 + 8], &[0x00, 0x00]);
        let segment = &packet[40..];
        let verify = calculate_checksum(&ipv6_pseudo_header(src, dst, 17, segment));
        assert_eq!(verify, 0, "IPv6 UDP checksum must verify to 0");
    }
}
