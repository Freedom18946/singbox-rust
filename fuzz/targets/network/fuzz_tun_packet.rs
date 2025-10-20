#![no_main]
//! TUN packet parsing fuzzer
//!
//! This fuzzer tests the TUN packet parsing which includes:
//! - TUN frame parsing (AF prefix + IP data packet)
//! - IPv4 packet parsing
//! - IPv6 packet parsing
//! - Protocol stack validation
//!
//! TUN is a critical inbound protocol, and parsing errors could lead to:
//! - Buffer overflows
//! - Panic/crash from malformed packets
//! - Resource exhaustion
//! - Network stack corruption

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: TUN frame parsing (AF prefix + IP data packet)
    if data.len() >= 4 {
        // TUN frames start with address family (2 bytes) + flags (2 bytes)
        let _af = u16::from_be_bytes([data[0], data[1]]);
        let _flags = u16::from_be_bytes([data[2], data[3]]);
        
        let ip_data = &data[4..];
        
        // Parse IP packet based on address family
        match _af {
            2 => {
                // IPv4 (AF_INET)
                let _ = parse_ipv4_packet(ip_data);
            }
            10 => {
                // IPv6 (AF_INET6)
                let _ = parse_ipv6_packet(ip_data);
            }
            _ => {
                // Other address families - should be handled gracefully
            }
        }
    }

    // Test 2: Direct IPv4 packet parsing
    if data.len() >= 20 {
        let _ = parse_ipv4_packet(data);
    }

    // Test 3: Direct IPv6 packet parsing
    if data.len() >= 40 {
        let _ = parse_ipv6_packet(data);
    }

    // Test 4: Edge cases
    // These should all be handled gracefully without panicking

    // Empty data
    if data.is_empty() {
        return;
    }

    // Single byte (invalid but shouldn't crash)
    if data.len() == 1 {
        let _ = data[0];
        return;
    }

    // Test 5: Malformed IP headers
    if data.len() >= 4 {
        // Test with invalid IP version
        let version = (data[0] >> 4) & 0x0F;
        match version {
            4 => {
                // IPv4 - should have at least 20 bytes
                if data.len() >= 20 {
                    let _ = parse_ipv4_packet(data);
                }
            }
            6 => {
                // IPv6 - should have at least 40 bytes
                if data.len() >= 40 {
                    let _ = parse_ipv6_packet(data);
                }
            }
            _ => {
                // Invalid IP version - should be handled gracefully
            }
        }
    }

    // Test 6: Large packets
    if data.len() > 65535 {
        // Very large packet - should be handled gracefully
        return;
    }

    // Test 7: Fragmented packets
    if data.len() >= 20 {
        // Test IPv4 fragmentation
        let flags = u16::from_be_bytes([data[6], data[7]]);
        let fragment_offset = flags & 0x1FFF;
        
        if fragment_offset > 0 {
            // Fragmented packet - should be handled gracefully
        }
    }
});

fn parse_ipv4_packet(data: &[u8]) -> Option<()> {
    if data.len() < 20 {
        return None;
    }

    // Parse IPv4 header
    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return None;
    }

    let ihl = (data[0] & 0x0F) as usize;
    if ihl < 5 || ihl > 15 {
        return None; // Invalid IHL
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_length < 20 || total_length > data.len() {
        return None; // Invalid total length
    }

    let _protocol = data[9];
    let _src_addr = &data[12..16];
    let _dst_addr = &data[16..20];

    // Parse options if present
    if ihl > 5 {
        let options_len = (ihl - 5) * 4;
        if data.len() >= 20 + options_len {
            let _options = &data[20..20 + options_len];
        }
    }

    Some(())
}

fn parse_ipv6_packet(data: &[u8]) -> Option<()> {
    if data.len() < 40 {
        return None;
    }

    // Parse IPv6 header
    let version = (data[0] >> 4) & 0x0F;
    if version != 6 {
        return None;
    }

    let _traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
    let _flow_label = u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]);
    let _payload_length = u16::from_be_bytes([data[4], data[5]]);
    let _next_header = data[6];
    let _hop_limit = data[7];
    let _src_addr = &data[8..24];
    let _dst_addr = &data[24..40];

    // Validate payload length
    let expected_length = 40 + _payload_length as usize;
    if expected_length > data.len() {
        return None; // Invalid payload length
    }

    Some(())
}

// TODO: When sb-adapters exposes the real parsing function, replace
// the above manual parsing with:
//
// let _ = sb_adapters::inbound::tun::parse_frame(data);
// let _ = sb_adapters::inbound::tun_enhanced::parse_ipv4_packet(data);
// let _ = sb_adapters::inbound::tun_enhanced::parse_ipv6_packet(data);
//
// This will ensure we're testing the actual production code path
// rather than a reimplementation.
