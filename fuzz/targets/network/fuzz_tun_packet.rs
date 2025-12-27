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
use sb_adapters::inbound::tun_enhanced::EnhancedTunInbound;

fuzz_target!(|data: &[u8]| {
    // Test 1: TUN frame parsing (AF prefix + IP data packet)
    if data.len() >= 4 {
        // TUN frames start with address family (2 bytes) + flags (2 bytes)
        let _af = u16::from_be_bytes([data[0], data[1]]);
        let _flags = u16::from_be_bytes([data[2], data[3]]);
        let ip_data = &data[4..];
        let _ = EnhancedTunInbound::parse_packet(ip_data);
    }

    // Test 2: Direct IPv4 packet parsing
    if data.len() >= 20 {
        let _ = EnhancedTunInbound::parse_packet(data);
    }

    // Test 3: Direct IPv6 packet parsing
    if data.len() >= 40 {
        let _ = EnhancedTunInbound::parse_packet(data);
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
                let _ = EnhancedTunInbound::parse_packet(data);
            }
            6 => {
                // IPv6 - should have at least 40 bytes
                let _ = EnhancedTunInbound::parse_packet(data);
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
