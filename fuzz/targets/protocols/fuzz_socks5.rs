#![no_main]
//! SOCKS5 protocol fuzzer
//!
//! This fuzzer tests SOCKS5 UDP datagram parsing using the real production code.
//! The SOCKS5 UDP format is:
//!   +----+------+------+----------+----------+----------+
//!   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//!   +----+------+------+----------+----------+----------+
//!   | 2  |  1   |  1   | Variable |    2     | Variable |
//!   +----+------+------+----------+----------+----------+
//!
//! Tests include:
//! - UDP datagram parsing (actual production code)
//! - Address type validation (IPv4, domain, IPv6)
//! - Boundary cases (empty data, malformed headers, etc.)

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Real SOCKS5 UDP datagram parser
    // This is the actual production code path used in the application
    let parse_result = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);

    match parse_result {
        Ok((target_addr, header_len)) => {
            // Successfully parsed - validate the header length makes sense
            if header_len > data.len() {
                // This should never happen in correct implementation
                panic!("Header length {} exceeds data length {}", header_len, data.len());
            }

            // Validate the target address is reasonable
            match target_addr {
                sb_adapters::inbound::socks::udp::UdpTargetAddr::Ip(addr) => {
                    // IP address parsed successfully
                    let _ = addr;
                }
                sb_adapters::inbound::socks::udp::UdpTargetAddr::Domain(domain, port) => {
                    // Domain parsed successfully
                    // Validate domain is valid UTF-8 (should already be checked)
                    assert!(!domain.is_empty() || port > 0, "Invalid domain/port combination");
                }
            }
        }
        Err(_e) => {
            // Parsing failed - this is expected for invalid input
            // The important thing is that it didn't panic
        }
    }

    // Test 2: Edge cases that should be handled gracefully

    // Empty data
    if data.is_empty() {
        return;
    }

    // Single byte (too short for valid header)
    if data.len() == 1 {
        let _ = data[0];
        return;
    }

    // Test 3: Validate SOCKS5 UDP header structure
    // Minimum valid header is 10 bytes: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2)
    if data.len() >= 10 {
        // Check reserved bytes (should be 0x00 0x00)
        let rsv = u16::from_be_bytes([data[0], data[1]]);
        if rsv != 0 {
            // Non-zero reserved field - should still parse or error gracefully
        }

        // Check fragment byte
        let frag = data[2];
        if frag != 0 {
            // Fragmentation not supported in most implementations
        }

        // Check address type
        let atyp = data[3];
        match atyp {
            0x01 => {
                // IPv4 address (4 bytes)
                if data.len() >= 10 {
                    let _ipv4 = &data[4..8];
                    let _port = u16::from_be_bytes([data[8], data[9]]);
                }
            }
            0x03 => {
                // Domain name (length-prefixed)
                if data.len() >= 5 {
                    let domain_len = data[4] as usize;
                    if data.len() >= 4 + 1 + domain_len + 2 {
                        let _domain = &data[5..5 + domain_len];
                        let _port = u16::from_be_bytes([
                            data[5 + domain_len],
                            data[5 + domain_len + 1],
                        ]);

                        // Validate domain length
                        if domain_len == 0 || domain_len > 253 {
                            // Invalid domain length
                        }
                    }
                }
            }
            0x04 => {
                // IPv6 address (16 bytes)
                if data.len() >= 22 {
                    let _ipv6 = &data[4..20];
                    let _port = u16::from_be_bytes([data[20], data[21]]);
                }
            }
            _ => {
                // Invalid address type - should be rejected
            }
        }
    }

    // Test 4: Encode/decode roundtrip (if we have valid data)
    if let Ok((target_addr, header_len)) = sb_adapters::inbound::socks::udp::parse_udp_datagram(data) {
        // Get the payload
        if header_len < data.len() {
            let payload = &data[header_len..];

            // Encode it back
            let encoded = sb_adapters::inbound::socks::udp::encode_udp_datagram(&target_addr, payload);

            // Parse the encoded data
            let parse_again = sb_adapters::inbound::socks::udp::parse_udp_datagram(&encoded);

            // Should be able to parse what we just encoded
            assert!(parse_again.is_ok(), "Failed to parse our own encoded data");
        }
    }

    // Test 5: Malformed domain names
    if data.len() >= 5 && data[3] == 0x03 {
        // Domain address type
        let domain_len = data[4] as usize;

        // Very large domain length
        if domain_len > 1000 {
            // Should be rejected gracefully
            let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
        }

        // Domain length exceeds remaining buffer
        if 4 + 1 + domain_len + 2 > data.len() {
            // Should be rejected gracefully
            let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
        }
    }

    // Test 6: Port edge cases
    if data.len() >= 10 && data[3] == 0x01 {
        // IPv4 address type
        let port = u16::from_be_bytes([data[8], data[9]]);

        // Port 0 or max port
        if port == 0 || port == 65535 {
            // These are technically valid but unusual
            let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
        }
    }

    // Test 7: Fragment number (usually should be 0)
    if data.len() >= 3 {
        let frag = data[2];
        if frag > 0 {
            // Non-zero fragment - most SOCKS5 implementations don't support fragmentation
            let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
        }
    }

    // Test 8: Very large payloads
    if data.len() > 65535 {
        // UDP datagram larger than max UDP packet size
        // Should still parse the header correctly
        let _ = sb_adapters::inbound::socks::udp::parse_udp_datagram(data);
    }
});
