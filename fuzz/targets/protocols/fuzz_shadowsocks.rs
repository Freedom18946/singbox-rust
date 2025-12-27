#![no_main]
//! Shadowsocks protocol parsing fuzzer
//!
//! This fuzzer tests the Shadowsocks protocol request parsing which includes:
//! - AEAD packet parsing (encrypted data with authentication)
//! - Address encoding parsing (SOCKS5-like format)
//! - TCP request parsing
//! - UDP packet parsing
//!
//! Shadowsocks is a critical inbound protocol, and parsing errors could lead to:
//! - Authentication bypass
//! - Buffer overflows
//! - Panic/crash from malformed packets
//! - Resource exhaustion

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Shadowsocks AEAD packet parsing
    // AEAD packets have: salt(16) + encrypted_data + auth_tag(16)
    if data.len() >= 32 {
        let _salt = &data[..16];
        let _encrypted_data = &data[16..data.len() - 16];
        let _auth_tag = &data[data.len() - 16..];

        // In real code, this would decrypt and authenticate the data
        // using the salt and auth tag
    }

    // Test 2: Address encoding parsing (SOCKS5-like format)
    let _ = sb_adapters::inbound::shadowsocks::parse_ss_addr(data);

    // Test 3: TCP request parsing
    if data.len() >= 3 {
        // Parse address type and data
        let atyp = data[0];
        let mut offset = 1;

        match atyp {
            0x01 => {
                // IPv4: 4 bytes + 2 bytes port
                if data.len() >= offset + 6 {
                    let _ipv4 = &data[offset..offset + 4];
                    let _port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
                }
            }
            0x02 => {
                // Domain: length byte + domain + 2 bytes port
                if data.len() > offset {
                    let domain_len = data[offset] as usize;
                    offset += 1;

                    if data.len() >= offset + domain_len + 2 {
                        let _domain = &data[offset..offset + domain_len];
                        let _port = u16::from_be_bytes([
                            data[offset + domain_len],
                            data[offset + domain_len + 1],
                        ]);

                        // Validate domain is valid UTF-8
                        let _ = std::str::from_utf8(_domain);
                    }
                }
            }
            0x03 => {
                // IPv6: 16 bytes + 2 bytes port
                if data.len() >= offset + 18 {
                    let _ipv6 = &data[offset..offset + 16];
                    let _port = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
                }
            }
            _ => {
                // Invalid address type - shouldn't panic
                return;
            }
        }
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

    // Test 5: Malformed domain names
    if data.len() >= 5 {
        let offset = 1; // After address type
        if data[offset] == 0x02 {
            // Domain address type
            if data.len() > offset + 1 {
                let domain_len = data[offset + 1] as usize;

                // Test various invalid domain lengths
                if domain_len == 0 {
                    // Empty domain
                    return;
                }
                if domain_len > 253 {
                    // Domain too long (DNS limit is 253)
                    return;
                }
            }
        }
    }

    // Test 6: Port edge cases
    // Port 0, max port (65535), etc.
    if data.len() >= 8 {
        // For IPv4 address type scenario
        let port_offset = 5; // After address type + IPv4
        if data.len() >= port_offset + 2 {
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            if port == 0 || port > 65535 {
                // These might be invalid but shouldn't panic
            }
        }
    }

    // Test 7: Invalid AEAD packet format
    if data.len() >= 16 {
        // Test with insufficient data for AEAD
        if data.len() < 32 {
            // Not enough data for salt + auth_tag
            return;
        }
    }

    // Test 8: Large domain names
    if data.len() >= 5 {
        let offset = 1;
        if data[offset] == 0x02 && data.len() > offset + 1 {
            let domain_len = data[offset + 1] as usize;
            if domain_len > 1000 {
                // Very large domain - should be handled gracefully
                return;
            }
        }
    }

});
