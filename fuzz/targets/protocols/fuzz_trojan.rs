#![no_main]
//! Trojan protocol parsing fuzzer
//!
//! This fuzzer tests the Trojan protocol request parsing which includes:
//! - Password hash validation (56 bytes SHA224 hex)
//! - Command parsing (1 byte: CONNECT=0x01, UDP=0x02)
//! - Address parsing (IPv4/IPv6/domain)
//! - Port parsing (2 bytes)
//!
//! Trojan is a critical inbound protocol, and parsing errors could lead to:
//! - Authentication bypass
//! - Buffer overflows
//! - Panic/crash from malformed packets
//! - Resource exhaustion

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Trojan password hash validation (56 bytes SHA224 hex)
    if data.len() >= 56 {
        let _password_hash = &data[..56];

        // Validate hex format (should be 56 hex characters)
        if let Ok(hash_str) = std::str::from_utf8(_password_hash) {
            if hash_str.len() == 56 && hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
                // Valid hex format
            }
        }
    }

    // Test 2: Trojan request parsing (after password hash)
    if data.len() >= 57 {
        let mut offset = 56; // Skip password hash

        // CRLF (2 bytes)
        if data.len() >= offset + 2 {
            if data[offset] == b'\r' && data[offset + 1] == b'\n' {
                offset += 2;
            } else {
                return; // Invalid CRLF, but shouldn't panic
            }
        }

        // Command (1 byte)
        if data.len() > offset {
            let command = data[offset];
            offset += 1;

            match command {
                0x01 => { /* CONNECT */ }
                0x02 => { /* UDP */ }
                _ => return, // Invalid command
            }
        }

        // Address type (1 byte)
        if data.len() > offset {
            let atyp = data[offset];
            offset += 1;

            // Parse address based on type
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

        // CRLF (2 bytes)
        if data.len() >= offset + 2 {
            if data[offset] == b'\r' && data[offset + 1] == b'\n' {
                // Valid request format
            }
        }
    }

    // Test 3: Edge cases
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

    // Test 4: Malformed domain names
    if data.len() >= 60 {
        let offset = 59; // After password hash + CRLF + command
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

    // Test 5: Port edge cases
    // Port 0, max port (65535), etc.
    if data.len() >= 65 {
        // For IPv4 address type scenario
        let port_offset = 63; // After password hash + CRLF + command + IPv4
        if data.len() >= port_offset + 2 {
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            if port == 0 || port > 65535 {
                // These might be invalid but shouldn't panic
            }
        }
    }

    // Test 6: Invalid password hash format
    if data.len() >= 56 {
        let hash_bytes = &data[..56];
        if let Ok(hash_str) = std::str::from_utf8(hash_bytes) {
            // Test non-hex characters
            if !hash_str.chars().all(|c| c.is_ascii_hexdigit()) {
                // Invalid hex format - should be handled gracefully
            }
        }
    }

    // Test 7: Missing CRLF
    if data.len() >= 58 {
        let crlf_pos = 56;
        if data[crlf_pos] != b'\r' || data[crlf_pos + 1] != b'\n' {
            // Missing CRLF - should be handled gracefully
        }
    }

    // TODO: When sb-adapters exposes the real parsing function, replace
    // the above manual parsing with:
    //
    // let _ = sb_adapters::inbound::trojan::parse_trojan_request(data);
    //
    // This will ensure we're testing the actual production code path
    // rather than a reimplementation.
});
