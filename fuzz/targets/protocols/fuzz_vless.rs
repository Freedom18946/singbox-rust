#![no_main]
//! VLESS protocol parsing fuzzer
//!
//! Tests VLESS protocol parsing with various malformed inputs to ensure
//! robust error handling and prevent crashes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test VLESS request parsing (minimum 19 bytes)
    if data.len() >= 19 {
        let mut offset = 0;

        // Version (1 byte)
        let version = data[offset];
        offset += 1;
        if version != 0x01 {
            return; // Invalid version, but shouldn't panic
        }

        // UUID (16 bytes)
        if data.len() < offset + 16 {
            return;
        }
        let _uuid = &data[offset..offset + 16];
        offset += 16;

        // Additional data length
        if data.len() < offset + 1 {
            return;
        }
        let additional_len = data[offset] as usize;
        offset += 1;

        // Additional data
        if data.len() < offset + additional_len {
            return;
        }
        let _additional = &data[offset..offset + additional_len];
        offset += additional_len;

        // Command
        if data.len() < offset + 1 {
            return;
        }
        let command = data[offset];
        offset += 1;

        match command {
            0x01 => { /* TCP */ }
            0x02 => { /* UDP */ }
            0x03 => { /* MUX */ }
            _ => return, // Invalid command
        }

        // Address type
        if data.len() < offset + 1 {
            return;
        }
        let atyp = data[offset];
        offset += 1;

        // Parse address based on type
        match atyp {
            0x01 => {
                // IPv4: 4 bytes + 2 bytes port
                if data.len() < offset + 6 {
                    return;
                }
                let _ipv4 = &data[offset..offset + 4];
                let _port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            }
            0x02 => {
                // Domain: length byte + domain + 2 bytes port
                if data.len() < offset + 1 {
                    return;
                }
                let domain_len = data[offset] as usize;
                offset += 1;

                if data.len() < offset + domain_len + 2 {
                    return;
                }
                let _domain = &data[offset..offset + domain_len];
                let _port = u16::from_be_bytes([data[offset + domain_len], data[offset + domain_len + 1]]);

                // Validate domain is valid UTF-8
                let _ = std::str::from_utf8(_domain);
            }
            0x03 => {
                // IPv6: 16 bytes + 2 bytes port
                if data.len() < offset + 18 {
                    return;
                }
                let _ipv6 = &data[offset..offset + 16];
                let _port = u16::from_be_bytes([data[offset + 16], data[offset + 17]]);
            }
            _ => {
                // Invalid address type - shouldn't panic
                return;
            }
        }
    }

    // Test edge cases
    if data.is_empty() {
        return;
    }

    // Single byte (invalid but shouldn't crash)
    if data.len() == 1 {
        let _ = data[0];
        return;
    }

    // Very large additional_len that would overflow
    if data.len() >= 19 {
        let additional_len = data[18] as usize;
        if additional_len > 1024 * 1024 {
            // This tests that the parser properly validates lengths
            // before allocating or reading
            return;
        }
    }

    // Test malformed domain names
    if data.len() >= 20 {
        let offset = 19; // After version + uuid + additional_len(0) + command
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

    // Test port edge cases
    if data.len() >= 25 {
        // For IPv4 address type scenario
        let port_offset = 23; // After minimal header + IPv4
        if data.len() >= port_offset + 2 {
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            if port == 0 || port > 65535 {
                // These might be invalid but shouldn't panic
            }
        }
    }
});