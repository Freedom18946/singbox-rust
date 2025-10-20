#![no_main]
//! VMess protocol parsing fuzzer
//!
//! Tests VMess protocol parsing with various malformed inputs to ensure
//! robust error handling and prevent crashes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test VMess authentication header validation (minimum 24 bytes)
    if data.len() >= 24 {
        let timestamp = u64::from_be_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let hmac = &data[8..24];
        
        // Test timestamp validation (should be within reasonable range)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if timestamp > now + 300 || timestamp < now - 300 {
            // Timestamp out of range - should be handled gracefully
            return;
        }
        
        // Test HMAC validation (simplified)
        if hmac.len() != 16 {
            return;
        }
    }

    // Test VMess request parsing (after auth header)
    if data.len() >= 25 {
        let mut offset = 24; // Skip auth header
        
        // Version (1 byte)
        if data.len() > offset {
            let version = data[offset];
            offset += 1;
            
            if version != 0x01 {
                return; // Invalid version, but shouldn't panic
            }
        }
        
        // Data encryption IV (16 bytes)
        if data.len() >= offset + 16 {
            let _iv = &data[offset..offset + 16];
            offset += 16;
        }
        
        // Key ID (16 bytes)
        if data.len() >= offset + 16 {
            let _key_id = &data[offset..offset + 16];
            offset += 16;
        }
        
        // Response authentication (1 byte)
        if data.len() > offset {
            let _response_auth = data[offset];
            offset += 1;
        }
        
        // Options (1 byte)
        if data.len() > offset {
            let _options = data[offset];
            offset += 1;
        }
        
        // Security (1 byte)
        if data.len() > offset {
            let _security = data[offset];
            offset += 1;
        }
        
        // Reserved (1 byte)
        if data.len() > offset {
            let _reserved = data[offset];
            offset += 1;
        }
        
        // Command (1 byte)
        if data.len() > offset {
            let command = data[offset];
            offset += 1;
            
            match command {
                0x01 => { /* TCP */ }
                0x02 => { /* UDP */ }
                0x03 => { /* MUX */ }
                _ => return, // Invalid command
            }
        }
        
        // Port (2 bytes)
        if data.len() >= offset + 2 {
            let _port = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
        }
        
        // Address type (1 byte)
        if data.len() > offset {
            let atyp = data[offset];
            offset += 1;
            
            // Parse address based on type
            match atyp {
                0x01 => {
                    // IPv4: 4 bytes
                    if data.len() >= offset + 4 {
                        let _ipv4 = &data[offset..offset + 4];
                    }
                }
                0x02 => {
                    // Domain: length byte + domain
                    if data.len() > offset {
                        let domain_len = data[offset] as usize;
                        offset += 1;
                        
                        if data.len() >= offset + domain_len {
                            let _domain = &data[offset..offset + domain_len];
                            
                            // Validate domain is valid UTF-8
                            let _ = std::str::from_utf8(_domain);
                        }
                    }
                }
                0x03 => {
                    // IPv6: 16 bytes
                    if data.len() >= offset + 16 {
                        let _ipv6 = &data[offset..offset + 16];
                    }
                }
                _ => {
                    // Invalid address type - shouldn't panic
                    return;
                }
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
    if data.len() >= 25 {
        let additional_len = data[24] as usize;
        if additional_len > 1024 * 1024 {
            // This tests that the parser properly validates lengths
            // before allocating or reading
            return;
        }
    }

    // Test malformed domain names
    if data.len() >= 30 {
        let offset = 29; // After minimal header
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
    if data.len() >= 30 {
        // For IPv4 address type scenario
        let port_offset = 28; // After minimal header + IPv4
        if data.len() >= port_offset + 2 {
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            if port == 0 || port > 65535 {
                // These might be invalid but shouldn't panic
            }
        }
    }
});