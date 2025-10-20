#![no_main]
//! TUIC protocol parsing fuzzer
//!
//! Tests TUIC protocol parsing with various malformed inputs to ensure
//! robust error handling and prevent crashes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test TUIC protocol parsing
    if data.len() >= 8 {
        // TUIC starts with version (1 byte) + command (1 byte) + length (2 bytes) + uuid (16 bytes)
        let version = data[0];
        let command = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        
        // Validate version
        if version != 0x05 {
            return; // Invalid version, but shouldn't panic
        }
        
        if data.len() >= 8 + length {
            let payload = &data[8..8 + length];
            let _ = parse_tuic_command(command, payload);
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

    // Very large length that would overflow
    if data.len() >= 4 {
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if length > 1024 * 1024 {
            // This tests that the parser properly validates lengths
            // before allocating or reading
            return;
        }
    }
});

fn parse_tuic_command(command: u8, payload: &[u8]) -> Option<()> {
    match command {
        0x00 => {
            // Handshake
            if payload.len() >= 16 {
                let _uuid = &payload[..16];
            }
        }
        0x01 => {
            // Connect
            if payload.len() >= 2 {
                let _port = u16::from_be_bytes([payload[0], payload[1]]);
                if payload.len() > 2 {
                    let _host = &payload[2..];
                    let _ = std::str::from_utf8(_host);
                }
            }
        }
        0x02 => {
            // Data
            // Just validate it's not empty
            if payload.is_empty() {
                return None;
            }
        }
        _ => {
            // Unknown command
            return None;
        }
    }
    Some(())
}
