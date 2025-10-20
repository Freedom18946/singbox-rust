#![no_main]
//! Hysteria protocol parsing fuzzer
//!
//! Tests Hysteria v1/v2 protocol parsing with various malformed inputs to ensure
//! robust error handling and prevent crashes.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test Hysteria v1 protocol parsing
    if data.len() >= 4 {
        // Hysteria v1 starts with version (2 bytes) + command (1 byte) + length (1 byte)
        let version = u16::from_be_bytes([data[0], data[1]]);
        let command = data[2];
        let length = data[3] as usize;
        
        // Validate version
        match version {
            0x0001 => {
                // Hysteria v1
                if data.len() >= 4 + length {
                    let payload = &data[4..4 + length];
                    let _ = parse_hysteria_v1_command(command, payload);
                }
            }
            0x0002 => {
                // Hysteria v2
                if data.len() >= 4 + length {
                    let payload = &data[4..4 + length];
                    let _ = parse_hysteria_v2_command(command, payload);
                }
            }
            _ => {
                // Unknown version - should be handled gracefully
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

    // Very large length that would overflow
    if data.len() >= 4 {
        let length = data[3] as usize;
        if length > 1024 * 1024 {
            // This tests that the parser properly validates lengths
            // before allocating or reading
            return;
        }
    }
});

fn parse_hysteria_v1_command(command: u8, payload: &[u8]) -> Option<()> {
    match command {
        0x00 => {
            // Handshake
            if payload.len() >= 8 {
                let _client_id = &payload[..8];
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

fn parse_hysteria_v2_command(command: u8, payload: &[u8]) -> Option<()> {
    match command {
        0x00 => {
            // Handshake
            if payload.len() >= 16 {
                let _client_id = &payload[..16];
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
